import pytest
from conftest import make_cert_pair

import app as appmod
import core


@pytest.fixture
def client():
    appmod.app.config["TESTING"] = True
    appmod._FAILS.clear()
    with appmod.app.test_client() as c:
        yield c


def login(client):
    client.get("/login")
    with client.session_transaction() as s:
        tok = s["_csrf"]
    return client.post("/login", data={"user": "admin", "password": "secret123",
                                       "_csrf": tok})


# ---------------------------------------------------------------- auth painel
def test_index_requires_login(client):
    r = client.get("/")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_healthz_public(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert body["version"] == appmod.__version__


def test_issue_status_requires_login_as_json(client):
    r = client.get("/issue/status")
    assert r.status_code == 401
    assert r.get_json() == {"error": "auth"}


def test_issue_status_includes_version(client):
    login(client)
    r = client.get("/issue/status")
    assert r.status_code == 200
    assert r.get_json()["version"] == appmod.__version__


def test_reconcile_stale_running_state():
    core._set_state(status="running", message="Emitindo…", env="prod")
    core.reconcile_stale_state()
    st = core.le_state()
    assert st["status"] == "error"
    assert "interrompida" in st["message"]
    # idempotente: estado não-running fica como está
    core.reconcile_stale_state()
    assert core.le_state()["status"] == "error"


def test_login_success(client):
    r = login(client)
    assert r.status_code == 302
    assert r.headers["Location"] in ("/", "http://localhost/")


def test_login_wrong_password(client, monkeypatch):
    monkeypatch.setattr(appmod, "_FAIL_DELAY", 0)
    client.get("/login")
    with client.session_transaction() as s:
        tok = s["_csrf"]
    r = client.post("/login", data={"user": "admin", "password": "errada", "_csrf": tok})
    assert r.status_code == 200
    assert "inválidas".encode() in r.data


def test_login_lockout_after_5_fails(client, monkeypatch):
    monkeypatch.setattr(appmod, "_FAIL_DELAY", 0)
    client.get("/login")
    with client.session_transaction() as s:
        tok = s["_csrf"]
    for _ in range(5):
        client.post("/login", data={"user": "admin", "password": "errada", "_csrf": tok})
    # 6ª tentativa, mesmo com senha CERTA, é bloqueada
    r = client.post("/login", data={"user": "admin", "password": "secret123", "_csrf": tok})
    assert r.status_code == 200
    assert b"Muitas tentativas" in r.data


# ---------------------------------------------------------------- CSRF
def test_post_without_csrf_rejected(client):
    login(client)
    r = client.post("/issue", data={"env": "staging"})
    assert r.status_code == 400
    assert b"CSRF" in r.data


def test_login_post_without_csrf_rejected(client):
    r = client.post("/login", data={"user": "admin", "password": "secret123"})
    assert r.status_code == 400


# ---------------------------------------------------------------- API de cert
def test_api_disabled_returns_404(client, monkeypatch):
    monkeypatch.setattr(core, "CERT_API_TOKEN", "")
    r = client.get("/api/cert/info")
    assert r.status_code == 404


def test_api_requires_bearer(client, monkeypatch):
    monkeypatch.setattr(core, "CERT_API_TOKEN", "tok123")
    assert client.get("/api/cert/info").status_code == 401
    assert client.get("/api/cert/info",
                      headers={"Authorization": "Bearer errado"}).status_code == 401


def test_api_query_token_rejected(client, monkeypatch):
    """Regressão: token via query string foi removido — só header vale."""
    monkeypatch.setattr(core, "CERT_API_TOKEN", "tok123")
    r = client.get("/api/cert/info?token=tok123")
    assert r.status_code == 401


def test_api_with_valid_token(client, monkeypatch, cert_pair):
    monkeypatch.setattr(core, "CERT_API_TOKEN", "tok123")
    crt, key = cert_pair
    core.install_cert(crt, key)
    h = {"Authorization": "Bearer tok123"}

    r = client.get("/api/cert/info", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["cn"] == "*.example.test"
    assert body["is_wildcard"] is True

    r = client.get("/api/cert/fullchain.pem", headers=h)
    assert r.status_code == 200
    assert b"BEGIN CERTIFICATE" in r.data

    r = client.get("/api/cert/privkey.pem", headers=h)
    assert r.status_code == 200
    assert b"PRIVATE KEY" in r.data
    assert r.headers["Cache-Control"] == "no-store"

    r = client.get("/api/cert/bundle.pem", headers=h)
    assert b"BEGIN CERTIFICATE" in r.data and b"PRIVATE KEY" in r.data

    r = client.get("/api/cert/install.sh", headers=h)
    assert r.status_code == 200
    assert b"/api/cert" in r.data


def test_api_info_other_zone_without_cert_is_503(client, monkeypatch):
    monkeypatch.setattr(core, "CERT_API_TOKEN", "tok123")
    monkeypatch.setattr(core, "LE_DOMAIN", "*.alpha.test")
    monkeypatch.setattr(core, "LE_DOMAINS", "beta.test")
    monkeypatch.setattr(core, "SET_DEFAULT", True)
    a_crt, a_key = make_cert_pair(cn="*.alpha.test", sans=("*.alpha.test", "alpha.test"))
    core.install_cert_for_zone("alpha.test", a_crt, a_key)
    h = {"Authorization": "Bearer tok123"}

    r = client.get("/api/cert/info?domain=beta.test", headers=h)
    assert r.status_code == 503
    assert b"Sem certificado" in r.data

    r = client.get("/api/cert/fullchain.pem?domain=beta.test", headers=h)
    assert r.status_code == 503

    r = client.get("/api/cert/info?domain=alpha.test", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["cn"] == "*.alpha.test"
    assert body["zone"] == "alpha.test"
