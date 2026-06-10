import pytest

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
