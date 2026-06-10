import os

import pytest
from conftest import make_cert_pair

import core


# ---------------------------------------------------------------- parse/keys
def test_parse_cert_wildcard(cert_pair):
    crt, _ = cert_pair
    info = core.parse_cert(crt)
    assert info["cn"] == "*.example.test"
    assert set(info["sans"]) == {"*.example.test", "example.test"}
    assert info["is_wildcard"] is True
    assert info["issuer"] == "Test CA"
    assert 88 <= info["days_left"] <= 90


def test_parse_cert_non_wildcard():
    crt, _ = make_cert_pair(cn="www.example.test", sans=("www.example.test",))
    info = core.parse_cert(crt)
    assert info["is_wildcard"] is False


def test_keys_match(cert_pair):
    crt, key = cert_pair
    cert = core.parse_cert(crt)["cert"]
    assert core.keys_match(cert, key) is True
    _, other_key = make_cert_pair()
    assert core.keys_match(cert, other_key) is False


# ---------------------------------------------------------------- install
def test_install_cert_writes_files(cert_pair):
    crt, key = cert_pair
    info = core.install_cert(crt, key)
    assert info["is_wildcard"] is True
    assert os.path.exists(core.CRT_PATH)
    assert os.path.exists(core.KEY_PATH)
    with open(core.CUSTOM_YAML) as fh:
        yaml_text = fh.read()
    assert core.TRAEFIK_CRT in yaml_text
    assert core.TRAEFIK_KEY in yaml_text
    status = core.installed_status()
    assert status and status["cn"] == "*.example.test"


def test_install_cert_rejects_mismatched_key(cert_pair):
    crt, _ = cert_pair
    _, wrong_key = make_cert_pair()
    with pytest.raises(ValueError, match="não corresponde"):
        core.install_cert(crt, wrong_key)


def test_install_cert_rejects_expired():
    crt, key = make_cert_pair(days=-1)
    with pytest.raises(ValueError, match="expirado"):
        core.install_cert(crt, key)


def test_cert_api_info_fingerprint(cert_pair):
    crt, key = cert_pair
    core.install_cert(crt, key)
    info = core.cert_api_info()
    assert info["fingerprint"] == core.cert_fingerprint(open(core.CRT_PATH, "rb").read())
    assert info["cn"] == "*.example.test"


# ---------------------------------------------------------------- nomes/DNS
def test_normalize_name():
    assert core.normalize_name("@") == "example.test"
    assert core.normalize_name("") == "example.test"
    assert core.normalize_name("api") == "api.example.test"
    assert core.normalize_name("api.example.test") == "api.example.test"
    assert core.normalize_name("api.example.test.") == "api.example.test"
    assert core.normalize_name("API.example.test") == "API.example.test"


def test_record_kwargs(monkeypatch):
    monkeypatch.setattr(core, "zone_id", lambda: "Z1")
    kw = core._record_kwargs("a", "api", "1.2.3.4", ttl=300, proxied=True,
                             priority=None, comment="x")
    assert kw["type"] == "A"
    assert kw["name"] == "api.example.test"
    assert kw["proxied"] is True
    assert kw["ttl"] == 1            # proxied força TTL automático

    kw = core._record_kwargs("TXT", "@", "v=spf1", ttl=120, proxied=True,
                             priority=None, comment="")
    assert "proxied" not in kw       # TXT não é proxiável
    assert kw["ttl"] == 120

    kw = core._record_kwargs("MX", "@", "mail.example.test", ttl=1, proxied=False,
                             priority="20", comment="")
    assert kw["priority"] == 20


# ---------------------------------------------------------------- pré-requisitos LE
def test_le_can_issue(monkeypatch):
    monkeypatch.setattr(core, "CF_TOKEN", "tok")
    monkeypatch.setattr(core, "LE_EMAIL", "a@b.c")
    ok, why = core.le_can_issue()
    assert ok and why == ""

    monkeypatch.setattr(core, "CF_TOKEN", "")
    ok, why = core.le_can_issue()
    assert not ok and "Cloudflare" in why

    monkeypatch.setattr(core, "CF_TOKEN", "tok")
    monkeypatch.setattr(core, "LE_EMAIL", "")
    ok, why = core.le_can_issue()
    assert not ok and "LE_EMAIL" in why
