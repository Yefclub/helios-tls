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
    apex_crt, apex_key = core.zone_cert_paths("example.test")
    assert os.path.exists(apex_crt)
    assert os.path.exists(apex_key)
    with open(core.CUSTOM_YAML) as fh:
        yaml_text = fh.read()
    tcrt, tkey = core.traefik_cert_paths("example.test")
    assert tcrt in yaml_text
    assert tkey in yaml_text
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
    monkeypatch.setattr(core, "zone_id", lambda apex=None: "Z1")
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

    # regressão: e-mail colado no lugar do domínio (@ é inválido em hostname)
    monkeypatch.setattr(core, "LE_EMAIL", "a@b.c")
    monkeypatch.setattr(core, "LE_DOMAIN", "*.kalyel@example.com")
    ok, why = core.le_can_issue()
    assert not ok and "LE_DOMAIN inválido" in why


def test_data_dir_ok():
    ok, why = core.data_dir_ok()
    assert ok and why == ""


def test_data_dir_missing_blocks_issue(monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", os.path.join(core.DATA_DIR, "nao-existe"))
    ok, why = core.data_dir_ok()
    assert not ok and "Volume não montado" in why

    monkeypatch.setattr(core, "CF_TOKEN", "tok")
    monkeypatch.setattr(core, "LE_EMAIL", "a@b.c")
    ok, why = core.le_can_issue()
    assert not ok and "Volume não montado" in why


# ---------------------------------------------------------------- multi-zona
def test_parse_zones_le_domain_only():
    zones, errs = core.parse_zones("*.example.test", "", "", True)
    assert errs == []
    assert len(zones) == 1
    assert zones[0].apex == "example.test"
    assert zones[0].wildcard == "*.example.test"
    assert zones[0].is_default is True


def test_parse_zones_comma_extras_and_invalid():
    zones, errs = core.parse_zones(
        "*.kalyeloficial.com",
        "rastrofit.com, *.bad@host, not-a-zone",
        "",
        True,
    )
    assert [z.apex for z in zones] == ["kalyeloficial.com", "rastrofit.com"]
    assert zones[0].is_default is True
    assert zones[1].is_default is False
    assert any("inválid" in e.lower() or "LE_DOMAIN" in e for e in errs)
    assert any("zona inválida" in e or "not-a-zone" in e for e in errs)


def test_parse_zones_default_override():
    zones, errs = core.parse_zones(
        "*.alpha.test", "beta.test", "beta.test", True)
    assert errs == []
    assert zones[0].apex == "alpha.test" and zones[0].is_default is False
    assert zones[1].apex == "beta.test" and zones[1].is_default is True


def test_parse_zones_unknown_default_reports_error():
    zones, errs = core.parse_zones("*.alpha.test", "", "missing.test", True)
    assert zones[0].is_default is True
    assert any("LE_DEFAULT_ZONE" in e for e in errs)


def test_install_two_zones_keeps_both_and_one_default(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "LE_DOMAIN", "*.alpha.test")
    monkeypatch.setattr(core, "LE_DOMAINS", "beta.test")
    monkeypatch.setattr(core, "LE_DEFAULT_ZONE", "")
    monkeypatch.setattr(core, "SET_DEFAULT", True)
    monkeypatch.setattr(core, "CERTS_DIR", str(tmp_path / "certs"))
    monkeypatch.setattr(core, "CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setattr(core, "CUSTOM_YAML", str(tmp_path / "config" / "custom.yaml"))
    monkeypatch.setattr(core, "CRT_PATH", str(tmp_path / "certs" / "wildcard.crt"))
    monkeypatch.setattr(core, "KEY_PATH", str(tmp_path / "certs" / "wildcard.key"))
    monkeypatch.setattr(core, "DEFAULT_CRT", str(tmp_path / "default.cert"))
    monkeypatch.setattr(core, "DEFAULT_KEY", str(tmp_path / "default.key"))

    a_crt, a_key = make_cert_pair(cn="*.alpha.test", sans=("*.alpha.test", "alpha.test"))
    b_crt, b_key = make_cert_pair(cn="*.beta.test", sans=("*.beta.test", "beta.test"))
    core.install_cert_for_zone("alpha.test", a_crt, a_key)
    core.install_cert_for_zone("beta.test", b_crt, b_key)

    assert os.path.exists(os.path.join(core.CERTS_DIR, "alpha.test.crt"))
    assert os.path.exists(os.path.join(core.CERTS_DIR, "beta.test.crt"))
    with open(core.CUSTOM_YAML) as fh:
        yaml_text = fh.read()
    assert "/data/certs/alpha.test.crt" in yaml_text
    assert "/data/certs/beta.test.crt" in yaml_text
    assert "/data/certs/alpha.test.key" in yaml_text
    assert "/data/certs/beta.test.key" in yaml_text

    with open(core.DEFAULT_CRT, "rb") as fh:
        default_info = core.parse_cert(fh.read())
    assert default_info["cn"] == "*.alpha.test"
    beta_status = core.installed_status("beta.test")
    assert beta_status["cn"] == "*.beta.test"
    # segundo install não apagou o primeiro
    assert core.installed_status("alpha.test")["cn"] == "*.alpha.test"


def test_install_non_default_does_not_overwrite_default_slot(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "LE_DOMAIN", "*.alpha.test")
    monkeypatch.setattr(core, "LE_DOMAINS", "beta.test")
    monkeypatch.setattr(core, "SET_DEFAULT", True)
    monkeypatch.setattr(core, "CERTS_DIR", str(tmp_path / "certs"))
    monkeypatch.setattr(core, "CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setattr(core, "CUSTOM_YAML", str(tmp_path / "config" / "custom.yaml"))
    monkeypatch.setattr(core, "CRT_PATH", str(tmp_path / "certs" / "wildcard.crt"))
    monkeypatch.setattr(core, "KEY_PATH", str(tmp_path / "certs" / "wildcard.key"))
    monkeypatch.setattr(core, "DEFAULT_CRT", str(tmp_path / "default.cert"))
    monkeypatch.setattr(core, "DEFAULT_KEY", str(tmp_path / "default.key"))

    a_crt, a_key = make_cert_pair(cn="*.alpha.test", sans=("*.alpha.test", "alpha.test"))
    b_crt, b_key = make_cert_pair(cn="*.beta.test", sans=("*.beta.test", "beta.test"))
    core.install_cert_for_zone("alpha.test", a_crt, a_key)
    before = open(core.DEFAULT_CRT, "rb").read()
    core.install_cert_for_zone("beta.test", b_crt, b_key)
    after = open(core.DEFAULT_CRT, "rb").read()
    assert before == after
    assert core.parse_cert(after)["cn"] == "*.alpha.test"


def test_normalize_name_uses_chosen_apex():
    assert core.normalize_name("api", "beta.example") == "api.beta.example"
    assert core.normalize_name("@", "beta.example") == "beta.example"
    assert core.normalize_name("www.beta.example", "beta.example") == "www.beta.example"


def test_valid_domain():
    assert core.valid_domain("*.example.com")
    assert core.valid_domain("example.com")
    assert core.valid_domain("sub.example.co.uk")
    assert not core.valid_domain("*.user@example.com")   # @
    assert not core.valid_domain("exemplo")              # sem TLD
    assert not core.valid_domain("foo..bar")             # label vazio
    assert not core.valid_domain("-foo.bar")             # hífen na borda
    assert not core.valid_domain("https://example.com")  # esquema
    assert not core.valid_domain("foo .bar")             # espaço
    assert not core.valid_domain("")
