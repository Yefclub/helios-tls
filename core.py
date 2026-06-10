"""
core.py — lógica do Helios TLS:
  • instalação de certificado no Traefik (upload manual ou Let's Encrypt)
  • emissão/renovação de curinga via Let's Encrypt DNS-01 (lego + Cloudflare)
  • gerenciador de DNS da Cloudflare (SDK oficial)
"""
import datetime
import glob
import hashlib
import json
import os
import re
import subprocess
import threading
import time

from cloudflare import Cloudflare
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ---------------------------------------------------------------- paths/config
DATA_DIR    = os.environ.get("DATA_DIR", "/data")          # = /etc/easypanel/traefik
CERTS_DIR   = os.path.join(DATA_DIR, "certs")
CONFIG_DIR  = os.path.join(DATA_DIR, "config")
CUSTOM_YAML = os.path.join(CONFIG_DIR, "custom.yaml")
CRT_PATH    = os.path.join(CERTS_DIR, "wildcard.crt")
KEY_PATH    = os.path.join(CERTS_DIR, "wildcard.key")
DEFAULT_CRT = os.path.join(DATA_DIR, "default.cert")
DEFAULT_KEY = os.path.join(DATA_DIR, "default.key")
# caminhos como o Traefik enxerga (ele monta /etc/easypanel/traefik em /data)
TRAEFIK_CRT = "/data/certs/wildcard.crt"
TRAEFIK_KEY = "/data/certs/wildcard.key"

LEGO_PATH         = os.path.join(DATA_DIR, "lego")          # produção
LEGO_PATH_STAGING = os.path.join(DATA_DIR, "lego-staging")  # teste
STATE_PATH        = os.path.join(DATA_DIR, "le_state.json")
LE_STAGING_URL    = "https://acme-staging-v02.api.letsencrypt.org/directory"

SET_DEFAULT = os.environ.get("SET_DEFAULT", "true").lower() in ("1", "true", "yes")
# token compartilhado para a API de distribuição do certificado (vazio = desligada)
CERT_API_TOKEN = os.environ.get("CERT_API_TOKEN", "")
CF_TOKEN    = (os.environ.get("CLOUDFLARE") or os.environ.get("CF_DNS_API_TOKEN")
               or os.environ.get("CLOUDFLARE_DNS_API_TOKEN") or "")
LE_EMAIL    = os.environ.get("LE_EMAIL", "")
LE_DOMAIN   = os.environ.get("LE_DOMAIN", "*.example.com")          # curinga
BASE_DOMAIN = LE_DOMAIN[2:] if LE_DOMAIN.startswith("*.") else LE_DOMAIN
LE_RESOLVERS = os.environ.get("LE_RESOLVERS", "1.1.1.1:53,8.8.8.8:53")

PROXIABLE = {"A", "AAAA", "CNAME"}
DNS_TYPES = ["A", "AAAA", "CNAME", "TXT", "MX"]

_JOB_LOCK = threading.Lock()
_zone_id_cache = None


# ---------------------------------------------------------------- cert helpers
def parse_cert(pem_bytes):
    cert = x509.load_pem_x509_certificate(pem_bytes)
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except IndexError:
        cn = "(sem CN)"
    sans = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    try:
        issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
    except IndexError:
        try:
            issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except IndexError:
            issuer = ""
    not_after = cert.not_valid_after_utc
    days_left = (not_after - datetime.datetime.now(datetime.UTC)).days
    is_wild = any(s.startswith("*.") for s in sans) or cn.startswith("*.")
    return {"cn": cn, "sans": sans, "not_after": not_after, "issuer": issuer,
            "days_left": days_left, "is_wildcard": is_wild, "cert": cert}


def keys_match(cert, key_bytes):
    priv = serialization.load_pem_private_key(key_bytes, password=None)
    a = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    b = priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return a == b


def _write_secret(path, data, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    os.chmod(path, mode)


def _write_custom_yaml():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    stamp = datetime.datetime.now(datetime.UTC).isoformat()
    content = ("# Gerado pelo Helios TLS — NAO editar a mao.\n"
               f"# Atualizado em: {stamp}\n"
               "tls:\n  certificates:\n"
               f"    - certFile: {TRAEFIK_CRT}\n      keyFile: {TRAEFIK_KEY}\n")
    with open(CUSTOM_YAML, "w") as fh:
        fh.write(content)


def install_cert(crt_bytes, key_bytes):
    """Valida e instala o par no Traefik. Lança ValueError em caso de problema."""
    info = parse_cert(crt_bytes)                 # valida o cert
    if not keys_match(info["cert"], key_bytes):
        raise ValueError("A chave privada não corresponde ao certificado.")
    if info["days_left"] < 0:
        raise ValueError("O certificado está expirado.")
    _write_secret(CRT_PATH, crt_bytes, 0o644)
    _write_secret(KEY_PATH, key_bytes, 0o600)
    _write_custom_yaml()                         # dispara reload por file-watch
    if SET_DEFAULT:
        _write_secret(DEFAULT_CRT, crt_bytes, 0o644)
        _write_secret(DEFAULT_KEY, key_bytes, 0o600)
    return info


def installed_status():
    if not os.path.exists(CRT_PATH):
        return None
    try:
        with open(CRT_PATH, "rb") as fh:
            return parse_cert(fh.read())
    except Exception:
        return None


# ---------------------------------------------------------------- Let's Encrypt
def le_state():
    try:
        with open(STATE_PATH) as fh:
            return json.load(fh)
    except Exception:
        return {"status": "idle", "message": "", "env": "", "at": ""}


def _set_state(**kw):
    st = le_state()
    st.update(kw)
    st["at"] = datetime.datetime.now(datetime.UTC).isoformat()
    try:
        with open(STATE_PATH, "w") as fh:
            json.dump(st, fh)
    except Exception:
        pass


def _lego_env():
    e = dict(os.environ)
    if CF_TOKEN:
        e["CLOUDFLARE_DNS_API_TOKEN"] = CF_TOKEN
        e["CF_DNS_API_TOKEN"] = CF_TOKEN
    return e


def _lego_paths(path):
    crts = [p for p in glob.glob(os.path.join(path, "certificates", "*.crt"))
            if not p.endswith(".issuer.crt")]
    if not crts:
        return None, None
    crt = crts[0]
    key = crt[:-4] + ".key"
    return crt, key


_LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?$", re.IGNORECASE)


def valid_domain(domain):
    """Valida domínio (opcionalmente curinga '*.x.y'). Só LDH: letras/dígitos/hífen."""
    d = domain[2:] if domain.startswith("*.") else domain
    if not d or len(d) > 253:
        return False
    labels = d.split(".")
    if len(labels) < 2:
        return False
    return all(len(lb) <= 63 and _LABEL_RE.fullmatch(lb) for lb in labels)


def le_can_issue():
    """Retorna (ok, motivo) — pré-requisitos para emitir."""
    if not CF_TOKEN:
        return False, "Token da Cloudflare ausente (env CLOUDFLARE)."
    if not LE_EMAIL:
        return False, "E-mail do Let's Encrypt ausente (env LE_EMAIL)."
    if not valid_domain(LE_DOMAIN):
        return False, (f"LE_DOMAIN inválido: '{LE_DOMAIN}' — use o formato *.seudominio.com "
                       "(apenas letras, dígitos, hífen e pontos; sem @, espaços ou esquema).")
    if "*" not in LE_DOMAIN and BASE_DOMAIN == "example.com":
        return False, "Domínio não configurado (env LE_DOMAIN)."
    return True, ""


def issue_certificate(staging=False):
    """Bloqueante. Emite/renova via lego DNS-01. Em produção, instala no Traefik."""
    if not _JOB_LOCK.acquire(blocking=False):
        return False, "Já existe uma emissão em andamento."
    try:
        ok, why = le_can_issue()
        if not ok:
            _set_state(status="error", message=why, env=("staging" if staging else "prod"))
            return False, why

        path = LEGO_PATH_STAGING if staging else LEGO_PATH
        _set_state(status="running",
                   message=("Emitindo em staging…" if staging else "Emitindo em produção…"),
                   env=("staging" if staging else "prod"))

        # lego v5: NÃO existe o subcomando `renew` — `run` faz emitir *ou* renovar
        # (idempotente). Flags ficam DEPOIS do subcomando.
        existing, _ = _lego_paths(path)
        args = ["lego", "run", "--accept-tos", "--email", LE_EMAIL,
                "--dns", "cloudflare", "--path", path, "-d", LE_DOMAIN]
        # usa resolvers PÚBLICOS para a autoverificação de propagação —
        # o DNS interno (split-horizon) retorna NXDOMAIN para _acme-challenge.
        for rsv in [r.strip() for r in LE_RESOLVERS.split(",") if r.strip()]:
            args += ["--dns.resolvers", rsv]
        if BASE_DOMAIN and BASE_DOMAIN != LE_DOMAIN:
            args += ["-d", BASE_DOMAIN]
        if staging:
            args += ["--server", LE_STAGING_URL]
        if existing:
            # já há cert: só renova se faltarem <30 dias (no-op caso contrário)
            args += ["--renew-days", "30", "--no-random-sleep"]

        p = subprocess.run(args, env=_lego_env(), capture_output=True,
                           text=True, timeout=270)
        if p.returncode != 0:
            tail = (p.stderr or p.stdout or "")[-900:]
            _set_state(status="error",
                       message=f"lego falhou: {tail}", env=("staging" if staging else "prod"))
            return False, tail

        crt, key = _lego_paths(path)
        if not crt:
            _set_state(status="error", message="lego não produziu certificado.",
                       env=("staging" if staging else "prod"))
            return False, "sem certificado"

        if staging:
            _set_state(status="success",
                       message="Emissão em staging OK (não instalada — cert de teste).",
                       env="staging")
            return True, "staging ok"

        # produção: instala se mudou
        with open(crt, "rb") as f:
            crt_b = f.read()
        with open(key, "rb") as f:
            key_b = f.read()
        fp = hashlib.sha256(crt_b).hexdigest()
        if le_state().get("installed_fp") == fp and installed_status():
            _set_state(status="success", message="Certificado já estava atualizado.",
                       env="prod")
            return True, "sem mudança"
        info = install_cert(crt_b, key_b)
        _set_state(status="success",
                   message=f"Certificado emitido e instalado — expira em {info['days_left']} dias.",
                   env="prod", installed_fp=fp,
                   expires=info["not_after"].isoformat())
        return True, "instalado"
    except subprocess.TimeoutExpired:
        _set_state(status="error", message="Tempo esgotado na emissão (DNS-01).",
                   env=("staging" if staging else "prod"))
        return False, "timeout"
    except Exception as e:
        _set_state(status="error", message=str(e), env=("staging" if staging else "prod"))
        return False, str(e)
    finally:
        _JOB_LOCK.release()


def issue_async(staging=False):
    if _JOB_LOCK.locked():
        return False
    threading.Thread(target=issue_certificate, kwargs={"staging": staging},
                     daemon=True).start()
    return True


def start_scheduler():
    """Thread diária: renova produção quando faltam <30 dias (idempotente)."""
    def loop():
        time.sleep(60)
        while True:
            try:
                ok, _ = le_can_issue()
                if ok and _lego_paths(LEGO_PATH)[0]:
                    issue_certificate(staging=False)   # lego renew = no-op se não vencido
            except Exception:
                pass
            time.sleep(12 * 3600)
    threading.Thread(target=loop, daemon=True).start()


# ---------------------------------------------------------------- Cloudflare DNS
def _cf():
    return Cloudflare(api_token=CF_TOKEN)


def zone_id():
    global _zone_id_cache
    if _zone_id_cache:
        return _zone_id_cache
    for z in _cf().zones.list(name=BASE_DOMAIN):
        _zone_id_cache = z.id
        return _zone_id_cache
    raise RuntimeError(f"Zona '{BASE_DOMAIN}' não encontrada na Cloudflare.")


def dns_list():
    out = []
    for r in _cf().dns.records.list(zone_id=zone_id()):
        out.append({"id": r.id, "type": r.type, "name": r.name, "content": r.content,
                    "ttl": r.ttl, "proxied": bool(getattr(r, "proxied", False)),
                    "proxiable": bool(getattr(r, "proxiable", False)),
                    "priority": getattr(r, "priority", None),
                    "comment": getattr(r, "comment", None) or ""})
    out.sort(key=lambda x: (x["type"], x["name"]))
    return out


def normalize_name(name):
    """Aceita só o subdomínio e completa com a zona. '@'/vazio = raiz."""
    name = (name or "").strip().rstrip(".")
    if name in ("", "@"):
        return BASE_DOMAIN
    low = name.lower()
    if low == BASE_DOMAIN or low.endswith("." + BASE_DOMAIN):
        return name
    return name + "." + BASE_DOMAIN


def _record_kwargs(rtype, name, content, ttl, proxied, priority, comment):
    rtype = rtype.upper()
    kw = {"zone_id": zone_id(), "type": rtype, "name": normalize_name(name),
          "content": content, "comment": comment or ""}
    if rtype in PROXIABLE:
        kw["proxied"] = bool(proxied)
        kw["ttl"] = 1 if proxied else int(ttl or 1)
    else:
        kw["ttl"] = int(ttl or 1)
    if rtype == "MX":
        kw["priority"] = int(priority or 10)
    return kw


def dns_create(rtype, name, content, ttl=1, proxied=False, priority=None, comment=""):
    _cf().dns.records.create(**_record_kwargs(rtype, name, content, ttl, proxied, priority, comment))


def dns_edit(rid, rtype, name, content, ttl=1, proxied=False, priority=None, comment=""):
    _cf().dns.records.edit(dns_record_id=rid,
                           **_record_kwargs(rtype, name, content, ttl, proxied, priority, comment))


def dns_delete(rid):
    _cf().dns.records.delete(dns_record_id=rid, zone_id=zone_id())


# ---------------------------------------------------------------- API de distribuição
def cert_files():
    """Retorna (fullchain_bytes, key_bytes) do certificado instalado, ou (None, None)."""
    if not (os.path.exists(CRT_PATH) and os.path.exists(KEY_PATH)):
        return None, None
    with open(CRT_PATH, "rb") as f:
        crt = f.read()
    with open(KEY_PATH, "rb") as f:
        key = f.read()
    return crt, key


def cert_fingerprint(crt_bytes):
    return hashlib.sha256(crt_bytes).hexdigest()


def cert_api_info():
    crt, _ = cert_files()
    if not crt:
        return None
    info = parse_cert(crt)
    return {"cn": info["cn"], "sans": info["sans"], "issuer": info["issuer"],
            "not_after": info["not_after"].isoformat(), "days_left": info["days_left"],
            "is_wildcard": info["is_wildcard"], "fingerprint": cert_fingerprint(crt)}
