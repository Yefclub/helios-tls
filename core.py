"""
core.py — lógica do Helios TLS:
  • instalação de certificado no Traefik (upload manual ou Let's Encrypt)
  • emissão/renovação de curinga via Let's Encrypt DNS-01 (lego + Cloudflare)
  • gerenciador de DNS da Cloudflare (SDK oficial)
  • várias zonas (apex) ao mesmo tempo, sem apagar o cert das outras
"""
import datetime
import glob
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass

from cloudflare import Cloudflare
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ---------------------------------------------------------------- paths/config
DATA_DIR    = os.environ.get("DATA_DIR", "/data")          # = /etc/easypanel/traefik
CERTS_DIR   = os.path.join(DATA_DIR, "certs")
CONFIG_DIR  = os.path.join(DATA_DIR, "config")
CUSTOM_YAML = os.path.join(CONFIG_DIR, "custom.yaml")
CRT_PATH    = os.path.join(CERTS_DIR, "wildcard.crt")      # alias legado do cert padrão
KEY_PATH    = os.path.join(CERTS_DIR, "wildcard.key")
DEFAULT_CRT = os.path.join(DATA_DIR, "default.cert")
DEFAULT_KEY = os.path.join(DATA_DIR, "default.key")
TRAEFIK_CRT = "/data/certs/wildcard.crt"
TRAEFIK_KEY = "/data/certs/wildcard.key"

LEGO_PATH         = os.path.join(DATA_DIR, "lego")
LEGO_PATH_STAGING = os.path.join(DATA_DIR, "lego-staging")
STATE_PATH        = os.path.join(DATA_DIR, "le_state.json")
LE_STAGING_URL    = "https://acme-staging-v02.api.letsencrypt.org/directory"

SET_DEFAULT = os.environ.get("SET_DEFAULT", "true").lower() in ("1", "true", "yes")
CERT_API_TOKEN = os.environ.get("CERT_API_TOKEN", "")
CF_TOKEN    = (os.environ.get("CLOUDFLARE") or os.environ.get("CF_DNS_API_TOKEN")
               or os.environ.get("CLOUDFLARE_DNS_API_TOKEN") or "")
LE_EMAIL    = os.environ.get("LE_EMAIL", "")
LE_DOMAIN   = os.environ.get("LE_DOMAIN", "*.example.com")
LE_DOMAINS  = os.environ.get("LE_DOMAINS", "")
LE_DEFAULT_ZONE = os.environ.get("LE_DEFAULT_ZONE", "")
BASE_DOMAIN = LE_DOMAIN[2:] if LE_DOMAIN.startswith("*.") else LE_DOMAIN
LE_RESOLVERS = os.environ.get("LE_RESOLVERS", "1.1.1.1:53,8.8.8.8:53")

PROXIABLE = {"A", "AAAA", "CNAME"}
DNS_TYPES = ["A", "AAAA", "CNAME", "TXT", "MX"]

_JOB_LOCK = threading.Lock()
_zone_id_cache = {}
_state_warned = False

log = logging.getLogger("helios.core")


# ---------------------------------------------------------------- zone model
@dataclass(frozen=True)
class Zone:
    apex: str
    wildcard: str
    is_default: bool = False

    @property
    def slug(self):
        return self.apex


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


def parse_zone_spec(spec):
    """Aceita 'exemplo.com' ou '*.exemplo.com'. Retorna (Zone sem is_default, erro)."""
    raw = (spec or "").strip().rstrip(".")
    if not raw:
        return None, "zona vazia"
    if raw.startswith("*."):
        if not valid_domain(raw):
            return None, f"LE_DOMAIN inválido: '{spec}' — use o formato *.seudominio.com"
        apex = raw[2:].lower()
    else:
        if not valid_domain(raw):
            return None, f"zona inválida: '{spec}'"
        apex = raw.lower()
    return Zone(apex=apex, wildcard=f"*.{apex}", is_default=False), None


def parse_zones(le_domain, extra="", default_apex="", set_default=True):
    """Monta a lista de zonas. le_domain continua sendo a primeira (compatível).

    extra: lista separada por vírgula (apex ou curinga).
    default_apex: qual zona escreve o catch-all do Traefik; vazio = a primeira.
    Retorna (zones, errors) — entradas inválidas vão para errors e não entram na lista.
    """
    errors = []
    ordered = []
    seen = set()

    def _add(spec):
        zone, err = parse_zone_spec(spec)
        if err:
            errors.append(err)
            return
        if zone.apex in seen:
            return
        seen.add(zone.apex)
        ordered.append(zone)

    if le_domain and str(le_domain).strip():
        _add(str(le_domain).strip())
    for part in (extra or "").split(","):
        if part.strip():
            _add(part.strip())

    if not ordered:
        return [], errors or ["nenhuma zona configurada"]

    want = (default_apex or "").strip().lower().rstrip(".")
    if want.startswith("*."):
        want = want[2:]
    if want and want not in seen:
        errors.append(f"LE_DEFAULT_ZONE '{default_apex}' não está nas zonas configuradas")
        want = ordered[0].apex
    if not want:
        want = ordered[0].apex if set_default else ""

    zones = [
        Zone(apex=z.apex, wildcard=z.wildcard, is_default=(set_default and z.apex == want))
        for z in ordered
    ]
    return zones, errors


def configured_zones():
    """Lê LE_DOMAIN / LE_DOMAINS / LE_DEFAULT_ZONE atuais (honra monkeypatch)."""
    zones, _ = parse_zones(LE_DOMAIN, LE_DOMAINS, LE_DEFAULT_ZONE, SET_DEFAULT)
    return zones


def zone_parse_errors():
    _, errors = parse_zones(LE_DOMAIN, LE_DOMAINS, LE_DEFAULT_ZONE, SET_DEFAULT)
    return errors


def default_zone():
    zs = configured_zones()
    for z in zs:
        if z.is_default:
            return z
    return zs[0] if zs else None


def resolve_zone(apex=None):
    """Resolve apex (ou curinga) para Zone configurada. Sem apex = zona padrão."""
    zs = configured_zones()
    if not zs:
        raise ValueError("Nenhuma zona configurada.")
    if apex is None or str(apex).strip() == "":
        return default_zone()
    key = str(apex).strip().rstrip(".").lower()
    if key.startswith("*."):
        key = key[2:]
    for z in zs:
        if z.apex == key:
            return z
    raise ValueError(f"Zona '{apex}' não está configurada.")


def zone_cert_paths(apex):
    """Caminhos no DATA_DIR para o par de uma zona."""
    slug = apex.lower()
    return (
        os.path.join(CERTS_DIR, f"{slug}.crt"),
        os.path.join(CERTS_DIR, f"{slug}.key"),
    )


def traefik_cert_paths(apex):
    slug = apex.lower()
    return (f"/data/certs/{slug}.crt", f"/data/certs/{slug}.key")


def lego_dir(apex, staging=False):
    root = LEGO_PATH_STAGING if staging else LEGO_PATH
    return os.path.join(root, apex.lower())


def zone_state_path(apex):
    return os.path.join(DATA_DIR, f"le_state.{apex.lower()}.json")


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


def rebuild_tls_yaml():
    """Lista cada zona instalada como par distinto. Não apaga arquivos de outras zonas."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    stamp = datetime.datetime.now(datetime.UTC).isoformat()
    lines = [
        "# Gerado pelo Helios TLS — NAO editar a mao.\n",
        f"# Atualizado em: {stamp}\n",
        "tls:\n  certificates:\n",
    ]
    seen = set()
    for z in configured_zones():
        crt, key = zone_cert_paths(z.apex)
        if os.path.exists(crt) and os.path.exists(key):
            tcrt, tkey = traefik_cert_paths(z.apex)
            if tcrt not in seen:
                lines.append(f"    - certFile: {tcrt}\n      keyFile: {tkey}\n")
                seen.add(tcrt)
    # legado: wildcard.crt se ainda não houver par da zona padrão
    if os.path.exists(CRT_PATH) and os.path.exists(KEY_PATH) and TRAEFIK_CRT not in seen:
        dz = default_zone()
        apex_crt = zone_cert_paths(dz.apex)[0] if dz else ""
        if not apex_crt or not os.path.exists(apex_crt):
            lines.append(f"    - certFile: {TRAEFIK_CRT}\n      keyFile: {TRAEFIK_KEY}\n")
            seen.add(TRAEFIK_CRT)
    if not seen:
        lines.append(f"    - certFile: {TRAEFIK_CRT}\n      keyFile: {TRAEFIK_KEY}\n")
    with open(CUSTOM_YAML, "w") as fh:
        fh.writelines(lines)


def _write_custom_yaml():
    rebuild_tls_yaml()


def migrate_legacy_wildcard():
    """Copia certs/wildcard.* para {apex}.crt da zona padrão se o par novo ainda não existe."""
    z = default_zone()
    if not z or not os.path.exists(CRT_PATH) or not os.path.exists(KEY_PATH):
        return False
    dest_crt, dest_key = zone_cert_paths(z.apex)
    if os.path.exists(dest_crt) and os.path.exists(dest_key):
        return False
    os.makedirs(CERTS_DIR, exist_ok=True)
    shutil.copy2(CRT_PATH, dest_crt)
    shutil.copy2(KEY_PATH, dest_key)
    rebuild_tls_yaml()
    log.info("migrado wildcard legado → %s", dest_crt)
    return True


def install_cert_for_zone(apex, crt_bytes, key_bytes):
    """Instala o par numa zona sem apagar os arquivos das outras."""
    zone = resolve_zone(apex)
    info = parse_cert(crt_bytes)
    if not keys_match(info["cert"], key_bytes):
        raise ValueError("A chave privada não corresponde ao certificado.")
    if info["days_left"] < 0:
        raise ValueError("O certificado está expirado.")
    dest_crt, dest_key = zone_cert_paths(zone.apex)
    _write_secret(dest_crt, crt_bytes, 0o644)
    _write_secret(dest_key, key_bytes, 0o600)
    if zone.is_default:
        _write_secret(CRT_PATH, crt_bytes, 0o644)
        _write_secret(KEY_PATH, key_bytes, 0o600)
        if SET_DEFAULT:
            _write_secret(DEFAULT_CRT, crt_bytes, 0o644)
            _write_secret(DEFAULT_KEY, key_bytes, 0o600)
    rebuild_tls_yaml()
    return info


def install_cert(crt_bytes, key_bytes, apex=None):
    """Valida e instala o par. Sem apex = zona padrão (compatível com o upload antigo)."""
    zone = resolve_zone(apex)
    return install_cert_for_zone(zone.apex, crt_bytes, key_bytes)


def installed_status(apex=None):
    """Status do cert de uma zona. Sem apex = zona padrão (ou wildcard legado)."""
    try:
        zone = resolve_zone(apex) if apex or configured_zones() else None
    except ValueError:
        zone = None
    path = zone_cert_paths(zone.apex)[0] if zone else CRT_PATH
    if not os.path.exists(path):
        path = CRT_PATH
    if not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as fh:
            return parse_cert(fh.read())
    except Exception:
        return None


def installed_zones_status():
    """Uma entrada por zona configurada, com status do cert se houver."""
    out = []
    for z in configured_zones():
        st = installed_status(z.apex)
        out.append({"zone": z, "status": st})
    return out


# ---------------------------------------------------------------- Let's Encrypt
def _read_state_file(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {"status": "idle", "message": "", "env": "", "at": ""}
    except Exception as e:
        log.warning("estado ilegível em %s: %s", path, e)
        return {"status": "idle", "message": "", "env": "", "at": ""}


def le_state(apex=None):
    global _state_warned
    path = zone_state_path(apex) if apex else STATE_PATH
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        if apex:
            return {"status": "idle", "message": "", "env": "", "at": "", "apex": apex}
        return {"status": "idle", "message": "", "env": "", "at": ""}
    except Exception as e:
        if not _state_warned:
            _state_warned = True
            log.warning("estado ilegível em %s: %s", path, e)
        return {"status": "idle", "message": "", "env": "", "at": ""}


def _set_state(apex=None, **kw):
    st = le_state(apex)
    st.update(kw)
    st["at"] = datetime.datetime.now(datetime.UTC).isoformat()
    if apex:
        st["apex"] = apex
    paths = [STATE_PATH]
    if apex:
        paths.append(zone_state_path(apex))
    for path in paths:
        try:
            with open(path, "w") as fh:
                json.dump(st, fh)
        except Exception as e:
            log.error("não consegui gravar o estado em %s: %s — o /data está montado e gravável?",
                      path, e)


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


def data_dir_ok():
    """(ok, motivo) — /data precisa ser o bind mount do Traefik e ser gravável."""
    if not os.path.isdir(DATA_DIR):
        return False, (f"Volume não montado: {DATA_DIR} não existe no container. "
                       "Monte o bind /etc/easypanel/traefik → /data e faça redeploy.")
    probe = os.path.join(DATA_DIR, ".helios-probe")
    try:
        with open(probe, "w") as fh:
            fh.write("ok")
        os.remove(probe)
    except OSError as e:
        return False, f"Sem permissão de escrita em {DATA_DIR}: {e}"
    return True, ""


def le_can_issue(apex=None):
    """Retorna (ok, motivo) — pré-requisitos para emitir (opcionalmente uma zona)."""
    ok, why = data_dir_ok()
    if not ok:
        return False, why
    if not CF_TOKEN:
        return False, "Token da Cloudflare ausente (env CLOUDFLARE)."
    if not LE_EMAIL:
        return False, "E-mail do Let's Encrypt ausente (env LE_EMAIL)."
    if apex:
        try:
            resolve_zone(apex)
        except ValueError as e:
            return False, str(e)
    else:
        if not valid_domain(LE_DOMAIN):
            return False, (f"LE_DOMAIN inválido: '{LE_DOMAIN}' — use o formato *.seudominio.com "
                           "(apenas letras, dígitos, hífen e pontos; sem @, espaços ou esquema).")
        if "*" not in LE_DOMAIN and BASE_DOMAIN == "example.com":
            return False, "Domínio não configurado (env LE_DOMAIN)."
        if not configured_zones():
            return False, "Nenhuma zona válida em LE_DOMAIN / LE_DOMAINS."
    return True, ""


def issue_certificate(staging=False, apex=None):
    """Bloqueante. Emite/renova via lego DNS-01. Em produção, instala no Traefik."""
    if not _JOB_LOCK.acquire(blocking=False):
        return False, "Já existe uma emissão em andamento."
    try:
        zone = resolve_zone(apex)
        ok, why = le_can_issue(zone.apex)
        if not ok:
            _set_state(apex=zone.apex, status="error", message=why,
                       env=("staging" if staging else "prod"))
            return False, why

        path = lego_dir(zone.apex, staging=staging)
        log.info("emissão iniciada env=%s domínio=%s", "staging" if staging else "prod",
                 zone.wildcard)
        _set_state(apex=zone.apex, status="running",
                   message=("Emitindo em staging…" if staging else "Emitindo em produção…"),
                   env=("staging" if staging else "prod"))

        existing, _ = _lego_paths(path)
        args = ["lego", "run", "--accept-tos", "--email", LE_EMAIL,
                "--dns", "cloudflare", "--path", path, "-d", zone.wildcard, "-d", zone.apex]
        for rsv in [r.strip() for r in LE_RESOLVERS.split(",") if r.strip()]:
            args += ["--dns.resolvers", rsv]
        if staging:
            args += ["--server", LE_STAGING_URL]
        if existing:
            args += ["--renew-days", "30", "--no-random-sleep"]

        p = subprocess.run(args, env=_lego_env(), capture_output=True,
                           text=True, timeout=270)
        if p.returncode != 0:
            tail = (p.stderr or p.stdout or "")[-900:]
            log.error("lego falhou (env=%s zona=%s): %s",
                      "staging" if staging else "prod", zone.apex, tail)
            _set_state(apex=zone.apex, status="error",
                       message=f"lego falhou: {tail}", env=("staging" if staging else "prod"))
            return False, tail

        crt, key = _lego_paths(path)
        if not crt:
            _set_state(apex=zone.apex, status="error", message="lego não produziu certificado.",
                       env=("staging" if staging else "prod"))
            return False, "sem certificado"

        if staging:
            _set_state(apex=zone.apex, status="success",
                       message="Emissão em staging OK (não instalada — cert de teste).",
                       env="staging")
            return True, "staging ok"

        with open(crt, "rb") as f:
            crt_b = f.read()
        with open(key, "rb") as f:
            key_b = f.read()
        fp = hashlib.sha256(crt_b).hexdigest()
        dest_crt = zone_cert_paths(zone.apex)[0]
        if le_state(zone.apex).get("installed_fp") == fp and os.path.exists(dest_crt):
            _set_state(apex=zone.apex, status="success",
                       message="Certificado já estava atualizado.", env="prod")
            return True, "sem mudança"
        info = install_cert_for_zone(zone.apex, crt_b, key_b)
        log.info("certificado instalado zona=%s cn=%s expira_em=%s dias",
                 zone.apex, info["cn"], info["days_left"])
        _set_state(apex=zone.apex, status="success",
                   message=f"Certificado emitido e instalado — expira em {info['days_left']} dias.",
                   env="prod", installed_fp=fp,
                   expires=info["not_after"].isoformat())
        return True, "instalado"
    except subprocess.TimeoutExpired:
        z = None
        try:
            z = resolve_zone(apex)
        except Exception:
            pass
        _set_state(apex=(z.apex if z else apex), status="error",
                   message="Tempo esgotado na emissão (DNS-01).",
                   env=("staging" if staging else "prod"))
        return False, "timeout"
    except Exception as e:
        z = None
        try:
            z = resolve_zone(apex)
        except Exception:
            pass
        _set_state(apex=(z.apex if z else apex), status="error", message=str(e),
                   env=("staging" if staging else "prod"))
        return False, str(e)
    finally:
        _JOB_LOCK.release()


def reconcile_stale_state():
    """Reinício no meio de uma emissão deixa 'running' órfão no arquivo."""
    for path in [STATE_PATH] + [
        zone_state_path(z.apex) for z in configured_zones()
    ]:
        st = _read_state_file(path)
        if st.get("status") == "running":
            log.warning("estado 'running' órfão em %s — marcando como interrompido", path)
            st["status"] = "error"
            st["message"] = "Emissão interrompida por reinício da aplicação — emita novamente."
            st["at"] = datetime.datetime.now(datetime.UTC).isoformat()
            try:
                with open(path, "w") as fh:
                    json.dump(st, fh)
            except Exception as e:
                log.error("não consegui gravar o estado em %s: %s", path, e)


def issue_async(staging=False, apex=None):
    if _JOB_LOCK.locked():
        return False
    try:
        zone = resolve_zone(apex)
    except ValueError:
        return False
    _set_state(apex=zone.apex, status="running", message="Iniciando emissão…",
               env=("staging" if staging else "prod"))
    threading.Thread(target=issue_certificate,
                     kwargs={"staging": staging, "apex": zone.apex},
                     daemon=True).start()
    return True


def start_scheduler():
    """Thread: renova cada zona de produção quando faltam <30 dias."""
    def loop():
        time.sleep(60)
        while True:
            try:
                for z in configured_zones():
                    ok, _ = le_can_issue(z.apex)
                    if ok and _lego_paths(lego_dir(z.apex, staging=False))[0]:
                        log.info("agendador: checando renovação zona=%s", z.apex)
                        issue_certificate(staging=False, apex=z.apex)
            except Exception as e:
                log.error("agendador: %s", e)
            time.sleep(12 * 3600)
    threading.Thread(target=loop, daemon=True).start()


# ---------------------------------------------------------------- Cloudflare DNS
def _cf():
    return Cloudflare(api_token=CF_TOKEN)


def zone_id(apex=None):
    zone = resolve_zone(apex)
    cached = _zone_id_cache.get(zone.apex)
    if cached:
        return cached
    for z in _cf().zones.list(name=zone.apex):
        _zone_id_cache[zone.apex] = z.id
        return z.id
    raise RuntimeError(f"Zona '{zone.apex}' não encontrada na Cloudflare.")


def dns_list(apex=None):
    out = []
    zid = zone_id(apex)
    for r in _cf().dns.records.list(zone_id=zid):
        out.append({"id": r.id, "type": r.type, "name": r.name, "content": r.content,
                    "ttl": r.ttl, "proxied": bool(getattr(r, "proxied", False)),
                    "proxiable": bool(getattr(r, "proxiable", False)),
                    "priority": getattr(r, "priority", None),
                    "comment": getattr(r, "comment", None) or ""})
    out.sort(key=lambda x: (x["type"], x["name"]))
    return out


def normalize_name(name, apex=None):
    """Aceita só o subdomínio e completa com a zona. '@'/vazio = raiz."""
    if apex:
        parsed, err = parse_zone_spec(apex)
        if err:
            raise ValueError(err)
        base = parsed.apex
    else:
        base = resolve_zone(None).apex
    name = (name or "").strip().rstrip(".")
    if name in ("", "@"):
        return base
    low = name.lower()
    if low == base or low.endswith("." + base):
        return name
    return name + "." + base


def _record_kwargs(rtype, name, content, ttl, proxied, priority, comment, apex=None):
    rtype = rtype.upper()
    zone = resolve_zone(apex)
    kw = {"zone_id": zone_id(zone.apex), "type": rtype,
          "name": normalize_name(name, zone.apex),
          "content": content, "comment": comment or ""}
    if rtype in PROXIABLE:
        kw["proxied"] = bool(proxied)
        kw["ttl"] = 1 if proxied else int(ttl or 1)
    else:
        kw["ttl"] = int(ttl or 1)
    if rtype == "MX":
        kw["priority"] = int(priority or 10)
    return kw


def dns_create(rtype, name, content, ttl=1, proxied=False, priority=None, comment="", apex=None):
    _cf().dns.records.create(
        **_record_kwargs(rtype, name, content, ttl, proxied, priority, comment, apex=apex))
    log.info("DNS create %s %s", rtype.upper(), normalize_name(name, apex))


def dns_edit(rid, rtype, name, content, ttl=1, proxied=False, priority=None, comment="", apex=None):
    _cf().dns.records.edit(
        dns_record_id=rid,
        **_record_kwargs(rtype, name, content, ttl, proxied, priority, comment, apex=apex))
    log.info("DNS edit %s %s (id=%s)", rtype.upper(), normalize_name(name, apex), rid)


def dns_delete(rid, apex=None):
    _cf().dns.records.delete(dns_record_id=rid, zone_id=zone_id(apex))
    log.info("DNS delete id=%s zona=%s", rid, resolve_zone(apex).apex)


# ---------------------------------------------------------------- API de distribuição
def cert_files(apex=None):
    """Retorna (fullchain_bytes, key_bytes) do certificado da zona, ou (None, None)."""
    try:
        zone = resolve_zone(apex)
        crt_p, key_p = zone_cert_paths(zone.apex)
    except ValueError:
        crt_p, key_p = CRT_PATH, KEY_PATH
    if not (os.path.exists(crt_p) and os.path.exists(key_p)):
        if os.path.exists(CRT_PATH) and os.path.exists(KEY_PATH):
            crt_p, key_p = CRT_PATH, KEY_PATH
        else:
            return None, None
    with open(crt_p, "rb") as f:
        crt = f.read()
    with open(key_p, "rb") as f:
        key = f.read()
    return crt, key


def cert_fingerprint(crt_bytes):
    return hashlib.sha256(crt_bytes).hexdigest()


def cert_api_info(apex=None):
    crt, _ = cert_files(apex)
    if not crt:
        return None
    info = parse_cert(crt)
    payload = {"cn": info["cn"], "sans": info["sans"], "issuer": info["issuer"],
               "not_after": info["not_after"].isoformat(), "days_left": info["days_left"],
               "is_wildcard": info["is_wildcard"], "fingerprint": cert_fingerprint(crt)}
    try:
        payload["zone"] = resolve_zone(apex).apex
    except ValueError:
        pass
    return payload
