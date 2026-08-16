"""
Helios TLS — painel para emitir/instalar o certificado curinga no Traefik do
Easypanel e gerenciar o DNS da Cloudflare.
"""
import hmac
import logging
import os
import threading
import time
from functools import wraps

from flask import Flask, Response, flash, jsonify, redirect, render_template_string, request, session, url_for

import core

__version__ = "1.3.1"

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("helios")

APP_USER     = os.environ.get("APP_USER", "admin")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
SERVER_NAME  = os.environ.get("SERVER_LABEL", "helios")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() in ("1", "true", "yes"),
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # uploads são só PEMs pequenos
)

core.reconcile_stale_state()   # restart no meio de emissão não pode virar 'running' eterno
try:
    core.migrate_legacy_wildcard()
except Exception as e:
    log.warning("migração do wildcard legado: %s", e)
_data_ok, _data_why = core.data_dir_ok()
if not _data_ok:
    log.error(_data_why)
if os.environ.get("RUN_SCHEDULER", "true").lower() in ("1", "true", "yes"):
    core.start_scheduler()


@app.after_request
def _no_cache(resp):
    # evita o navegador servir HTML antigo após um deploy
    if resp.mimetype == "text/html":
        resp.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    return resp


def login_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if not session.get("auth"):
            if request.path.startswith("/api") or request.path.endswith("/status"):
                return jsonify({"error": "auth"}), 401
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrap


# ---------------------------------------------------------------- CSRF
def _csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = os.urandom(16).hex()
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = _csrf_token
app.jinja_env.globals["version"] = __version__


@app.before_request
def _csrf_protect():
    # /api/* autentica por Bearer token; o resto (forms de sessão) exige CSRF
    if request.method == "POST" and not request.path.startswith("/api/"):
        sent = request.form.get("_csrf", "")
        good = session.get("_csrf", "")
        if not sent or not good or not hmac.compare_digest(sent, good):
            return Response("Sessão expirada ou token CSRF inválido — recarregue a página.\n",
                            400, mimetype="text/plain")


# ---------------------------------------------------------------- auth
_FAILS = {}          # ip -> (tentativas, bloqueado_até — time.monotonic)
_FAILS_LOCK = threading.Lock()
_MAX_FAILS = 5
_LOCK_SECS = 300
_FAIL_DELAY = 0.8    # atraso por tentativa errada (anti força-bruta)


def _client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return (fwd.split(",")[0].strip() if fwd else request.remote_addr) or "?"


def _eq(a, b):
    return hmac.compare_digest(a.encode(), b.encode())


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("auth"):
        return redirect(url_for("index"))
    if request.method == "POST":
        ip, now = _client_ip(), time.monotonic()
        with _FAILS_LOCK:
            fails, until = _FAILS.get(ip, (0, 0.0))
            if now < until:
                flash(f"Muitas tentativas. Aguarde {int(until - now) + 1}s.", "error")
                return render_template_string(LOGIN_HTML, server=SERVER_NAME)
            if until:            # janela de bloqueio expirou: zera o contador
                fails = 0
        if (_eq(request.form.get("user", ""), APP_USER)
                and APP_PASSWORD and _eq(request.form.get("password", ""), APP_PASSWORD)):
            with _FAILS_LOCK:
                _FAILS.pop(ip, None)
            session["auth"] = True
            return redirect(url_for("index"))
        with _FAILS_LOCK:
            fails += 1
            _FAILS[ip] = (fails, now + _LOCK_SECS if fails >= _MAX_FAILS else 0.0)
        log.warning("login falhou ip=%s user=%r (%d/%d)", ip,
                    request.form.get("user", ""), fails, _MAX_FAILS)
        time.sleep(_FAIL_DELAY)
        flash("Credenciais inválidas. Verifique usuário e senha.", "error")
    return render_template_string(LOGIN_HTML, server=SERVER_NAME)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="7" fill="#1c1813"/>
  <circle cx="16" cy="16" r="6" fill="url(#f)"/>
  <g stroke="url(#f)" stroke-width="2.6" stroke-linecap="round">
    <path d="M16 3.4v3.3"/><path d="M16 25.3v3.3"/><path d="M3.4 16h3.3"/><path d="M25.3 16h3.3"/>
    <path d="M7.05 7.05l2.35 2.35"/><path d="M22.6 22.6l2.35 2.35"/>
    <path d="M24.95 7.05l-2.35 2.35"/><path d="M9.4 22.6l-2.35 2.35"/>
  </g>
  <defs><linearGradient id="f" x1="3" y1="3" x2="29" y2="29" gradientUnits="userSpaceOnUse">
    <stop stop-color="#f6b73c"/><stop offset="1" stop-color="#e36a1f"/></linearGradient></defs>
</svg>"""


@app.route("/favicon.svg")
@app.route("/favicon.ico")
def favicon():
    return Response(FAVICON_SVG, mimetype="image/svg+xml",
                   headers={"Cache-Control": "public, max-age=86400"})


def _zone_from_request():
    raw = (request.args.get("zone") or request.args.get("domain")
           or request.form.get("zone") or request.form.get("domain") or "")
    raw = raw.strip()
    if not raw:
        z = core.default_zone()
        return z.apex if z else None
    try:
        return core.resolve_zone(raw).apex
    except ValueError:
        return raw


@app.route("/healthz")
def healthz():
    # liveness p/ Docker HEALTHCHECK / Easypanel — sem auth, sem dado sensível
    return jsonify({"ok": True, "version": __version__,
                    "zones": [z.apex for z in core.configured_zones()]})


# ---------------------------------------------------------------- dashboard
@app.route("/", methods=["GET"])
@login_required
def index():
    apex = None
    try:
        apex = _zone_from_request()
        if apex:
            apex = core.resolve_zone(apex).apex
    except ValueError:
        apex = core.default_zone().apex if core.default_zone() else None
    can, why = core.le_can_issue(apex)
    zones_view = []
    for item in core.installed_zones_status():
        z = item["zone"]
        zones_view.append({
            "apex": z.apex,
            "wildcard": z.wildcard,
            "is_default": z.is_default,
            "status": item["status"],
        })
    return render_template_string(
        INDEX_HTML, active="home", server=SERVER_NAME,
        status=core.installed_status(apex), le=core.le_state(apex),
        le_domain=core.LE_DOMAIN, le_email=core.LE_EMAIL,
        can_issue=can, why=why, set_default=core.SET_DEFAULT,
        api_enabled=bool(core.CERT_API_TOKEN), api_base=_api_base(),
        zones=zones_view, current_zone=apex,
        zone_errors=core.zone_parse_errors())


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    ok, why = core.data_dir_ok()
    if not ok:
        flash(why, "error")
        return redirect(url_for("index"))
    crt, key = request.files.get("crt"), request.files.get("key")
    if not crt or not key or crt.filename == "" or key.filename == "":
        flash("Envie os dois arquivos: cadeia (.crt) e chave (.key).", "error")
        return redirect(url_for("index"))
    apex = _zone_from_request()
    try:
        info = core.install_cert(crt.read(), key.read(), apex=apex)
    except Exception as e:
        flash(f"Falha: {e}", "error")
        return redirect(url_for("index", zone=apex or ""))
    flash(f"Certificado instalado — válido por mais {info['days_left']} dias.", "ok")
    if not info["is_wildcard"]:
        flash("O certificado não parece ser curinga (sem SAN *.dominio).", "warn")
    return redirect(url_for("index", zone=apex or ""))


@app.route("/issue", methods=["POST"])
@login_required
def issue():
    staging = request.form.get("env") == "staging"
    apex = _zone_from_request()
    can, why = core.le_can_issue(apex)
    if not can:
        flash(why, "error")
        return redirect(url_for("index", zone=apex or ""))
    if not core.issue_async(staging=staging, apex=apex):
        flash("Já existe uma emissão em andamento.", "warn")
    else:
        flash("Emissão iniciada — acompanhe o status abaixo.", "ok")
    return redirect(url_for("index", zone=apex or ""))


@app.route("/issue/status", methods=["GET"])
@login_required
def issue_status():
    apex = _zone_from_request()
    try:
        apex = core.resolve_zone(apex).apex if apex else None
    except ValueError:
        apex = None
    st = core.le_state(apex)
    st["version"] = __version__
    st["zone"] = apex
    return jsonify(st)


# ---------------------------------------------------------------- DNS manager
@app.route("/dns", methods=["GET"])
@login_required
def dns():
    records, err = [], None
    apex = _zone_from_request()
    try:
        apex = core.resolve_zone(apex).apex
        records = core.dns_list(apex)
    except Exception as e:
        err = str(e)
        try:
            apex = core.resolve_zone(apex).apex
        except Exception:
            z = core.default_zone()
            apex = z.apex if z else ""
    return render_template_string(
        DNS_HTML, active="dns", server=SERVER_NAME,
        records=records, err=err, base=apex,
        types=core.DNS_TYPES, proxiable=list(core.PROXIABLE),
        zones=core.configured_zones(), current_zone=apex)


@app.route("/dns/create", methods=["POST"])
@login_required
def dns_create():
    f = request.form
    apex = _zone_from_request()
    try:
        core.dns_create(f["type"], f["name"].strip(), f["content"].strip(),
                        ttl=f.get("ttl", 1), proxied=f.get("proxied") == "on",
                        priority=f.get("priority"), comment=f.get("comment", "").strip(),
                        apex=apex)
        flash(f"Registro {f['type']} '{f['name']}' criado.", "ok")
    except Exception as e:
        flash(f"Erro ao criar registro: {e}", "error")
    return redirect(url_for("dns", zone=apex or ""))


@app.route("/dns/edit", methods=["POST"])
@login_required
def dns_edit():
    f = request.form
    apex = _zone_from_request()
    try:
        core.dns_edit(f["id"], f["type"], f["name"].strip(), f["content"].strip(),
                      ttl=f.get("ttl", 1), proxied=f.get("proxied") == "on",
                      priority=f.get("priority"), comment=f.get("comment", "").strip(),
                      apex=apex)
        flash(f"Registro '{f['name']}' atualizado.", "ok")
    except Exception as e:
        flash(f"Erro ao atualizar: {e}", "error")
    return redirect(url_for("dns", zone=apex or ""))


@app.route("/dns/delete", methods=["POST"])
@login_required
def dns_delete():
    apex = _zone_from_request()
    try:
        core.dns_delete(request.form["id"], apex=apex)
        flash("Registro excluído.", "ok")
    except Exception as e:
        flash(f"Erro ao excluir: {e}", "error")
    return redirect(url_for("dns", zone=apex or ""))


# ---------------------------------------------------------------- API de distribuição
def _api_base():
    proto = request.headers.get("X-Forwarded-Proto", request.scheme)
    host = request.headers.get("X-Forwarded-Host", request.host)
    return f"{proto}://{host}/api/cert"


def _token_ok():
    # SOMENTE header Authorization — token em query string vaza em logs/referrers
    auth = request.headers.get("Authorization", "")
    tok = auth[7:].strip() if auth.startswith("Bearer ") else ""
    return bool(tok) and hmac.compare_digest(tok.encode(), core.CERT_API_TOKEN.encode())


def _api_guard():
    if not core.CERT_API_TOKEN:
        return Response("Cert API desativada (defina CERT_API_TOKEN).\n", 404,
                        mimetype="text/plain")
    if not _token_ok():
        return Response("Nao autorizado.\n", 401, mimetype="text/plain",
                        headers={"WWW-Authenticate": "Bearer"})
    return None


def _pem(data, filename, sensitive=False):
    h = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if sensitive:
        h["Cache-Control"] = "no-store"
    return Response(data, mimetype="application/x-pem-file", headers=h)


@app.route("/api/cert/info")
def api_cert_info():
    g = _api_guard()
    if g:
        return g
    info = core.cert_api_info(_zone_from_request())
    if not info:
        return Response("Sem certificado instalado.\n", 503, mimetype="text/plain")
    return jsonify(info)


@app.route("/api/cert/fullchain.pem")
def api_cert_fullchain():
    g = _api_guard()
    if g:
        return g
    crt, _ = core.cert_files(_zone_from_request())
    if not crt:
        return Response("Sem certificado.\n", 503, mimetype="text/plain")
    return _pem(crt, "fullchain.pem")


@app.route("/api/cert/privkey.pem")
def api_cert_privkey():
    g = _api_guard()
    if g:
        return g
    _, key = core.cert_files(_zone_from_request())
    if not key:
        return Response("Sem certificado.\n", 503, mimetype="text/plain")
    return _pem(key, "privkey.pem", sensitive=True)


@app.route("/api/cert/bundle.pem")
def api_cert_bundle():
    g = _api_guard()
    if g:
        return g
    crt, key = core.cert_files(_zone_from_request())
    if not crt:
        return Response("Sem certificado.\n", 503, mimetype="text/plain")
    return _pem(crt.rstrip() + b"\n" + key, "bundle.pem", sensitive=True)


INSTALL_SH = """#!/usr/bin/env bash
# Helios TLS — sincroniza o certificado curinga para um caminho local.
# Configure TOKEN/DEST/RELOAD_CMD e agende no cron (ex.: 0 */6 * * *).
set -euo pipefail
BASE="__BASE__"
TOKEN="${TOKEN:-COLE_SEU_TOKEN_AQUI}"
DEST="${DEST:-/etc/ssl/helios}"
RELOAD_CMD="${RELOAD_CMD:-}"   # ex.: "systemctl reload nginx"

mkdir -p "$DEST"
AUTH="Authorization: Bearer $TOKEN"
new=$(curl -fsS -H "$AUTH" "$BASE/info" | grep -o '"fingerprint":"[^"]*"' | cut -d'"' -f4)
old=$(cat "$DEST/.fingerprint" 2>/dev/null || true)
if [ -n "$new" ] && [ "$new" = "$old" ]; then echo "Certificado ja atualizado."; exit 0; fi
curl -fsS -H "$AUTH" "$BASE/fullchain.pem" -o "$DEST/fullchain.pem.tmp"
curl -fsS -H "$AUTH" "$BASE/privkey.pem"  -o "$DEST/privkey.pem.tmp"
mv "$DEST/fullchain.pem.tmp" "$DEST/fullchain.pem"
mv "$DEST/privkey.pem.tmp"  "$DEST/privkey.pem"
chmod 600 "$DEST/privkey.pem"
echo "$new" > "$DEST/.fingerprint"
echo "Certificado atualizado em $DEST/"
[ -n "$RELOAD_CMD" ] && eval "$RELOAD_CMD" && echo "Servico recarregado."
"""


@app.route("/api/cert/install.sh")
def api_cert_install():
    g = _api_guard()
    if g:
        return g
    body = INSTALL_SH.replace("__BASE__", _api_base())
    return Response(body, mimetype="text/x-shellscript",
                    headers={"Content-Disposition": 'attachment; filename="install-helios-cert.sh"'})


# ================================================================ UI
HEAD = """<!doctype html><html lang=pt-br><head><meta charset=utf-8><title>Helios TLS</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="icon" type="image/svg+xml" href="/favicon.svg?v={{version}}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#1c1813">
<script>(function(){try{if(localStorage.getItem('htheme')==='dark')document.documentElement.setAttribute('data-theme','dark');}catch(e){}})();
function toggleTheme(){var d=document.documentElement,dark=d.getAttribute('data-theme')!=='dark';if(dark){d.setAttribute('data-theme','dark');}else{d.removeAttribute('data-theme');}try{localStorage.setItem('htheme',dark?'dark':'light');}catch(e){}}
function _prog(){var p=document.getElementById('progress');if(!p)return;p.classList.add('go');var w=14;p.style.width='14%';clearInterval(window.__pg);window.__pg=setInterval(function(){w+=Math.random()*9;if(w>=92){clearInterval(window.__pg);}p.style.width=Math.min(w,92)+'%';},220);}
window.addEventListener('beforeunload',_prog);
window.addEventListener('pageshow',function(){var p=document.getElementById('progress');if(p){p.classList.remove('go');p.style.width='0';}});
document.addEventListener('submit',function(e){if(!e.defaultPrevented){_prog();}});
document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a[href]:not([href^="#"]):not([target])');if(a){_prog();}});
/* detector de atualização: imagem nova no servidor != versão desta página */
var APP_VERSION={{ version|tojson }};
setInterval(function(){fetch('/healthz').then(function(r){return r.json();}).then(function(d){
  if(d&&d.version&&d.version!==APP_VERSION){var b=document.getElementById('updbar');
    if(b&&b.style.display!=='flex'){b.querySelector('b').textContent='v'+d.version;b.style.display='flex';}}
}).catch(function(){});},60000);</script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#f4f2ee;--surface:#fffefb;--surface-2:#faf8f4;--border:#e9e4db;--border-strong:#ddd6ca;
--ink:#1c1813;--ink-2:#5d564d;--muted:#9a9287;--sun-1:#f6b73c;--sun-2:#e9701f;
--good:#15875a;--good-bg:#e8f5ee;--good-bd:#bfe3cf;--warn:#b9770a;--warn-bg:#fbf3df;--warn-bd:#f0dca6;
--err:#c8472f;--err-bg:#fbe9e4;--err-bd:#f1c7bb;
--shadow:0 1px 2px rgba(28,24,19,.05),0 18px 40px -22px rgba(28,24,19,.28);--radius:16px}
html,body{height:100%}
body{font-family:'Inter',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--ink);background:var(--bg);
background-image:radial-gradient(1100px 520px at 82% -10%,rgba(246,183,60,.16),transparent 60%),radial-gradient(820px 440px at -10% 6%,rgba(233,112,31,.08),transparent 55%);
-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;min-height:100%;padding:34px 24px 56px}
.wrap{width:100%;max-width:1440px;margin:0 auto}
.wrap.narrow{max-width:420px;padding-top:6vh}
.mark{flex:none;filter:drop-shadow(0 4px 10px rgba(233,112,31,.28))}
/* topbar */
.topbar{display:flex;align-items:center;gap:18px;margin-bottom:22px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:11px}
.brand .name{font-weight:800;font-size:18px;letter-spacing:-.02em;line-height:1}
.brand .name small{display:block;font-weight:500;font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-top:5px}
.tabs{display:flex;gap:4px;background:var(--surface);border:1px solid var(--border);border-radius:11px;padding:4px}
.tabs a{font-size:13.5px;font-weight:600;color:var(--ink-2);text-decoration:none;padding:8px 16px;border-radius:8px;transition:.15s}
.tabs a:hover{color:var(--ink)}
.tabs a.on{background:var(--ink);color:#fff}
.sp{flex:1}
.logout{display:inline-flex;align-items:center;gap:6px;font-size:13px;color:var(--ink-2);text-decoration:none;padding:8px 13px;border-radius:9px;border:1px solid var(--border);background:var(--surface)}
.logout:hover{color:var(--ink);border-color:var(--border-strong)}
/* grid */
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:18px;align-items:start}
.col-12{grid-column:span 12}.col-8{grid-column:span 8}.col-7{grid-column:span 7}
.col-6{grid-column:span 6}.col-5{grid-column:span 5}.col-4{grid-column:span 4}
@media(max-width:880px){.col-8,.col-7,.col-6,.col-5,.col-4{grid-column:span 12}}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);padding:24px}
.card.tight{padding:20px}
.eyebrow{font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--sun-2)}
h1{font-size:21px;letter-spacing:-.025em;margin:8px 0 6px;line-height:1.15}
.lead{color:var(--ink-2);font-size:13.5px;line-height:1.55}
.alerts{margin-bottom:18px;display:flex;flex-direction:column;gap:10px}
.alert{display:flex;gap:11px;align-items:flex-start;padding:13px 15px;border-radius:12px;font-size:13.5px;line-height:1.5;border:1px solid}
.alert svg{flex:none;margin-top:1px}
.alert.ok{background:var(--good-bg);border-color:var(--good-bd);color:#0f5f40}
.alert.error{background:var(--err-bg);border-color:var(--err-bd);color:#9a3320}
.alert.warn{background:var(--warn-bg);border-color:var(--warn-bd);color:#8a5807}
/* hero status */
.hero{display:flex;gap:28px;flex-wrap:wrap;align-items:center;margin-top:16px}
.hero .left{flex:1 1 260px;min-width:0}
.hero .right{flex:1 1 260px;min-width:0}
.status-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.status-cn{font-family:'JetBrains Mono',monospace;font-size:19px;font-weight:500;word-break:break-all}
.pill{flex:none;display:inline-flex;align-items:center;gap:5px;font-size:11.5px;font-weight:600;padding:4px 9px;border-radius:999px}
.pill.wild{background:linear-gradient(135deg,rgba(246,183,60,.2),rgba(233,112,31,.16));color:var(--sun-2);border:1px solid rgba(233,112,31,.25)}
.bar{height:8px;border-radius:999px;background:#ece6db;overflow:hidden;margin-top:8px}
.bar>i{display:block;height:100%;border-radius:999px}
.bar.is-good>i{background:linear-gradient(90deg,#1aa56b,#15875a)}
.bar.is-warn>i{background:linear-gradient(90deg,#e6a528,#b9770a)}
.barline{display:flex;justify-content:space-between;font-size:13px;color:var(--ink-2)}
.barline b{color:var(--ink);font-weight:700;font-size:15px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}
.chip{font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--ink-2);background:var(--surface-2);border:1px solid var(--border);border-radius:7px;padding:3px 8px}
.kk{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-top:14px;margin-bottom:6px}
/* fact list (sidebar) */
.facts{margin-top:6px}
.fact{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:11px 0;border-bottom:1px solid var(--border);font-size:13px}
.fact:last-child{border-bottom:0}.fact .k{color:var(--muted)}
.fact .v{font-weight:600;text-align:right;word-break:break-word}
.badge{display:inline-flex;align-items:center;gap:5px;font-size:11.5px;font-weight:700;padding:3px 9px;border-radius:999px;background:var(--good-bg);color:var(--good);border:1px solid var(--good-bd)}
.badge.off{background:var(--surface-2);color:var(--muted);border-color:var(--border)}
/* fields */
.field{margin-top:14px}
.field>label,.flabel{display:block;font-size:12px;font-weight:600;color:var(--ink);margin-bottom:6px}
.input{display:flex;align-items:center;gap:10px;padding:0 13px;background:var(--surface-2);border:1px solid var(--border-strong);border-radius:11px;transition:.15s}
.input:focus-within{border-color:var(--sun-2);background:#fff;box-shadow:0 0 0 3.5px rgba(233,112,31,.13)}
.input svg{flex:none;color:var(--muted)}
.input input,.input select{flex:1;min-width:0;border:0;outline:0;background:transparent;padding:11px 0;font:inherit;font-size:14px;color:var(--ink)}
.row{display:flex;gap:12px;flex-wrap:wrap}
.row>*{flex:1 1 220px;min-width:0}
.drop{display:flex;align-items:center;gap:14px;width:100%;cursor:pointer;padding:15px;border:1.5px dashed var(--border-strong);border-radius:13px;background:var(--surface-2);transition:.16s;text-align:left}
.drop:hover{border-color:var(--sun-2);background:#fffdf8}
.drop.drag{border-color:var(--sun-2);background:#fff7ea}
.drop.has-file{border-style:solid;border-color:var(--good-bd);background:var(--good-bg)}
.drop .ic{flex:none;width:40px;height:40px;border-radius:11px;display:grid;place-items:center;background:#fff;border:1px solid var(--border);color:var(--sun-2)}
.drop.has-file .ic{color:var(--good);border-color:var(--good-bd)}
.drop-main{flex:1;min-width:0}.drop-title{display:block;font-weight:600;font-size:14px}
.drop-sub{display:block;font-size:12.5px;color:var(--muted);margin-top:2px}
.drop-file{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--good);font-weight:500;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.drop-file:empty{display:none}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:9px;padding:12px 18px;border:0;border-radius:11px;cursor:pointer;font:inherit;font-weight:600;font-size:14.5px;color:#fff;background:linear-gradient(180deg,#2a241d,#1c1813);box-shadow:0 10px 22px -12px rgba(28,24,19,.7);transition:.16s;white-space:nowrap}
.btn:hover{transform:translateY(-1px)}.btn:active{transform:translateY(0)}
.btn.full{width:100%}.btn:disabled{opacity:.6;cursor:wait;transform:none}
.btn.ghost{background:none;color:var(--ink);border:1px solid var(--border-strong);box-shadow:none}
.btn.ghost:hover{border-color:var(--sun-2)}
.btn.sm{padding:10px 14px;font-size:13.5px}
.btn .spin{width:15px;height:15px;border:2px solid rgba(255,255,255,.35);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite;display:none}
.btn.loading .spin{display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}
.le-state{display:flex;gap:11px;align-items:center;padding:12px 14px;border-radius:11px;font-size:13.5px;border:1px solid var(--border);background:var(--surface-2);margin-top:16px}
.le-state.running{background:var(--warn-bg);border-color:var(--warn-bd);color:#8a5807}
.le-state.success{background:var(--good-bg);border-color:var(--good-bd);color:#0f5f40}
.le-state.error{background:var(--err-bg);border-color:var(--err-bd);color:#9a3320}
.dot{width:9px;height:9px;border-radius:50%;flex:none;background:var(--muted)}
.le-state.running .dot{background:#b9770a;animation:pulse 1s infinite}
.le-state.success .dot{background:var(--good)}.le-state.error .dot{background:var(--err)}
@keyframes pulse{50%{opacity:.3}}
.note{display:flex;gap:9px;align-items:flex-start;margin-top:16px;padding-top:14px;border-top:1px solid var(--border);font-size:12.5px;color:var(--ink-2);line-height:1.55}
.note svg{flex:none;margin-top:1px;color:var(--muted)}.note b{color:var(--ink)}
/* stat tiles */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:12px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:13px;padding:15px 17px;box-shadow:var(--shadow)}
.stat .n{font-size:25px;font-weight:800;letter-spacing:-.03em;line-height:1}
.stat .l{font-size:10.5px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);margin-top:6px;font-weight:600}
.stat.accent .n{color:var(--sun-2)}
/* table */
.tablehead{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;margin-bottom:8px}
.searchbox{display:flex;align-items:center;gap:8px;background:var(--surface-2);border:1px solid var(--border-strong);border-radius:10px;padding:0 12px;min-width:220px;flex:1;max-width:320px}
.searchbox svg{color:var(--muted);flex:none}
.searchbox input{border:0;outline:0;background:transparent;padding:9px 0;font:inherit;font-size:13.5px;width:100%}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);font-weight:600;padding:9px 10px;border-bottom:1px solid var(--border)}
td{padding:11px 10px;border-bottom:1px solid var(--border);vertical-align:middle}
tbody tr:hover td{background:var(--surface-2)}
.tag{font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600;padding:2px 7px;border-radius:6px;background:#eef0f2;color:#414b56}
.tag.A,.tag.AAAA{background:#e8f1fb;color:#1c4e80}.tag.CNAME{background:#eef0f2;color:#414b56}
.tag.TXT{background:#f3edfb;color:#5b3b86}.tag.MX{background:#fbf0e6;color:#8a5414}
.mono{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--ink-2);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:bottom}
.prox{font-size:11px;font-weight:700;color:var(--sun-2)}.prox.off{color:var(--muted)}
.acts{display:flex;gap:6px;justify-content:flex-end}
.iconbtn{display:grid;place-items:center;width:31px;height:31px;border-radius:8px;border:1px solid var(--border);background:var(--surface);color:var(--ink-2);cursor:pointer;transition:.15s}
.iconbtn:hover{color:var(--ink);border-color:var(--border-strong)}
.iconbtn.danger:hover{color:var(--err);border-color:var(--err-bd);background:var(--err-bg)}
dialog{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%) scale(.96);margin:0;border:0;border-radius:16px;padding:0;box-shadow:var(--shadow);max-width:460px;width:92%;max-height:90vh;overflow:auto;opacity:0;transition:opacity .18s ease,transform .18s ease}
dialog[open]{opacity:1;transform:translate(-50%,-50%) scale(1)}
dialog::backdrop{background:rgba(28,24,19,.4);backdrop-filter:blur(2px)}
#progress{position:fixed;top:0;left:0;height:3px;width:0;background:linear-gradient(90deg,#f6b73c,#e9701f);z-index:99999;opacity:0;transition:width .25s ease,opacity .35s ease;box-shadow:0 0 10px rgba(233,112,31,.55)}
#progress.go{opacity:1}
#updbar{display:none;position:fixed;right:18px;bottom:18px;z-index:9998;align-items:center;gap:9px;background:var(--surface);border:1px solid var(--warn-bd);box-shadow:var(--shadow);border-radius:12px;padding:11px 15px;font-size:13px;color:var(--ink)}
#updbar a{color:var(--sun-2);font-weight:600;text-decoration:none}#updbar a:hover{text-decoration:underline}
.rcomment{display:flex;align-items:center;gap:5px;font-size:11.5px;color:var(--ink-2);margin-top:4px;max-width:300px}
.rcomment span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rcomment svg{flex:none;color:var(--sun-2);opacity:.85}
.suffix{color:var(--muted);font-size:13px;white-space:nowrap;font-family:'JetBrains Mono',monospace;padding-right:2px;user-select:none}
.endpoints{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.endpoints code{font-family:'JetBrains Mono',monospace;font-size:12px;background:var(--surface-2);border:1px solid var(--border);border-radius:8px;padding:7px 11px;color:var(--ink-2)}
.cmd{font-family:'JetBrains Mono',monospace;font-size:11.5px;background:var(--ink);color:#f3ede2;border-radius:10px;padding:13px 15px;margin-top:8px;overflow-x:auto;white-space:pre;line-height:1.55}
[data-theme=dark] .cmd{background:#0f0d0a;border:1px solid var(--border)}
.skel{position:relative;overflow:hidden;background:var(--surface-2)}
.skel::after{content:"";position:absolute;inset:0;transform:translateX(-100%);background:linear-gradient(90deg,transparent,rgba(233,112,31,.10),transparent);animation:shimmer 1.3s infinite}
@keyframes shimmer{100%{transform:translateX(100%)}}
.dlg{padding:24px}.dlg h3{font-size:17px;margin-bottom:4px}
.switch{display:inline-flex;align-items:center;gap:9px;cursor:pointer;font-size:13px;font-weight:500;white-space:nowrap}
.switch input{display:none}
.switch .tr{width:38px;height:22px;border-radius:999px;background:var(--border-strong);position:relative;transition:.18s;flex:none}
.switch .tr::after{content:"";position:absolute;top:2px;left:2px;width:18px;height:18px;border-radius:50%;background:#fff;transition:.18s;box-shadow:0 1px 3px rgba(0,0,0,.2)}
.switch input:checked+.tr{background:var(--sun-2)}
.switch input:checked+.tr::after{transform:translateX(16px)}
.foot{text-align:center;margin-top:24px;font-size:12px;color:var(--muted)}
.foot code{font-family:'JetBrains Mono',monospace}
.empty{text-align:center;color:var(--muted);font-size:13.5px;padding:30px}
@media(max-width:560px){.topbar{gap:12px}.tabs{order:3;width:100%}.status-cn{font-size:16px}}
/* ---- modo escuro ---- */
[data-theme=dark]{--bg:#15120d;--surface:#211c15;--surface-2:#1a1610;--border:#352e24;--border-strong:#473d30;
--ink:#f2ede4;--ink-2:#bdb4a7;--muted:#8a8175;
--good:#43c08c;--good-bg:#15291f;--good-bd:#234634;--warn:#e6a52a;--warn-bg:#2b2410;--warn-bd:#4a3c18;
--err:#e26a52;--err-bg:#2c1714;--err-bd:#4a2920;
--shadow:0 1px 2px rgba(0,0,0,.4),0 22px 44px -24px rgba(0,0,0,.75)}
[data-theme=dark] body{background-image:radial-gradient(1100px 520px at 82% -10%,rgba(233,112,31,.13),transparent 60%),radial-gradient(820px 440px at -10% 6%,rgba(233,112,31,.06),transparent 55%)}
[data-theme=dark] .tabs a.on{background:var(--sun-2);color:#fff}
[data-theme=dark] .btn{background:linear-gradient(180deg,#ef7a27,#d9610f);color:#fff;box-shadow:0 10px 22px -12px rgba(0,0,0,.7)}
[data-theme=dark] .btn.ghost{background:none;color:var(--ink)}
[data-theme=dark] .bar{background:#2a241d}
[data-theme=dark] dialog{background:var(--surface)}
[data-theme=dark] .tag{background:#2a241d;color:#bdb4a7}
[data-theme=dark] .tag.A,[data-theme=dark] .tag.AAAA{background:#16273b;color:#86b3e6}
[data-theme=dark] .tag.CNAME{background:#2a241d;color:#b3a99d}
[data-theme=dark] .tag.TXT{background:#241a33;color:#bd9fe6}
[data-theme=dark] .tag.MX{background:#2e2212;color:#d59a4f}
</style></head><body><div id="progress"></div>
<div id="updbar">☀️ Nova versão <b></b> no servidor — <a href="javascript:location.reload()">recarregar</a></div>"""

MARK = """<svg class="mark" width="34" height="34" viewBox="0 0 34 34" fill="none">
<circle cx="17" cy="17" r="6.6" fill="url(#hg)"/>
<g stroke="url(#hg)" stroke-width="2.5" stroke-linecap="round">
<path d="M17 2.6v3.6"/><path d="M17 27.8v3.6"/><path d="M2.6 17h3.6"/><path d="M27.8 17h3.6"/>
<path d="M6.9 6.9l2.55 2.55"/><path d="M24.55 24.55l2.55 2.55"/><path d="M27.1 6.9l-2.55 2.55"/><path d="M9.45 24.55l-2.55 2.55"/></g>
<defs><linearGradient id="hg" x1="3" y1="3" x2="31" y2="31" gradientUnits="userSpaceOnUse">
<stop stop-color="#f6b73c"/><stop offset="1" stop-color="#e36a1f"/></linearGradient></defs></svg>"""

NAV = ('<div class="topbar"><div class="brand">' + MARK +
       '<div class="name">Helios<small>TLS Manager</small></div></div>'
       '<nav class="tabs">'
       '<a href="/" class="{{ \'on\' if active==\'home\' else \'\' }}">Certificado</a>'
       '<a href="/dns" class="{{ \'on\' if active==\'dns\' else \'\' }}">DNS</a>'
       '</nav><div class="sp"></div>'
       '<button class="logout" type="button" onclick="toggleTheme()" title="Alternar tema" '
       'style="cursor:pointer"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" '
       'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
       '<path d="M12 3a9 9 0 1 0 9 9 6 6 0 0 1-9-9Z"/></svg></button>'
       '<a class="logout" href="/logout">Sair</a></div>')

ALERTS = """{% with msgs = get_flashed_messages(with_categories=true) %}{% if msgs %}<div class="alerts">
{% for cat,m in msgs %}<div class="alert {{cat}}">
{% if cat=='ok' %}<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
{% elif cat=='warn' %}<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
{% else %}<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>{% endif %}
<span>{{m}}</span></div>{% endfor %}</div>{% endif %}{% endwith %}"""

LOGIN_HTML = HEAD + '<div class="wrap narrow"><div class="topbar"><div class="brand">' + MARK + \
    '<div class="name">Helios<small>TLS Manager</small></div></div></div><div class="card">' \
    '<div class="eyebrow">Acesso restrito</div><h1>Entrar no painel</h1>' \
    '<p class="lead">Emita, instale e gerencie o TLS do servidor.</p>' + ALERTS + """
<form method="post">
<input type="hidden" name="_csrf" value="{{ csrf_token() }}">
<div class="field"><label>Usuário</label><div class="input">
<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
<input type="text" name="user" autocomplete="username" autofocus placeholder="admin"></div></div>
<div class="field"><label>Senha</label><div class="input">
<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
<input type="password" name="password" autocomplete="current-password" placeholder="••••••••••"></div></div>
<button class="btn full" type="submit" style="margin-top:20px">Entrar</button></form></div>
<p class="foot">Servidor <code>{{server}}</code> · Traefik / Easypanel · v{{version}}</p></div></body></html>"""

INDEX_HTML = HEAD + '<div class="wrap">' + NAV + ALERTS + """
<div class="grid">

  {% if zone_errors %}
  <div class="col-12">{% for e in zone_errors %}<div class="alert warn" style="margin-bottom:8px">{{e}}</div>{% endfor %}</div>
  {% endif %}

  {% if zones and zones|length > 1 %}
  <div class="card col-12 tight">
    <div class="eyebrow">Zonas</div>
    <div class="chips" style="margin-top:10px">{% for z in zones %}
      <a class="chip" href="/?zone={{z.apex}}" style="text-decoration:none;{% if z.apex==current_zone %}border-color:var(--sun-2);color:var(--sun-2);font-weight:600{% endif %}">
        {{z.wildcard}}{% if z.is_default %} · padrão{% endif %}{% if z.status %} · {{z.status.days_left}}d{% else %} · sem cert{% endif %}
      </a>
    {% endfor %}</div>
  </div>
  {% endif %}

  {% if status %}
  <div class="card col-12">
    <div class="eyebrow">Certificado ativo no Traefik{% if current_zone %} · {{current_zone}}{% endif %}</div>
    <div class="hero">
      <div class="left">
        <div class="status-head">
          <span class="status-cn">{{status.cn}}</span>
          {% if status.is_wildcard %}<span class="pill wild">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v20M2 12h20M4.9 4.9l14.2 14.2M19.1 4.9 4.9 19.1"/></svg>curinga</span>{% endif %}
        </div>
        <div class="kk">Domínios cobertos</div>
        <div class="chips">{% for s in status.sans %}<span class="chip">{{s}}</span>{% endfor %}
          {% if not status.sans %}<span class="chip">{{status.cn}}</span>{% endif %}</div>
      </div>
      <div class="right">
        {% set raw = (status.days_left * 100 // 90) %}{% set pct = [[raw,100]|min, 4]|max %}
        <div class="barline"><span>Validade restante</span><span><b>{{status.days_left}}</b> dias</span></div>
        <div class="bar {{ 'is-warn' if status.days_left < 21 else 'is-good' }}"><i style="width:{{pct}}%"></i></div>
        <div class="kk">Expira em</div>
        <div style="font-weight:600;font-size:14px">{{status.not_after.strftime('%d/%m/%Y')}}{% if status.issuer %} · <span style="color:var(--ink-2);font-weight:500">{{status.issuer}}</span>{% endif %}</div>
      </div>
    </div>
  </div>
  {% endif %}

  <div class="card col-8">
    <div class="eyebrow">Let's Encrypt · curinga automático</div>
    <h1>Emitir via DNS-01</h1>
    <p class="lead">Gera <code>{{current_zone and ('*.' + current_zone) or le_domain}}</code> validando por DNS na Cloudflare — sem expor o servidor.</p>
    {% if not can_issue %}
    <div class="le-state error"><span class="dot"></span><span>{{why}}</span></div>
    {% else %}
    <div id="lebox" class="le-state {{le.status}}"><span class="dot"></span>
      <span id="lemsg">{% if le.status=='idle' %}Pronto para emitir. Recomendado testar no staging primeiro.{% else %}{{le.message}}{% endif %}</span></div>
    <div class="row" style="margin-top:16px">
      <form method="post" action="/issue"><input type="hidden" name="env" value="staging"><input type="hidden" name="zone" value="{{current_zone or ''}}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}">
        <button class="btn ghost full" type="submit">Testar no staging</button></form>
      <form method="post" action="/issue"><input type="hidden" name="env" value="prod"><input type="hidden" name="zone" value="{{current_zone or ''}}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}">
        <button class="btn full" type="submit">Emitir / Renovar produção</button></form>
    </div>
    {% endif %}
    <div class="note"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
      <span>O <b>staging</b> valida o fluxo sem gastar cota; a <b>produção</b> emite o certificado confiável e instala no Traefik.</span></div>
  </div>

  <div class="card col-4 tight">
    <div class="eyebrow">Configuração</div>
    <div class="facts">
      <div class="fact"><span class="k">Auto-renovação</span><span class="v"><span class="badge"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>ativa</span></span></div>
      <div class="fact"><span class="k">Zona ativa</span><span class="v">{{current_zone or le_domain}}</span></div>
      <div class="fact"><span class="k">Zonas</span><span class="v">{{zones|length}}</span></div>
      <div class="fact"><span class="k">Provedor DNS</span><span class="v">Cloudflare</span></div>
      <div class="fact"><span class="k">Conta LE</span><span class="v" style="font-size:12px">{{le_email or '—'}}</span></div>
      <div class="fact"><span class="k">Cert padrão</span><span class="v"><span class="badge {{ '' if set_default else 'off' }}">{{ 'sim' if set_default else 'não' }}</span></span></div>
      <div class="fact"><span class="k">Versão</span><span class="v">v{{version}}</span></div>
    </div>
  </div>

  {% if api_enabled %}
  <div class="card col-12">
    <div class="eyebrow">Distribuição · API de certificado</div>
    <h1>Usar em outras aplicações</h1>
    <p class="lead">Endpoints autenticados por token para apps internas baixarem o certificado e renovarem sozinhas (cron). A app aponta para o arquivo local; o script re-busca e recarrega quando muda.</p>
    <div class="endpoints">
      <code>GET {{api_base}}/info</code>
      <code>GET {{api_base}}/fullchain.pem</code>
      <code>GET {{api_base}}/privkey.pem</code>
      <code>GET {{api_base}}/bundle.pem</code>
    </div>
    <div class="kk">Instalação no servidor consumidor (com cron)</div>
    <pre class="cmd">TOKEN=SEU_TOKEN
curl -fsS -H "Authorization: Bearer $TOKEN" {{api_base}}/install.sh -o /usr/local/bin/helios-cert.sh
chmod +x /usr/local/bin/helios-cert.sh
TOKEN=$TOKEN DEST=/etc/ssl/helios RELOAD_CMD="systemctl reload nginx" /usr/local/bin/helios-cert.sh
# cron (a cada 6h):  0 */6 * * * TOKEN=... DEST=/etc/ssl/helios RELOAD_CMD="systemctl reload nginx" /usr/local/bin/helios-cert.sh</pre>
    <div class="note"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <span>Autentique pelo <b>header Authorization</b> (não use <code>?token=</code> — aparece no log). A rota <code>privkey.pem</code> entrega a <b>chave privada</b>: mantenha tudo na rede interna.</span></div>
  </div>
  {% endif %}

  <div class="card col-12">
    <div class="eyebrow">Alternativa</div>
    <h1>Upload manual</h1>
    <p class="lead">Já tem o certificado emitido? Envie a cadeia e a chave.</p>
    <form class="upload" method="post" action="/upload" enctype="multipart/form-data">
      <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
      <input type="hidden" name="zone" value="{{current_zone or ''}}">
      <div class="row" style="margin-top:14px">
        <label class="drop" id="d-crt"><input type="file" name="crt" accept=".crt,.pem,.cer,.txt" hidden>
          <span class="ic"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 15l2 2 4-4"/></svg></span>
          <span class="drop-main"><span class="drop-title">Cadeia (fullchain)</span><span class="drop-sub">.crt / .pem</span></span><span class="drop-file"></span></label>
        <label class="drop" id="d-key"><input type="file" name="key" accept=".key,.pem,.txt" hidden>
          <span class="ic"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="3.5"/><path d="m10 13 8.5-8.5"/><path d="m16 5 2.5 2.5"/><path d="m13.5 7.5 2.5 2.5"/></svg></span>
          <span class="drop-main"><span class="drop-title">Chave privada</span><span class="drop-sub">.key — PEM sem senha</span></span><span class="drop-file"></span></label>
      </div>
      <button class="btn full" type="submit" style="margin-top:16px">Instalar e aplicar</button>
    </form>
  </div>
</div>
<p class="foot">Servidor <code>{{server}}</code> · alterações em <code>/etc/easypanel/traefik</code> · v{{version}}</p></div>

<script>
document.querySelectorAll('.drop').forEach(function(z){
  var i=z.querySelector('input[type=file]'),o=z.querySelector('.drop-file');
  function s(){if(i.files&&i.files.length){o.textContent=i.files[0].name+' · '+(i.files[0].size/1024).toFixed(1)+' KB';z.classList.add('has-file');}}
  i.addEventListener('change',s);
  ['dragenter','dragover'].forEach(e=>z.addEventListener(e,v=>{v.preventDefault();z.classList.add('drag');}));
  ['dragleave','dragend'].forEach(e=>z.addEventListener(e,v=>{v.preventDefault();z.classList.remove('drag');}));
  z.addEventListener('drop',v=>{v.preventDefault();z.classList.remove('drag');if(v.dataTransfer.files.length){i.files=v.dataTransfer.files;s();}});
});
document.querySelectorAll('form.upload,form[action="/issue"]').forEach(function(f){
  f.addEventListener('submit',function(){var b=f.querySelector('button');b.classList.add('loading');b.disabled=true;});
});
/* status do Let's Encrypt sempre ao vivo (não só quando já carregou 'running') */
var box=document.getElementById('lebox');
if(box){
  var lemsg=document.getElementById('lemsg'),fails=0;
  var t=setInterval(function(){
    fetch('/issue/status?zone='+encodeURIComponent({{ current_zone|tojson }}||'')).then(function(r){
      if(r.status===401){clearInterval(t);box.className='le-state error';
        lemsg.textContent='Sessão expirada — recarregue a página e entre de novo.';return null;}
      return r.json();
    }).then(function(d){
      if(!d)return;fails=0;
      var wasRunning=box.classList.contains('running');
      box.className='le-state '+d.status;
      if(d.status==='idle'){lemsg.textContent='Pronto para emitir. Recomendado testar no staging primeiro.';}
      else{var at=d.at?'  ·  '+new Date(d.at).toLocaleTimeString():'';lemsg.textContent=(d.message||'')+at;}
      if(wasRunning && d.status!=='running'){clearInterval(t);setTimeout(function(){location.reload();},1200);}
    }).catch(function(){if(++fails>5)clearInterval(t);});
  },4000);
}
</script></body></html>"""

DNS_HTML = HEAD + '<div class="wrap">' + NAV + ALERTS + """
{% set cnt = {'A': records|selectattr('type','equalto','A')|list|length,
              'AAAA': records|selectattr('type','equalto','AAAA')|list|length,
              'CNAME': records|selectattr('type','equalto','CNAME')|list|length,
              'TXT': records|selectattr('type','equalto','TXT')|list|length,
              'MX': records|selectattr('type','equalto','MX')|list|length} %}
<div class="grid">
  <div class="col-12 stats">
    <div class="stat accent"><div class="n">{{records|length}}</div><div class="l">Total · {{base}}</div></div>
    <div class="stat"><div class="n">{{cnt.A + cnt.AAAA}}</div><div class="l">A / AAAA</div></div>
    <div class="stat"><div class="n">{{cnt.CNAME}}</div><div class="l">CNAME</div></div>
    <div class="stat"><div class="n">{{cnt.TXT}}</div><div class="l">TXT</div></div>
    <div class="stat"><div class="n">{{cnt.MX}}</div><div class="l">MX</div></div>
  </div>

  {% if zones and zones|length > 1 %}
  <div class="card col-12 tight">
    <div class="eyebrow">Zona DNS</div>
    <div class="chips" style="margin-top:10px">{% for z in zones %}
      <a class="chip" href="/dns?zone={{z.apex}}" style="text-decoration:none;{% if z.apex==current_zone %}border-color:var(--sun-2);color:var(--sun-2);font-weight:600{% endif %}">{{z.apex}}</a>
    {% endfor %}</div>
  </div>
  {% endif %}

  <div class="card col-12">
    <div class="eyebrow">Novo registro</div>
    {% if err %}<div class="le-state error" style="margin-top:12px"><span class="dot"></span><span>{{err}}</span></div>{% endif %}
    <form method="post" action="/dns/create" id="createForm" style="margin-top:14px">
      <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
      <input type="hidden" name="zone" value="{{current_zone or base}}">
      <div class="row" style="align-items:flex-end">
        <div style="flex:0 1 110px"><span class="flabel">Tipo</span><div class="input"><select name="type" id="ctype">{% for t in types %}<option>{{t}}</option>{% endfor %}</select></div></div>
        <div style="flex:2 1 210px"><span class="flabel">Nome (subdomínio)</span><div class="input"><input name="name" id="cname" placeholder="subdominio  ·  @ p/ raiz" required oninput="syncSuffix(this,csuf)" autocomplete="off"><span class="suffix" id="csuf">.{{base}}</span></div></div>
        <div style="flex:3 1 220px"><span class="flabel">Conteúdo</span><div class="input"><input name="content" id="ccontent" placeholder="IP, destino, valor…" required></div></div>
        <div style="flex:0 1 90px" id="cprio" hidden><span class="flabel">Prioridade</span><div class="input"><input name="priority" type="number" value="10"></div></div>
        <div style="flex:0 1 90px"><span class="flabel">TTL</span><div class="input"><input name="ttl" type="number" value="1" title="1 = automático"></div></div>
      </div>
      <div class="row" style="margin-top:14px;align-items:center">
        <label class="switch" id="cproxwrap" style="flex:0 0 auto"><input type="checkbox" name="proxied" id="cprox"><span class="tr"></span>Proxy Cloudflare</label>
        <div style="flex:1 1 240px"><div class="input"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 10h8"/><path d="M8 14h5"/><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2Z"/></svg><input name="comment" placeholder="Comentário / descrição (opcional)"></div></div>
        <button class="btn sm" type="submit" style="flex:0 0 auto">Adicionar registro</button>
      </div>
    </form>
  </div>

  <div class="card col-12">
    <div class="tablehead">
      <div class="eyebrow">Registros</div>
      <div class="searchbox"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
        <input id="filter" placeholder="Filtrar por nome, conteúdo ou tipo…"></div>
    </div>
    {% if records %}
    <div style="overflow-x:auto">
    <table><thead><tr><th>Tipo</th><th>Nome</th><th>Conteúdo</th><th>TTL</th><th>Proxy</th><th></th></tr></thead><tbody id="dnsbody">
    {% for r in records %}
    <tr data-s="{{r.type|lower}} {{r.name|lower}} {{r.content|lower}} {{r.comment|lower}}">
      <td><span class="tag {{r.type}}">{{r.type}}</span></td>
      <td><span class="mono" title="{{r.name}}">{{r.name}}</span>{% if r.comment %}<div class="rcomment" title="{{r.comment}}"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2Z"/></svg><span>{{r.comment}}</span></div>{% endif %}</td>
      <td><span class="mono" title="{{r.content}}">{% if r.type=='MX' %}[{{r.priority}}] {% endif %}{{r.content}}</span></td>
      <td>{{ 'auto' if r.ttl==1 else r.ttl }}</td>
      <td><span class="prox {{ '' if r.proxied else 'off' }}">{{ 'on' if r.proxied else '—' }}</span></td>
      <td><div class="acts">
        <button class="iconbtn" title="Editar" data-id="{{r.id}}" data-type="{{r.type}}" data-name="{{r.name}}" data-content="{{r.content}}" data-ttl="{{r.ttl}}" data-proxied="{{1 if r.proxied else 0}}" data-priority="{{r.priority or ''}}" data-comment="{{r.comment}}" onclick="openEdit(this)">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg></button>
        <form method="post" action="/dns/delete" onsubmit="return confirm('Excluir {{r.type}} {{r.name}}?')" style="display:inline">
          <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
          <input type="hidden" name="zone" value="{{current_zone or base}}">
          <input type="hidden" name="id" value="{{r.id}}">
          <button class="iconbtn danger" title="Excluir" type="submit"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button></form>
      </div></td>
    </tr>{% endfor %}
    </tbody></table></div>
    <div id="noresult" class="empty" hidden>Nenhum registro corresponde ao filtro.</div>
    {% else %}<div class="empty">Nenhum registro encontrado.</div>{% endif %}
  </div>
</div>
<p class="foot">Servidor <code>{{server}}</code> · Cloudflare API · v{{version}}</p></div>

<dialog id="editDlg"><form method="post" action="/dns/edit" class="dlg">
  <h3>Editar registro</h3><p class="lead" id="edlabel"></p>
  <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
  <input type="hidden" name="zone" value="{{current_zone or base}}">
  <input type="hidden" name="id" id="eid">
  <div class="row" style="margin-top:16px">
    <div style="flex:0 1 120px"><span class="flabel">Tipo</span><div class="input"><select name="type" id="etype">{% for t in types %}<option>{{t}}</option>{% endfor %}</select></div></div>
    <div style="flex:1 1 200px"><span class="flabel">Nome (subdomínio)</span><div class="input"><input name="name" id="ename" required oninput="syncSuffix(this,esuf)" autocomplete="off"><span class="suffix" id="esuf">.{{base}}</span></div></div>
  </div>
  <div class="field"><label>Conteúdo</label><div class="input"><input name="content" id="econtent" required></div></div>
  <div class="field"><label>Comentário / descrição</label><div class="input"><input name="comment" id="ecomment" placeholder="opcional"></div></div>
  <div class="row" style="margin-top:10px">
    <div style="flex:0 1 120px" id="eprio" hidden><span class="flabel">Prioridade</span><div class="input"><input name="priority" id="epriority" type="number"></div></div>
    <div style="flex:1"><span class="flabel">TTL</span><div class="input"><input name="ttl" id="ettl" type="number"></div></div>
  </div>
  <label class="switch" id="eproxwrap" style="margin-top:14px"><input type="checkbox" name="proxied" id="eprox"><span class="tr"></span>Proxy Cloudflare</label>
  <div class="row" style="margin-top:20px">
    <button type="button" class="btn ghost" onclick="editDlg.close()">Cancelar</button>
    <button type="submit" class="btn">Salvar</button>
  </div>
</form></dialog>

<script>
var PROX = {{ proxiable|tojson }};
var BASE = {{ base|tojson }};
function stripBase(n){if(n===BASE)return '@';var s='.'+BASE;return (n.length>=s.length&&n.slice(-s.length)===s)?n.slice(0,-s.length):n;}
function syncSuffix(inp,suf){if(!suf)return;var v=inp.value.trim(),s='.'+BASE;suf.style.display=(v==='@'||(v.length>=s.length&&v.slice(-s.length)===s))?'none':'';}
function syncType(sel,pw,prw){var t=sel.value;pw.style.display=PROX.indexOf(t)>=0?'inline-flex':'none';prw.hidden=(t!=='MX');}
var ct=document.getElementById('ctype');
ct.addEventListener('change',()=>syncType(ct,cproxwrap,cprio));syncType(ct,cproxwrap,cprio);
var dlg=document.getElementById('editDlg');
function openEdit(b){eid.value=b.dataset.id;etype.value=b.dataset.type;ename.value=stripBase(b.dataset.name);syncSuffix(ename,esuf);econtent.value=b.dataset.content;ettl.value=b.dataset.ttl;eprox.checked=b.dataset.proxied==='1';epriority.value=b.dataset.priority;ecomment.value=b.dataset.comment||'';edlabel.textContent=b.dataset.type+'  ·  '+b.dataset.name;syncType(etype,eproxwrap,eprio);dlg.showModal();}
etype.addEventListener('change',()=>syncType(etype,eproxwrap,eprio));
var fi=document.getElementById('filter');
if(fi){fi.addEventListener('input',function(){var q=this.value.toLowerCase().trim(),n=0,rows=document.querySelectorAll('#dnsbody tr');
  rows.forEach(function(r){var ok=r.dataset.s.indexOf(q)>=0;r.style.display=ok?'':'none';if(ok)n++;});
  document.getElementById('noresult').hidden=(n>0);});}
</script></body></html>"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
