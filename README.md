<div align="center">

# ☀️ Helios TLS Manager

**Emita, instale e renove certificados curinga (wildcard) no Traefik do Easypanel — e gerencie o DNS da Cloudflare — por uma interface simples.**

[![CI](https://github.com/Yefclub/helios-tls/actions/workflows/ci.yml/badge.svg)](https://github.com/Yefclub/helios-tls/actions/workflows/ci.yml)
[![Security](https://github.com/Yefclub/helios-tls/actions/workflows/security.yml/badge.svg)](https://github.com/Yefclub/helios-tls/actions/workflows/security.yml)
[![Docker](https://github.com/Yefclub/helios-tls/actions/workflows/docker.yml/badge.svg)](https://github.com/Yefclub/helios-tls/actions/workflows/docker.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## O que é

Uma aplicação web leve (Flask) pensada para rodar **dentro de um Easypanel**. Ela:

- 🔐 **Emite certificados curinga** (`*.seudominio.com`) pelo **Let's Encrypt** usando o desafio **DNS-01** (via [`lego`](https://go-acme.github.io/lego/) + API da Cloudflare). Como é DNS-01, **o servidor não precisa estar exposto à internet**.
- ♻️ **Renova automaticamente** (agendador interno; renova quando faltam menos de 30 dias).
- 🚚 **Instala no Traefik** do Easypanel — registra o certificado por SNI e, opcionalmente, como certificado **padrão (catch-all)** — e dispara o *reload* automático.
- 📤 **Upload manual** de certificado (cadeia + chave) como alternativa.
- 🌐 **Gerencia o DNS da Cloudflare** — lista, cria, edita e exclui registros (com comentários/descrições), tudo pelo SDK oficial.
- 📡 **Distribui o certificado** para outras apps internas via endpoints autenticados (`/api/cert/*`) — elas baixam por cron e renovam sozinhas.
- 🌙 Interface responsiva com **modo escuro**.

## API de distribuição do certificado

Defina `CERT_API_TOKEN` para ligar endpoints autenticados (token via header `Authorization: Bearer`). Servem o certificado para apps internas que precisam de um **arquivo local** (nginx, Apache, HAProxy…). O consumidor baixa por cron → aponta para o arquivo local → a renovação se propaga sozinha.

| Endpoint | Retorna |
|---|---|
| `GET /api/cert/info` | metadados (CN, SANs, validade, fingerprint) — JSON |
| `GET /api/cert/fullchain.pem` | cadeia pública |
| `GET /api/cert/privkey.pem` | chave privada (**segredo**) |
| `GET /api/cert/bundle.pem` | cadeia + chave |
| `GET /api/cert/install.sh` | script de sincronização (cron) com o domínio preenchido |

```bash
# no servidor consumidor:
TOKEN=seu-token
curl -fsS -H "Authorization: Bearer $TOKEN" https://SEU-DOMINIO/api/cert/install.sh -o /usr/local/bin/helios-cert.sh
chmod +x /usr/local/bin/helios-cert.sh
# cron (a cada 6h): re-baixa só se mudou e recarrega o serviço
0 */6 * * * TOKEN=$TOKEN DEST=/etc/ssl/helios RELOAD_CMD="systemctl reload nginx" /usr/local/bin/helios-cert.sh
```

> ⚠️ A `privkey.pem` entrega a **chave privada** — use **apenas na rede interna**, sempre por **HTTPS**. O token é aceito **somente** pelo header `Authorization` (query string vaza em logs e foi propositalmente desabilitada).

## Como funciona

```
┌───────────────────────────────┐   DNS-01 (TXT _acme-challenge)   ┌────────────┐
│  Helios TLS (no Easypanel)    │ ───────────────────────────────▶ │ Cloudflare │
│  • lego  → emite/renova        │ ◀──── certificado curinga ───┐   │   (API)    │
│  • escreve em /data (Traefik)  │        Let's Encrypt          │   └────────────┘
└───────────────┬───────────────┘                               ▼
                │ reload por file-watch              *.seudominio.com (fullchain+key)
                ▼
        Traefik do Easypanel  →  serve o curinga para todos os subdomínios
```

A aplicação escreve diretamente na pasta do Traefik do Easypanel (montada como `/data`):
`certs/wildcard.crt|key`, `config/custom.yaml` (lista `tls.certificates`) e, se `SET_DEFAULT=true`, `default.cert|key` (o slot de certificado padrão que o Easypanel já gerencia).

## Requisitos

- Easypanel (Docker Swarm + Traefik) — padrão.
- Domínio gerenciado na **Cloudflare** + um **token de API** (`Zone.DNS = Edit` e `Zone.Zone = Read` na zona).
- O Traefik com file-provider observando `config/` (padrão do Easypanel).

## Variáveis de ambiente

| Variável | Obrigatória | Descrição |
|---|:---:|---|
| `APP_USER` / `APP_PASSWORD` | ✅ | Login do painel |
| `SECRET_KEY` | ✅ | Segredo da sessão Flask |
| `CLOUDFLARE` | ✅ | Token de API da Cloudflare |
| `LE_EMAIL` | ✅ | E-mail da conta Let's Encrypt |
| `LE_DOMAIN` | ✅ | Domínio curinga, ex. `*.seudominio.com` |
| `LE_RESOLVERS` | — | Resolvers p/ checagem de propagação (padrão `1.1.1.1:53,8.8.8.8:53`) |
| `SET_DEFAULT` | — | Instala como cert padrão/catch-all (padrão `true`) |
| `RUN_SCHEDULER` | — | Liga a auto-renovação (padrão `true`) |
| `SERVER_LABEL` | — | Rótulo no rodapé |

Veja [`.env.example`](.env.example).

## Deploy no Easypanel

Imagem pronta (multi-arch `amd64`/`arm64`, com SBOM e provenance):

```
ghcr.io/yefclub/helios-tls:latest
```

1. Crie um serviço **App** apontando para a imagem acima (ou faça build do repositório).
2. **Bind mount** (essencial): host `/etc/easypanel/traefik` → container `/data`.
3. Defina as **variáveis de ambiente** (acima).
4. Publique uma **porta** (ex.: `8082 → 8080`).
5. Deploy. Acesse o painel, faça login e clique em **Testar no staging** → **Emitir / Renovar (produção)**.

> ⚠️ Se a porta for publicada em **host-mode** com réplica única, use atualização **stop-first** (evita o conflito "host-mode port already in use").

## Desenvolvimento local

```bash
pip install -r requirements.txt -r requirements-dev.txt
export APP_PASSWORD=teste CLOUDFLARE=token LE_EMAIL=... LE_DOMAIN='*.seudominio.com'
python app.py   # http://localhost:8080

pytest          # testes
ruff check .    # lint
```

O `lego` precisa estar no PATH para a emissão (já incluso na imagem Docker).

## Segurança

- A aplicação controla **DNS e TLS** e guarda o **token da Cloudflare** → mantenha-a **restrita à rede interna** (ou atrás de autenticação) e **não exponha** publicamente.
- Login com comparação em tempo constante, **bloqueio após 5 tentativas** (5 min) e atraso anti força-bruta; forms protegidos por **token CSRF**; cookies de sessão `HttpOnly` + `SameSite=Lax` (defina `COOKIE_SECURE=true` quando servir por HTTPS).
- A API de distribuição autentica **apenas** pelo header `Authorization: Bearer` (comparação em tempo constante).
- O transporte/instalação acontece localmente, dentro do servidor.
- Nunca versione `.env`, `.admin-password` nem certificados (já cobertos pelo `.gitignore`).

## CI/CD

| Workflow | O que faz |
|---|---|
| `ci.yml` | ruff + pytest + hadolint (Dockerfile) + actionlint (workflows) |
| `security.yml` | CodeQL, pip-audit, Trivy (filesystem + imagem), Dependency Review; roda também toda segunda |
| `docker.yml` | build multi-arch (`amd64`/`arm64`) → `ghcr.io`, com SBOM + provenance; tag `vX.Y.Z` gera Release com notas automáticas |

Dependabot atualiza pip, Docker e Actions semanalmente. Actions pinadas por SHA.

**Release:** `git tag v1.0.0 && git push --tags` → imagem `:1.0.0`/`:latest` + GitHub Release.

## Estrutura

| Arquivo | Descrição |
|---|---|
| `app.py` | Rotas Flask + interface (templates inline) |
| `core.py` | Instalação no Traefik, emissão LE (lego), DNS manager (Cloudflare) |
| `tests/` | Testes (pytest) |
| `.github/` | Workflows de CI/CD + Dependabot |
| `Dockerfile` | Imagem (Python + lego + SDK) |
| `requirements.txt` | Dependências |

## Licença

[MIT](LICENSE).
