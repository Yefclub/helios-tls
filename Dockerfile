FROM python:3.12-slim

ARG LEGO_VERSION=v5.2.2
# preenchido pelo buildx (amd64 | arm64); default p/ docker build sem buildkit
ARG TARGETARCH=amd64
WORKDIR /app

# lego (cliente ACME para emissão DNS-01) — binário único
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && curl -fsSL "https://github.com/go-acme/lego/releases/download/${LEGO_VERSION}/lego_${LEGO_VERSION}_linux_${TARGETARCH}.tar.gz" -o /tmp/lego.tgz \
 && tar -xzf /tmp/lego.tgz -C /usr/local/bin lego \
 && rm /tmp/lego.tgz \
 && apt-get purge -y --auto-remove curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./

EXPOSE 8080
# 1 worker (agendador de renovação roda 1x) + threads para concorrência;
# timeout alto cobre a emissão DNS-01; logs no stdout/stderr.
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "8", \
     "--timeout", "300", "--access-logfile", "-", "--error-logfile", "-", \
     "--access-logformat", "%(h)s %(t)s \"%(r)s\" %(s)s %(b)s", "app:app"]
