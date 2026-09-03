FROM python:3.13-alpine3.23@sha256:7ea3f82de8ea6d4fb7e5d2bbe3fe3c9d931700b7a529f1fe5769e42abe514ca1 AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY requirements.txt .
RUN python -m pip wheel --wheel-dir=/wheels --require-hashes --requirement requirements.txt

FROM python:3.13-alpine3.23@sha256:7ea3f82de8ea6d4fb7e5d2bbe3fe3c9d931700b7a529f1fe5769e42abe514ca1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app
RUN apk add --no-cache \
      'openssl=3.5.8-r0' \
      'sqlite-libs=3.53.4-r0'
COPY --from=build /wheels /wheels
COPY requirements.txt .
RUN python -m pip install --no-index --find-links=/wheels --require-hashes --requirement requirements.txt \
    && python -m pip uninstall --yes pip \
    && rm -rf /wheels /root/.cache

# Application code stays root-owned and read-only for the runtime UID. The only
# writable locations are the mounted state and staging volumes.
COPY app ./app
COPY frontend ./frontend
COPY main.py ./main.py
COPY dropctl.py ./dropctl.py

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]

CMD ["python", "main.py"]
