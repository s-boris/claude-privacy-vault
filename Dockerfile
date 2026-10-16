# claude-vault: the owner's privacy vault (raw Telegram archive + session, paperless/Firefly tokens, local LLM).
# Built on the Unraid host by `vault admin deploy` (from the assistant's ~/opt/claude-vault). Everything pinned:
# base image by digest, llama.cpp by tag + commit, Python deps by sha256.
ARG BASE=debian@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

# ---------------------------------------------------------------- llama.cpp (llama-server only, static, no TLS)
FROM ${BASE} AS llama
ARG LLAMA_TAG=b11669
ARG LLAMA_COMMIT=620d2225cc436ab0b001e3200e590e3b286ef9ab
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential cmake git ca-certificates libgomp1 && rm -rf /var/lib/apt/lists/*
RUN git clone -q --depth 1 --branch "$LLAMA_TAG" https://github.com/ggml-org/llama.cpp.git /src \
 && test "$(git -C /src rev-parse HEAD)" = "$LLAMA_COMMIT" \
 && cmake -S /src -B /src/build -DCMAKE_BUILD_TYPE=Release -DGGML_NATIVE=ON -DLLAMA_OPENSSL=OFF \
      -DBUILD_SHARED_LIBS=OFF -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_UI=OFF \
      -DLLAMA_BUILD_SERVER=ON >/dev/null \
 && cmake --build /src/build --target llama-server -j"$(nproc)" >/dev/null \
 && install -D -m 755 /src/build/bin/llama-server /out/llama-server \
 && /out/llama-server --version

# ---------------------------------------------------------------- sqlite-vec (memory plan C3): one C file, sha256-pinned
FROM ${BASE} AS vec
ARG VEC_VERSION=0.1.9
ARG VEC_SHA256=3acd67cb4aff080c7050926fd3cf8227905fe5b7ee3829d8ee5024ab1283cf61
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential libsqlite3-dev curl ca-certificates python3 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/vec.tgz \
      "https://github.com/asg017/sqlite-vec/releases/download/v${VEC_VERSION}/sqlite-vec-${VEC_VERSION}-amalgamation.tar.gz" \
 && echo "${VEC_SHA256}  /tmp/vec.tgz" | sha256sum -c --quiet \
 && mkdir /src && tar -xzf /tmp/vec.tgz -C /src \
 && gcc -O2 -fPIC -shared /src/sqlite-vec.c -o /out-vec0.so -lm \
 && install -D -m 644 /out-vec0.so /out/vec0.so \
 && python3 -I -c "import sqlite3; c = sqlite3.connect(':memory:'); c.enable_load_extension(True); \
c.load_extension('/out/vec0'); v = c.execute('select vec_version()').fetchone()[0]; assert v == 'v${VEC_VERSION}', v"

# ---------------------------------------------------------------- Python deps for tgread + the Firefly sync (hash-pinned)
FROM ${BASE} AS pydeps
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-venv ca-certificates && rm -rf /var/lib/apt/lists/*
COPY requirements/ /req/
RUN python3 -m venv /opt/vault/venv \
 && /opt/vault/venv/bin/pip install -q --disable-pip-version-check --no-cache-dir --require-hashes --no-deps \
      -r /req/build.txt \
 && /opt/vault/venv/bin/pip install -q --disable-pip-version-check --no-cache-dir --require-hashes --no-deps \
      --no-build-isolation --use-pep517 -r /req/tgread.txt \
 && /opt/vault/venv/bin/pip install -q --disable-pip-version-check --no-cache-dir --require-hashes --no-deps \
      --only-binary :all: -r /req/finance.txt \
 && /opt/vault/venv/bin/pip uninstall -q -y pip setuptools

# ---------------------------------------------------------------- runtime
FROM ${BASE}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 ca-certificates tzdata libgomp1 poppler-utils zbar-tools python3-pil \
      tesseract-ocr tesseract-ocr-eng tesseract-ocr-deu tesseract-ocr-fra tesseract-ocr-ita \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --user-group --home-dir /data/home --no-create-home --shell /usr/sbin/nologin vault \
 && mkdir -p /data && chown 10001:10001 /data && chmod 700 /data
COPY --from=llama /out/llama-server /opt/vault/bin/llama-server
COPY --from=vec /out/vec0.so /opt/vault/lib/vec0.so
COPY --from=pydeps /opt/vault/venv /opt/vault/venv
COPY vendor/ /opt/vault/vendor/
COPY app/ /opt/vault/app/
COPY tests/ /opt/vault/tests/
RUN chmod 755 /opt/vault/vendor/tgread /opt/vault/vendor/llm-local /opt/vault/vendor/bills /opt/vault/app/llm-ctl \
      /opt/vault/app/vaultd.py \
 && /opt/vault/venv/bin/python3 -I /opt/vault/vendor/tgread selfcheck \
 && /opt/vault/venv/bin/python3 -I -c 'import openpyxl' \
 && for l in eng deu fra ita; do tesseract --list-langs 2>/dev/null | grep -qx "$l" || { echo "tesseract: $l missing"; exit 1; }; done \
 && /usr/bin/python3 -I -c "import sqlite3; c = sqlite3.connect(':memory:'); c.enable_load_extension(True); \
c.load_extension('/opt/vault/lib/vec0'); print('sqlite-vec', c.execute('select vec_version()').fetchone()[0])" \
 && printf '#!/bin/sh\n# the owner at the Unraid terminal: docker exec -it claude-vault vault-console 2fa|secret NAME|tg-credentials|watch [--full]\nexec /usr/bin/python3 -I /opt/vault/app/vaultd.py console "$@"\n' \
      > /usr/local/bin/vault-console && chmod 755 /usr/local/bin/vault-console
LABEL org.claude.vault=1
ENV HOME=/data/home TZ=Europe/Zurich LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
WORKDIR /data
EXPOSE 8300
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/usr/bin/python3", "-I", "-c", "import urllib.request as u; u.build_opener(u.ProxyHandler({})).open('http://127.0.0.1:8300/health', timeout=4)"]
ENTRYPOINT ["/usr/bin/python3", "-I", "/opt/vault/app/vaultd.py"]
