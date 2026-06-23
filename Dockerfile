FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Dependency layer (cached until pyproject.toml changes) ────────────────────
# pip automatically downloads pre-built manylinux x86_64 wheels for C-extension
# packages (cryptography, paramiko, pyyaml) — no compilation under QEMU.
# Stub out the package tree so setuptools can resolve and install all deps
# without the real source. Mirrors [tool.setuptools.packages.find].
COPY pyproject.toml ./
RUN mkdir -p major minor/src/ursa_minor \
    && touch major/__init__.py minor/src/ursa_minor/__init__.py \
    && pip install --no-cache-dir . \
    && rm -rf major minor

# ── Source layer (rebuilt on code changes only) ───────────────────────────────
# All deps are already installed above — this just lays in the package files.
COPY . .
RUN pip install --no-cache-dir --no-deps .

EXPOSE 6708 6707
