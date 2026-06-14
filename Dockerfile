# praxis container image (BL-092, BL-033, ADR-0032).
#
# Minimal, non-root, multi-stage. The builder installs the project (default
# runtime deps only: pydantic; no dev/tsa/postgres extras) into a venv; the
# runtime stage copies that venv onto a clean base and runs `python -m praxis`
# over stdio. The base is digest-pinned (ADR-0001 supply-chain posture); the tag
# is kept in a comment so Renovate can maintain the digest. Distroless is not used
# because its python3 image ships Python 3.11, below the project's 3.12 floor.
#
# Build:   docker build -t ghcr.io/rmednitzer/praxis:<version> .
# The published digest (not a tag) is what deploy/helm + zarf pin; see
# deploy/RELEASE-CHECKLIST.md.

# python:3.12-slim-bookworm
FROM python:3.14-slim-bookworm@sha256:a70519002c49552ea0a853de47599cf40479b001bd7a624f1112eaf44dcaccc7 AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /src
# Only what the build backend needs to produce the wheel (hatchling reads the
# readme and license metadata); src/ carries the package.
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir .

# python:3.12-slim-bookworm
FROM python:3.14-slim-bookworm@sha256:a70519002c49552ea0a853de47599cf40479b001bd7a624f1112eaf44dcaccc7 AS runtime

# Governance-as-code labels (BL-033): provenance and the base pin, plus the ADR/
# backlog pointers so the deployed bytes carry their own traceability.
LABEL org.opencontainers.image.title="praxis" \
      org.opencontainers.image.description="Unified AI-operations MCP: bitemporal fleet model, drift engine, tiered audited actuator." \
      org.opencontainers.image.source="https://github.com/rmednitzer/aiops-mcp" \
      org.opencontainers.image.documentation="https://github.com/rmednitzer/aiops-mcp/blob/main/docs/architecture.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="praxis maintainers" \
      org.opencontainers.image.base.name="docker.io/library/python:3.12-slim-bookworm" \
      org.opencontainers.image.base.digest="sha256:76d4b7b6305788c6b4c6a19d6a22a3921bf802e9af4d5e1e5bd771208dba74bf" \
      io.praxis.governance="self-contained, digest-pinned supply chain (ADR-0001); container build (ADR-0032); work items in docs/backlog.md"

# Drop root: a fixed, high, system uid/gid with an explicit non-login shell
# (/usr/sbin/nologin), so the comment holds regardless of /etc/default/useradd. The
# Helm chart's PSA-restricted securityContext runs as non-root too (BL-014); this
# makes the image non-root by construction, not only by orchestrator policy.
RUN groupadd --system --gid 10001 praxis \
    && useradd --system --uid 10001 --gid praxis --shell /usr/sbin/nologin \
       --home-dir /home/praxis --create-home praxis

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001
WORKDIR /home/praxis

# Serves MCP JSON-RPC over stdio (the default, working transport); refuses an
# unsafe HTTP bind (fails closed). HTTP serving is staged, not implemented (BL-012).
ENTRYPOINT ["python", "-m", "praxis"]
