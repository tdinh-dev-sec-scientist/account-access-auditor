# A container for the two things people want to do with this repository without
# installing anything: see the auditor produce a report, and re-derive the
# numbers the README claims.
#
#   docker build -t account-access-auditor .
#   docker run --rm -v "$PWD/reports:/out" account-access-auditor          # demo
#   docker run --rm account-access-auditor verify                          # all the claims
#   docker run --rm -v ~/.aws:/home/auditor/.aws:ro account-access-auditor \
#       audit --profile audit-readonly --output json,html --output-dir /out
#
# The image installs the development requirements, not just the runtime ones,
# because `verify` runs the test suite. Nothing in `auditor/` imports moto or
# pytest; see auditor/permissions.py and tests/test_security_properties.py.

FROM python:3.12-slim

# Fail fast and keep the image free of caches and .pyc clutter.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Requirements first, so a source edit does not re-resolve the dependency tree.
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY . .

# A read-only auditor has no reason to run as root, and the demo writes only to
# /out, which is the one path the container needs to be able to write.
RUN useradd --create-home --uid 10001 auditor \
    && mkdir -p /out \
    && chown -R auditor:auditor /app /out
USER auditor

VOLUME ["/out"]

ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
CMD ["demo"]
