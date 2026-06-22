# ARIA Flask backend — container image.
# Matches the host venv interpreter (Python 3.9.6).
FROM python:3.9-slim

# - PYTHONUNBUFFERED: logs stream to `docker logs` immediately
# - PYTHONDONTWRITEBYTECODE: no .pyc clutter
# - ARIA_PORT: app reads this (aria_server.py), defaults to 5001
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    ARIA_PORT=5001 \
    ARIA_LOG_FILE=/app/logs/aria_server.log

WORKDIR /app

# curl is only needed for the container HEALTHCHECK below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first so this layer caches across code changes.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code. Secrets, data, venv, and the mobile wrapper are
# excluded via .dockerignore and provided at runtime via volumes.
COPY . .

EXPOSE 5001

# Self-signed mkcert cert → curl with -k. Generous start-period covers the
# background fleet pre-warm thread at startup.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsk https://localhost:5001/ || exit 1

CMD ["python", "aria_server.py"]
