FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AUDITDEX_DB=/data/auditdex.sqlite3

WORKDIR /srv
COPY backend/requirements.txt /srv/backend/requirements.txt
RUN pip install --no-cache-dir -r /srv/backend/requirements.txt \
    && useradd --uid 10001 --create-home auditdex \
    && mkdir -p /data \
    && chown auditdex:auditdex /data

COPY --chown=auditdex:auditdex backend/ /srv/backend/
COPY --chown=auditdex:auditdex scripts/ /srv/scripts/
COPY --chown=auditdex:auditdex web/ /srv/web/

WORKDIR /srv/backend
USER auditdex
EXPOSE 8000
CMD ["sh", "-c", "python -m app.seed && exec python -m uvicorn app.main:app --host 0.0.0.0 --port 8000"]
