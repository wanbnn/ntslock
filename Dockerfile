FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY inlock ./inlock
RUN python -m pip install --no-cache-dir .

RUN useradd --system --uid 10001 --create-home inlock && mkdir -p /data && chown inlock:inlock /data
USER inlock
ENV INLOCK_DATA_DIR=/data
EXPOSE 8080
CMD ["uvicorn", "inlock.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]

