FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SOC_DB_PATH=/app/data/soc.sqlite3
WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 soc \
    && useradd --uid 10001 --gid soc --no-create-home soc \
    && mkdir -p /app/data \
    && chown soc:soc /app/data
COPY app ./app
COPY config ./config
COPY sample_data ./sample_data
USER soc
VOLUME ["/app/data"]
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3)"
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
