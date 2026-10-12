FROM python:3.11-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates openssl \
    && apt-get clean && rm -r /var/lib/apt/lists
WORKDIR /opt/node-dispatch
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY tools/fetch_engine.py ./tools/fetch_engine.py
RUN python3 tools/fetch_engine.py --output /usr/local/bin/mihomo
COPY app/ ./app/
COPY ENGINE.json ./PACKAGE-MANIFEST.json
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DEPLOY_CONFIG=/config/config.yaml DATA_ROOT=/data
ENTRYPOINT ["python3", "-B", "app/portable.py"]
CMD ["run"]
