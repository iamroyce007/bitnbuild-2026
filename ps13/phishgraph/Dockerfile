# ---- stage 1: build the dashboard ----
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- stage 2: API + workers ----
FROM python:3.12-slim
ARG WITH_EMBEDDINGS=false
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt requirements-embeddings.txt ./
RUN pip install -r requirements.txt \
 && if [ "$WITH_EMBEDDINGS" = "true" ]; then pip install --extra-index-url https://download.pytorch.org/whl/cpu torch && pip install -r requirements-embeddings.txt; fi
COPY backend/ backend/
COPY models/ models/
COPY data/brands.json data/brands.json
COPY data/demo/ data/demo/
COPY scripts/ scripts/
COPY --from=web /web/dist frontend/dist
# reference data (Tranco, PSL, confusables) is fetched at build time so the image is self-contained
RUN python scripts/download_datasets.py --reference-only
RUN useradd -r -u 10001 phishgraph && mkdir -p data/processed && chown -R phishgraph /app/data
USER phishgraph
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health').status==200 else 1)"
CMD ["python", "-m", "uvicorn", "--app-dir", "backend", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
