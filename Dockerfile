FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Render levert $PORT aan; lokaal valt het terug op 8000.
ENV PORT=8000
CMD gunicorn app:app \
    -k uvicorn.workers.UvicornWorker \
    -b 0.0.0.0:${PORT} \
    --workers 2 --timeout 60
