FROM python:3.12-slim

WORKDIR /app

# Fuggosegek elobb (Docker cache-elesi optimalizacio)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Alkalmazas kod
COPY app/ ./app/

# Railway a PORT env var-t allitja be automatikusan
ENV PORT=8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
