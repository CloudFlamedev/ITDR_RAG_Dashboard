FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=7860

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Hugging Face Spaces compatibility: run as non-root user 1000
RUN useradd -m -u 1000 user || true && \
    chown -R 1000:1000 /app
USER 1000

# Expose Hugging Face default port 7860 and standard port 8000
EXPOSE 7860 8000

# Dynamic port binding: uses $PORT if provided (Render/Railway), otherwise defaults to 7860 (Hugging Face Spaces)
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-7860}"]
