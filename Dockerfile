# Use a small, recent Python base image
FROM python:3.11-slim

# Set a working directory
WORKDIR /app

# Install build deps and cleanup to keep image small
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application files
COPY ai_ids.py /app/ai_ids.py

# Create non-root user (optional)
RUN useradd -m appuser || true
USER appuser

# Default command
ENTRYPOINT ["python", "ai_ids.py"]
