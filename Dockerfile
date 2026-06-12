# Use official Python image
FROM python:3.11-slim

# Image metadata
LABEL org.opencontainers.image.title="CyberThreatX" \
    org.opencontainers.image.version="1.1"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directory for monitored logs
RUN mkdir -p monitored_logs sigma_rules

# Expose dashboard port
EXPOSE 5000

# Default command (can be overridden in docker-compose)
CMD ["python", "dashboard.py"]
