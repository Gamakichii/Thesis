# Use slim Python
FROM python:3.10-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc \
 && rm -rf /var/lib/apt/lists/*

# Copy requirements first
COPY requirements.txt .

# Install Python deps
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Expose port 8080
EXPOSE 8080

# Ensure unbuffered logs
ENV PYTHONUNBUFFERED=1

# Start Gunicorn directly
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers=1", "--timeout=600", "--access-logfile=-", "--error-logfile=-", "app:app"]
