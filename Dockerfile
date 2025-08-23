# Use Python slim image for smaller size
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies (for numpy, tensorflow, etc.)
RUN apt-get update && apt-get install -y \
    build-essential \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy the application code
COPY . .

# Expose port
EXPOSE 8080

# Ensure unbuffered logs
ENV PYTHONUNBUFFERED=1

# Start Gunicorn directly (no startup.sh needed)
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers=1", "--timeout=600", "--access-logfile=-", "--error-logfile=-", "app:app"]

