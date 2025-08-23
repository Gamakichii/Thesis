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

# Preload models at build time (optional: can skip if heavy)
RUN python preload_models.py || echo "Preload failed, continuing."

# Expose port
EXPOSE 8080

# Startup command
CMD ["./startup.sh"]
