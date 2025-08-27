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

# Expose port 80 (for Azure)
EXPOSE 80

# Ensure startup.sh has execute permissions
RUN chmod +x startup.sh

# Startup script
CMD ["./startup.sh"]
