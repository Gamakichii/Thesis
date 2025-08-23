#!/bin/sh
set -e

echo "Running preload..."
python preload_models.py || echo "Preload failed, continuing."

echo "Starting Gunicorn..."
# Bind to port 8080 (DigitalOcean App Platform expects this by default)
exec gunicorn --bind 0.0.0.0:8080 --workers=1 --timeout=600 app:app
