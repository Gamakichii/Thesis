#!/bin/sh
set -e

echo "🔄 Running preload_models.py..."
python preload_models.py || echo "⚠️ Preload failed, continuing."

PORT=${PORT:-80}  # Use Azure port if set, otherwise default to 80
echo "🚀 Starting Gunicorn on port $PORT..."
exec gunicorn --bind 0.0.0.0:$PORT app:app
