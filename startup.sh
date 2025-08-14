#!/bin/bash
cd /app/phishing_api
exec gunicorn --bind 0.0.0.0:${PORT:-8000} --workers=1 --timeout=600 app:app