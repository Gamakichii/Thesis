# Use official Python 3.11 slim image
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Copy only requirements.txt first to leverage Docker cache
COPY phishing_api/requirements.txt ./phishing_api/requirements.txt

# Upgrade pip and install dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r ./phishing_api/requirements.txt

# Copy the rest of the source code including models and Firestore credentials
COPY phishing_api/ ./phishing_api/
COPY startup.sh /startup.sh

# Make startup.sh executable
RUN chmod +x /startup.sh

# Expose the port (Gunicorn will use $PORT in startup.sh)
EXPOSE 8000

# Use startup.sh as the entrypoint
ENTRYPOINT ["/startup.sh"]
