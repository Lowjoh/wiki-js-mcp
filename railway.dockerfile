# Railway deployment Dockerfile for Wiki.js ChatGPT Web Server
FROM python:3.13-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY .env .env

# Expose port for Railway
EXPOSE 8000

# Set environment variables for Railway deployment
ENV PYTHONPATH=/app
ENV WEB_SERVER_PORT=8000

# Run the ChatGPT web server
CMD ["python", "src/chatgpt_web_server.py"]
