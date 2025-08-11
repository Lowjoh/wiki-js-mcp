# Railway Deployment Dockerfile for Wiki.js ChatGPT Web Server
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies (minimal for faster builds)
RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/

# Create a non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port for Railway (Railway will set $PORT automatically)  
EXPOSE 8080

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Health check (removed curl dependency)
# HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
#   CMD curl -f http://localhost:8080/health || exit 1

# Run the OAuth + Search server
CMD ["python", "src/oauth_with_search.py"]
