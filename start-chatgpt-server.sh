#!/bin/bash

# Wiki.js MCP Server with ChatGPT Web API
# This script starts both the MCP server and the web API for ChatGPT integration

set -e  # Exit on any error

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🚀 Starting Wiki.js MCP Server with ChatGPT Integration..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Error: Virtual environment not found. Please run ./setup.sh first." >&2
    exit 1
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "❌ Error: .env file not found. Please copy config/example.env to .env and configure it." >&2
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Install additional dependencies for web server
echo "📦 Installing web server dependencies..."
pip install fastapi uvicorn

# Check if the main server file exists
if [ ! -f "src/wiki_mcp_server.py" ]; then
    echo "❌ Error: Server file src/wiki_mcp_server.py not found." >&2
    exit 1
fi

# Load environment variables for validation
source .env

# Validate required environment variables
if [ -z "$WIKIJS_API_URL" ]; then
    echo "❌ Error: WIKIJS_API_URL not set in .env file" >&2
    exit 1
fi

if [ -z "$WIKIJS_TOKEN" ] && [ -z "$WIKIJS_USERNAME" ]; then
    echo "❌ Error: Either WIKIJS_TOKEN or WIKIJS_USERNAME must be set in .env file" >&2
    exit 1
fi

# Create logs directory if it doesn't exist
mkdir -p logs

# Enable web server for ChatGPT integration
export RUN_WEB_SERVER=true

echo "🌐 Starting MCP Server with Web API on port 8000..."
echo "📊 MCP Tools: Available for Cursor integration"
echo "🔍 Search API: http://localhost:8000/search"
echo "📋 Plugin Manifest: http://localhost:8000/ai-plugin.json"
echo "❤️  Health Check: http://localhost:8000/health"
echo ""
echo "🔄 Press Ctrl+C to stop both servers"

# Start the combined MCP + Web server
exec python src/wiki_mcp_server.py
