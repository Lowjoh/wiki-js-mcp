#!/usr/bin/env python3
"""Standalone web server for ChatGPT integration with Wiki.js MCP."""

import os
from dotenv import load_dotenv
load_dotenv()

import json
import logging
import asyncio
from typing import Optional

import httpx
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pydantic import Field
from pydantic_settings import BaseSettings
from tenacity import retry, stop_after_attempt, wait_exponential

# Configuration
class Settings(BaseSettings):
    WIKIJS_API_URL: str = Field(default="http://localhost:3000")
    WIKIJS_TOKEN: Optional[str] = Field(default=None)
    WIKIJS_API_KEY: Optional[str] = Field(default=None)  # Alternative name for token
    WIKIJS_USERNAME: Optional[str] = Field(default=None)
    WIKIJS_PASSWORD: Optional[str] = Field(default=None)
    LOG_LEVEL: str = Field(default="INFO")
    WEB_SERVER_PORT: int = Field(default=8000)
    
    class Config:
        env_file = ".env"
        extra = "ignore"
    
    @property
    def token(self) -> Optional[str]:
        """Get the token from either WIKIJS_TOKEN or WIKIJS_API_KEY."""
        return self.WIKIJS_TOKEN or self.WIKIJS_API_KEY

settings = Settings()

# Setup logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class WikiJSClient:
    """Wiki.js GraphQL API client for handling requests."""
    
    def __init__(self):
        self.base_url = settings.WIKIJS_API_URL.rstrip('/')
        self.client = httpx.AsyncClient(timeout=30.0)
        self.authenticated = False
        
    async def authenticate(self) -> bool:
        """Set up authentication headers for GraphQL requests."""
        if settings.token:
            self.client.headers.update({
                "Authorization": f"Bearer {settings.token}",
                "Content-Type": "application/json"
            })
            self.authenticated = True
            return True
        elif settings.WIKIJS_USERNAME and settings.WIKIJS_PASSWORD:
            # Login via GraphQL mutation
            login_mutation = """
            mutation($username: String!, $password: String!) {
                authentication {
                    login(username: $username, password: $password, strategy: "local") {
                        responseResult {
                            succeeded
                            errorCode
                            slug
                            message
                        }
                        jwt
                    }
                }
            }
            """
            variables = {
                "username": settings.WIKIJS_USERNAME,
                "password": settings.WIKIJS_PASSWORD
            }
            
            response = await self.graphql_request(login_mutation, variables)
            login_data = response.get("data", {}).get("authentication", {}).get("login", {})
            
            if login_data.get("responseResult", {}).get("succeeded"):
                jwt_token = login_data.get("jwt")
                if jwt_token:
                    self.client.headers.update({
                        "Authorization": f"Bearer {jwt_token}",
                        "Content-Type": "application/json"
                    })
                    self.authenticated = True
                    return True
        
        return False

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def graphql_request(self, query: str, variables: dict = None) -> dict:
        """Make a GraphQL request to Wiki.js."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
            
        response = await self.client.post(f"{self.base_url}/graphql", json=payload)
        response.raise_for_status()
        return response.json()

    async def search_pages(self, query: str) -> dict:
        """Search pages in Wiki.js."""
        search_query = """
        query($query: String!) {
            pages {
                search(query: $query, path: "", locale: "en") {
                    results {
                        id
                        title
                        description
                        path
                        locale
                    }
                    totalHits
                }
            }
        }
        """
        
        variables = {"query": query}
        response = await self.graphql_request(search_query, variables)
        
        search_data = response.get("data", {}).get("pages", {}).get("search", {})
        
        results = []
        for item in search_data.get("results", []):
            results.append({
                "pageId": item.get("id"),
                "title": item.get("title"),
                "snippet": item.get("description", ""),
                "score": 1.0,  # Wiki.js doesn't provide scores
                "path": item.get("path")
            })
        
        return {
            "results": results, 
            "total": search_data.get("totalHits", len(results))
        }

# Initialize Wiki.js client
wikijs = WikiJSClient()

# FastAPI web server for ChatGPT integration
app = FastAPI(
    title="Wiki.js ChatGPT Search API",
    description="Search API for Wiki.js documentation accessible to ChatGPT",
    version="1.0.0"
)

# Add CORS middleware for ChatGPT access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ChatGPT needs access
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/search")
async def search_endpoint(q: str = Query(..., description="Search query term")):
    """
    Search endpoint compatible with ChatGPT.
    
    Args:
        q: The search query term
        
    Returns:
        JSON object with search results
    """
    try:
        if not wikijs.authenticated:
            await wikijs.authenticate()
        
        search_data = await wikijs.search_pages(q)
        
        # Transform results to ChatGPT-compatible format
        results = []
        for item in search_data.get("results", []):
            results.append({
                "title": item.get("title", ""),
                "link": f"{settings.WIKIJS_API_URL.rstrip('/')}/{item.get('path', '')}",
                "snippet": item.get("snippet", ""),
                "score": item.get("score", 1.0)
            })
        
        return JSONResponse({
            "results": results,
            "total": search_data.get("total", len(results))
        })
        
    except Exception as e:
        logger.error(f"Search endpoint error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")

@app.get("/ai-plugin.json")
async def plugin_manifest():
    """Plugin manifest for ChatGPT integration."""
    base_url = os.getenv("PUBLIC_URL", settings.WIKIJS_API_URL)
    return JSONResponse({
        "schema_version": "v1",
        "name_for_human": "Wiki.js Search",
        "name_for_model": "wikijs_search",
        "description_for_human": "Search and access Wiki.js documentation",
        "description_for_model": "API for searching Wiki.js documentation pages and content. Use this to find information in the knowledge base.",
        "api": {
            "type": "openapi",
            "url": f"{base_url}/openapi.json"
        },
        "auth": {
            "type": "none"
        },
        "logo_url": f"{base_url}/logo.png",
        "contact_email": "support@example.com",
        "legal_info_url": f"{base_url}/legal"
    })

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        if not wikijs.authenticated:
            await wikijs.authenticate()
        return JSONResponse({"status": "healthy", "wiki_connected": True})
    except Exception as e:
        return JSONResponse({"status": "unhealthy", "error": str(e)}, status_code=503)

@app.get("/")
async def root():
    """Root endpoint with API information."""
    return JSONResponse({
        "name": "Wiki.js ChatGPT Search API",
        "version": "1.0.0",
        "endpoints": {
            "search": "/search?q=your_query",
            "health": "/health",
            "plugin_manifest": "/ai-plugin.json",
            "docs": "/docs"
        }
    })

def main():
    """Main entry point for the web server."""
    logger.info(f"Starting Wiki.js ChatGPT Web Server on port {settings.WEB_SERVER_PORT}")
    logger.info(f"Wiki.js URL: {settings.WIKIJS_API_URL}")
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=settings.WEB_SERVER_PORT, 
        log_level=settings.LOG_LEVEL.lower()
    )

if __name__ == "__main__":
    main()
