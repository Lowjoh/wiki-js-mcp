#!/usr/bin/env python3
"""
OAuth Server with Search API for ChatGPT integration
Combines OAuth authentication with Wiki.js search functionality
"""

import os
from dotenv import load_dotenv
load_dotenv()

import json
import logging
import hashlib
import secrets
import time
from typing import Optional, Dict, Any
from urllib.parse import urlencode, parse_qs
import base64

import httpx
from fastapi import FastAPI, Query, HTTPException, Request, Form
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pydantic import Field, BaseModel
from pydantic_settings import BaseSettings
from tenacity import retry, stop_after_attempt, wait_exponential

# Configuration
class Settings(BaseSettings):
    WIKIJS_API_URL: str = Field(default="https://wiki.laax.ai")
    WIKIJS_TOKEN: Optional[str] = Field(default=None)
    OAUTH_CLIENT_ID: str = Field(default="wikijs-mcp-client")
    OAUTH_CLIENT_SECRET: str = Field(default="")
    OAUTH_JWT_SECRET: str = Field(default="")
    OAUTH_REDIRECT_URI: str = Field(default="https://chatgpt.com/connector_platform_oauth_redirect")
    LOG_LEVEL: str = Field(default="INFO")
    PORT: int = Field(default=8080)
    
    class Config:
        env_file = ".env"
        extra = "ignore"
    
    @property
    def token(self) -> Optional[str]:
        return self.WIKIJS_TOKEN

settings = Settings()

# Setup logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# In-memory storage for OAuth flows (use Redis in production)
auth_codes = {}
access_tokens = {}
refresh_tokens = {}
client_registrations = {}

class WikiJSClient:
    """Wiki.js GraphQL API client."""
    
    def __init__(self):
        self.base_url = settings.WIKIJS_API_URL.rstrip('/')
        self.client = httpx.AsyncClient(timeout=30.0)
        self.authenticated = False
        
    async def authenticate(self) -> bool:
        """Set up authentication headers."""
        if settings.token:
            self.client.headers.update({
                "Authorization": f"Bearer {settings.token}",
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
                "title": item.get("title"),
                "snippet": item.get("description", ""),
                "url": f"{self.base_url}/{item.get('path', '')}",
                "score": 1.0
            })
        
        return {
            "results": results, 
            "total": search_data.get("totalHits", len(results))
        }

# Initialize Wiki.js client
wikijs = WikiJSClient()

# FastAPI app
app = FastAPI(
    title="Wiki.js OAuth + Search API",
    description="OAuth server with Wiki.js search for ChatGPT",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth Discovery
@app.get("/.well-known/oauth-authorization-server")
async def oauth_discovery():
    """OAuth 2.0 authorization server metadata."""
    base_url = f"https://{os.getenv('RAILWAY_STATIC_URL', 'localhost:8080')}"
    return JSONResponse({
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "userinfo_endpoint": f"{base_url}/oauth/userinfo",
        "registration_endpoint": f"{base_url}/oauth/register",
        "scopes_supported": ["read", "write", "read write"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]
    })

# Client Registration
@app.post("/oauth/register")
async def register_client(request: Request):
    """Dynamic client registration."""
    body = await request.json()
    logger.debug(f"Client registration request: {body}")
    
    client_id = f"chatgpt-mcp-{secrets.token_urlsafe(20)}"
    client_secret = secrets.token_urlsafe(32)
    
    client_registrations[client_id] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": body.get("client_name", "Unknown"),
        "redirect_uris": body.get("redirect_uris", []),
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "response_types": body.get("response_types", ["code"]),
        "created_at": int(time.time())
    }
    
    logger.debug(f"Registered new client: {client_id}")
    
    return JSONResponse({
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": body.get("client_name"),
        "redirect_uris": body.get("redirect_uris"),
        "grant_types": body.get("grant_types"),
        "response_types": body.get("response_types")
    })

# Authorization
@app.get("/oauth/authorize")
async def authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    state: str = None,
    scope: str = None,
    code_challenge: str = None,
    code_challenge_method: str = None
):
    """OAuth authorization endpoint."""
    logger.debug(f"Authorization request - client_id: {client_id}, redirect_uri: {redirect_uri}")
    
    if client_id not in client_registrations:
        raise HTTPException(status_code=400, detail="Invalid client")
    
    # Generate authorization code
    auth_code = secrets.token_urlsafe(32)
    auth_codes[auth_code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope or "read write",
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "created_at": int(time.time())
    }
    
    # Redirect with authorization code
    params = {"code": auth_code}
    if state:
        params["state"] = state
    
    redirect_url = f"{redirect_uri}?{urlencode(params)}"
    return RedirectResponse(url=redirect_url, status_code=307)

# Token Exchange
@app.post("/oauth/token")
async def token_exchange(request: Request):
    """OAuth token endpoint."""
    body = await request.form()
    logger.debug(f"Token request body: {dict(body)}")
    
    grant_type = body.get("grant_type")
    client_id = body.get("client_id")
    client_secret = body.get("client_secret")
    
    logger.debug(f"Token request - client_id: {client_id}, grant_type: {grant_type}")
    
    if grant_type == "authorization_code":
        code = body.get("code")
        if code not in auth_codes:
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        auth_data = auth_codes[code]
        del auth_codes[code]  # One-time use
        
        # Generate tokens
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        
        access_tokens[access_token] = {
            "client_id": client_id,
            "scope": auth_data["scope"],
            "created_at": int(time.time()),
            "expires_in": 3600
        }
        
        refresh_tokens[refresh_token] = {
            "client_id": client_id,
            "access_token": access_token,
            "created_at": int(time.time())
        }
        
        return JSONResponse({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token,
            "scope": auth_data["scope"]
        })
    
    raise HTTPException(status_code=400, detail="Unsupported grant type")

# User Info
@app.get("/oauth/userinfo")
async def userinfo(request: Request):
    """OAuth userinfo endpoint."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = auth_header[7:]
    if token not in access_tokens:
        raise HTTPException(status_code=401, detail="Invalid access token")
    
    return JSONResponse({
        "sub": "wikijs-user",
        "name": "Wiki.js User",
        "preferred_username": "wikijs"
    })

# Search API (The missing piece!)
@app.get("/search")
async def search_endpoint(
    request: Request,
    q: str = Query(..., description="Search query")
):
    """Search endpoint for ChatGPT."""
    # Debug logging
    logger.info(f"Search request received: q={q}")
    logger.info(f"Headers: {dict(request.headers)}")
    
    # Verify OAuth token
    auth_header = request.headers.get("Authorization", "")
    logger.info(f"Auth header: {auth_header[:20]}..." if auth_header else "No auth header")
    
    if not auth_header.startswith("Bearer "):
        logger.warning("Missing or invalid Authorization header")
        raise HTTPException(status_code=401, detail="Authentication required")
    
    token = auth_header[7:]
    logger.info(f"Token check: token in access_tokens = {token in access_tokens}")
    logger.info(f"Current access_tokens count: {len(access_tokens)}")
    
    if token not in access_tokens:
        logger.warning(f"Invalid access token: {token[:10]}...")
        raise HTTPException(status_code=401, detail="Invalid access token")
    
    try:
        if not wikijs.authenticated:
            await wikijs.authenticate()
        
        search_data = await wikijs.search_pages(q)
        
        return JSONResponse({
            "results": search_data["results"],
            "total": search_data["total"],
            "query": q
        })
        
    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")

# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        if not wikijs.authenticated:
            await wikijs.authenticate()
        return JSONResponse({"status": "healthy", "wiki_connected": wikijs.authenticated})
    except Exception as e:
        return JSONResponse({"status": "unhealthy", "error": str(e)}, status_code=503)

# ChatGPT Plugin Manifest
@app.get("/ai-plugin.json")
async def plugin_manifest():
    """Return the ChatGPT plugin manifest."""
    public_url = os.getenv("PUBLIC_URL", "https://wiki-js-mcp-production.up.railway.app")
    
    return JSONResponse({
        "schema_version": "v1",
        "name_for_model": "wikijs_search",
        "name_for_human": "Wiki.js Search",
        "description_for_model": "Search and retrieve information from a Wiki.js documentation system. Use this when users ask questions that might be answered by internal documentation, knowledge base articles, or wiki content.",
        "description_for_human": "Search your organization's Wiki.js documentation",
        "auth": {
            "type": "oauth",
            "client_url": f"{public_url}/oauth/authorize",
            "scope": "read",
            "authorization_url": f"{public_url}/oauth/authorize",
            "authorization_content_type": "application/x-www-form-urlencoded",
            "verification_tokens": {
                "openai": os.getenv("OAUTH_CLIENT_SECRET", "")
            }
        },
        "api": {
            "type": "openapi",
            "url": f"{public_url}/openapi.json"
        },
        "logo_url": f"{public_url}/logo.png",
        "contact_email": "support@example.com",
        "legal_info_url": f"{public_url}/legal"
    })

# OpenAPI specification for ChatGPT
@app.get("/openapi.json")
async def openapi_spec():
    """Return OpenAPI specification for the search API."""
    public_url = os.getenv("PUBLIC_URL", "https://wiki-js-mcp-production.up.railway.app")
    
    return JSONResponse({
        "openapi": "3.0.1",
        "info": {
            "title": "Wiki.js Search API",
            "description": "API for searching Wiki.js documentation",
            "version": "v1"
        },
        "servers": [{"url": public_url}],
        "paths": {
            "/search": {
                "get": {
                    "operationId": "searchWiki",
                    "summary": "Search Wiki.js documentation",
                    "parameters": [
                        {
                            "in": "query",
                            "name": "q",
                            "schema": {"type": "string"},
                            "required": True,
                            "description": "Search query term"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Search results",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "results": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "integer"},
                                                        "title": {"type": "string"},
                                                        "description": {"type": "string"},
                                                        "path": {"type": "string"},
                                                        "locale": {"type": "string"}
                                                    }
                                                }
                                            },
                                            "total": {"type": "integer"},
                                            "query": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    })

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint."""
    return JSONResponse({
        "status": "ok",
        "service": "Wiki.js MCP OAuth Proxy with Search v2",
        "endpoints": {
            "oauth_discovery": "/.well-known/oauth-authorization-server",
            "search": "/search?q=query",
            "health": "/health",
            "ai_plugin": "/ai-plugin.json",
            "openapi": "/openapi.json"
        }
    })

@app.post("/")
async def root_post():
    """Handle POST requests to root (ChatGPT might be confused about endpoints)."""
    logger.warning("Received POST to root endpoint - redirecting to GET")
    return JSONResponse({
        "error": "POST not supported on root endpoint",
        "message": "Use GET /search?q=query for search functionality",
        "available_endpoints": {
            "search": "GET /search?q=query",
            "health": "GET /health",
            "plugin": "GET /ai-plugin.json"
        }
    }, status_code=405)

def main():
    """Main entry point."""
    port = int(os.getenv("PORT", 8080))  # Railway provides PORT env var
    logger.info(f"Starting OAuth + Search server on port {port}")
    logger.info(f"Wiki.js URL: {settings.WIKIJS_API_URL}")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level=settings.LOG_LEVEL.lower()
    )

if __name__ == "__main__":
    main()
