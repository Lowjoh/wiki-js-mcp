#!/usr/bin/env python3
"""
OAuth 2.0 Proxy Server for ChatGPT Integration
This service handles OAuth authentication and proxies requests to the MCP server.
"""

import os
import secrets
import httpx
from datetime import datetime, timedelta
from urllib.parse import urlencode
from fastapi import FastAPI, HTTPException, Request, Form, Depends
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
import jwt

# FastAPI app for OAuth
app = FastAPI(title="Wiki.js MCP OAuth Proxy")

# Configuration from environment
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "wikijs-mcp-client")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", "your-client-secret")
OAUTH_JWT_SECRET = os.getenv("OAUTH_JWT_SECRET", "your-jwt-secret")
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:8000")
# ChatGPT MCP connector uses this specific callback format
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "https://chatgpt.com/aip/oauth/callback")

# Database setup
engine = create_engine("sqlite:///oauth_tokens.db")
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class OAuthToken(Base):
    __tablename__ = "oauth_tokens"
    
    id = Column(Integer, primary_key=True)
    access_token = Column(String(500), unique=True, nullable=False)
    refresh_token = Column(String(500), unique=True, nullable=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(engine)

# Pydantic models
class TokenRequest(BaseModel):
    grant_type: str
    code: str = None
    client_id: str = None
    client_secret: str = None
    redirect_uri: str = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str = None
    scope: str = "read write"

# Security
security = HTTPBearer()

def generate_tokens():
    """Generate access and refresh tokens."""
    access_token = f"mcp_{secrets.token_urlsafe(32)}"
    refresh_token = f"ref_{secrets.token_urlsafe(32)}"
    return access_token, refresh_token

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Health check and basic endpoints
@app.get("/")
async def root():
    """Root endpoint for health check."""
    return {"status": "ok", "service": "Wiki.js MCP OAuth Proxy"}

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.get("/test")
async def test():
    """Simple test endpoint."""
    return {"message": "Test endpoint working", "timestamp": datetime.utcnow().isoformat()}

# OAuth Endpoints
@app.get("/oauth/authorize")
async def authorize(
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    scope: str = "read write",
    state: str = None
):
    """OAuth authorization endpoint."""
    # Validate client
    if client_id != OAUTH_CLIENT_ID or redirect_uri != OAUTH_REDIRECT_URI:
        raise HTTPException(status_code=400, detail="Invalid client_id or redirect_uri")
    
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type")
    
    # Generate authorization code (for demo, we auto-approve)
    auth_code = secrets.token_urlsafe(32)
    
    # Build redirect URL
    params = {"code": auth_code}
    if state:
        params["state"] = state
    
    redirect_url = f"{redirect_uri}?{urlencode(params)}"
    return RedirectResponse(url=redirect_url)

@app.post("/oauth/token")
async def token(request: TokenRequest, db = Depends(get_db)) -> TokenResponse:
    """OAuth token endpoint."""
    
    if request.grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant_type")
    
    # Validate client credentials
    if (request.client_id != OAUTH_CLIENT_ID or 
        request.client_secret != OAUTH_CLIENT_SECRET):
        raise HTTPException(status_code=401, detail="Invalid client credentials")
    
    # Generate tokens
    access_token, refresh_token = generate_tokens()
    expires_at = datetime.utcnow() + timedelta(hours=1)
    
    # Store token
    db_token = OAuthToken(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at
    )
    db.add(db_token)
    db.commit()
    
    return TokenResponse(
        access_token=access_token,
        expires_in=3600,  # 1 hour
        refresh_token=refresh_token
    )

@app.get("/oauth_config")
async def oauth_config(request: Request, mcp_url: str = None):
    """OAuth configuration endpoint for ChatGPT MCP integration."""
    host = request.headers.get('host', 'localhost')
    base_url = f"https://{host}"
    
    # Debug: Log the environment variables
    print(f"DEBUG: OAUTH_CLIENT_ID = {OAUTH_CLIENT_ID}")
    print(f"DEBUG: OAUTH_CLIENT_SECRET = {'***' if OAUTH_CLIENT_SECRET else 'NOT SET'}")
    print(f"DEBUG: OAUTH_REDIRECT_URI = {OAUTH_REDIRECT_URI}")
    
    # Return the format that ChatGPT expects for MCP OAuth
    config = {
        "type": "OAUTH",
        "authorization_url": f"{base_url}/oauth/authorize",
        "token_url": f"{base_url}/oauth/token",
        "scope": "read write",
        "client_id": OAUTH_CLIENT_ID,
        "custom_redirect_url_params": None,
        "pkce_required": True,
        "pkce_methods": ["plain", "S256"],
        "allow_http_redirect": True
    }
    
    # Only include client_secret if it's set
    if OAUTH_CLIENT_SECRET and OAUTH_CLIENT_SECRET != "your-secure-client-secret-here":
        config["client_secret"] = OAUTH_CLIENT_SECRET
    
    print(f"DEBUG: OAuth config response: {config}")
    return config

@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server(request: Request):
    """OAuth 2.0 Authorization Server Metadata (RFC 8414)."""
    host = request.headers.get('host', 'localhost')
    base_url = f"https://{host}"
    
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "scopes_supported": ["read", "write", "read write"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]
    }

@app.get("/.well-known/ai-plugin.json")
async def ai_plugin_manifest(request: Request):
    """AI Plugin manifest for ChatGPT."""
    host = request.headers.get('host', 'localhost')
    base_url = f"https://{host}"
    
    return {
        "schema_version": "v1",
        "name_for_human": "Wiki.js MCP Integration",
        "name_for_model": "wikijs_mcp",
        "description_for_human": "Manage Wiki.js documentation with hierarchical structure support.",
        "description_for_model": "Comprehensive Wiki.js integration for creating, updating, searching, and managing documentation pages with support for hierarchical organization, file mappings, and bulk operations.",
        "auth": {
            "type": "oauth",
            "authorization_url": f"{base_url}/oauth/authorize",
            "token_url": f"{base_url}/oauth/token",
            "scope": "read write"
        },
        "api": {
            "type": "openapi",
            "url": f"{base_url}/openapi.json"
        },
        "logo_url": f"{base_url}/static/logo.png",
        "contact_email": "support@example.com",
        "legal_info_url": f"{base_url}/legal"
    }

# OAuth Client validation endpoint
@app.post("/oauth/validate_client")
async def validate_oauth_client(request: Request):
    """Validate OAuth client configuration for ChatGPT."""
    body = await request.json()
    
    # Validate the client configuration
    client_id = body.get("client_id", OAUTH_CLIENT_ID)
    
    if client_id == OAUTH_CLIENT_ID:
        return {
            "valid": True,
            "client_id": client_id,
            "redirect_uris": [OAUTH_REDIRECT_URI],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "read write"
        }
    else:
        return {"valid": False, "error": "Invalid client_id"}

# ChatGPT MCP Connector endpoints
@app.post("/backend-api/aip/connectors/mcp")
async def create_mcp_connector(request: Request):
    """Handle ChatGPT MCP connector creation."""
    body = await request.json()
    
    # Return success response for MCP connector creation
    return {
        "success": True,
        "connector_id": "wiki-mcp-connector",
        "name": body.get("name", "Wiki"),
        "mcp_url": body.get("mcp_url", ""),
        "oauth_configured": True,
        "status": "active"
    }

@app.get("/backend-api/aip/connectors/list_accessible")
async def list_accessible_connectors():
    """List accessible MCP connectors."""
    return {
        "connectors": [
            {
                "id": "wiki-mcp-connector",
                "name": "Wiki",
                "type": "mcp",
                "status": "active",
                "oauth_configured": True
            }
        ]
    }

# MCP Server endpoints that ChatGPT expects
@app.get("/tools/list")
async def list_tools():
    """List available MCP tools."""
    return {
        "tools": [
            {
                "name": "wikijs_create_page",
                "description": "Create a new page in Wiki.js with support for hierarchical organization.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Page title"},
                        "content": {"type": "string", "description": "Page content in markdown"},
                        "space_id": {"type": "string", "description": "Space ID (optional)"},
                        "parent_id": {"type": "string", "description": "Parent page ID (optional)"}
                    },
                    "required": ["title", "content"]
                }
            },
            {
                "name": "wikijs_search_pages", 
                "description": "Search pages by text in Wiki.js.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"},
                        "space_id": {"type": "string", "description": "Space ID to limit search (optional)"}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "wikijs_get_page",
                "description": "Retrieve page metadata and content from Wiki.js.",
                "parameters": {
                    "type": "object", 
                    "properties": {
                        "page_id": {"type": "integer", "description": "Page ID (optional)"},
                        "slug": {"type": "string", "description": "Page slug/path (optional)"}
                    }
                }
            }
        ]
    }

# Proxy endpoints to MCP server
async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security), db = Depends(get_db)):
    """Verify OAuth token."""
    token = credentials.credentials
    
    db_token = db.query(OAuthToken).filter(
        OAuthToken.access_token == token,
        OAuthToken.expires_at > datetime.utcnow()
    ).first()
    
    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return db_token

@app.post("/tools/{tool_name}/invoke")
async def invoke_tool(
    tool_name: str,
    request: Request,
    token: OAuthToken = Depends(verify_token)
):
    """Invoke MCP tool with OAuth authentication."""
    body = await request.json()
    
    # Forward to actual MCP server (the original wiki_mcp_server.py)
    async with httpx.AsyncClient() as client:
        try:
            # For now, return a mock response since we need to set up the MCP server connection
            if tool_name == "wikijs_search_pages":
                return {
                    "result": "OAuth authentication successful. MCP tool integration in progress.",
                    "tool": tool_name,
                    "authenticated": True
                }
            else:
                return {
                    "result": f"Tool {tool_name} authenticated and ready for execution.",
                    "tool": tool_name,
                    "authenticated": True
                }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"MCP server error: {str(e)}")

# Catch-all disabled temporarily to debug route issues
# @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
# async def catch_all(request: Request, path: str):
#     """Catch-all endpoint for debugging unknown requests."""
#     print(f"Unknown request: {request.method} /{path}")
#     if request.method == "POST":
#         try:
#             body = await request.json()
#             print(f"Request body: {body}")
#         except:
#             pass
#     
#     # Return a generic response
#     return {"error": "Endpoint not found", "path": f"/{path}", "method": request.method}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
