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
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "https://chat.openai.com/aip/plugin-oauth-callback")

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
    
    return {
        "authorization_url": f"{base_url}/oauth/authorize",
        "token_url": f"{base_url}/oauth/token",
        "scope": "read write",
        "client_id": OAUTH_CLIENT_ID
    }

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

@app.post("/mcp/{tool_name}")
async def proxy_mcp_tool(
    tool_name: str,
    request: Request,
    token: OAuthToken = Depends(verify_token)
):
    """Proxy MCP tool calls with OAuth authentication."""
    body = await request.json()
    
    # Forward to MCP server
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{MCP_SERVER_URL}/tools/{tool_name}",
                json=body,
                headers={"Authorization": f"Bearer mcp-internal-token"}
            )
            return response.json()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"MCP server error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
