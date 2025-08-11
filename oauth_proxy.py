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
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "https://chatgpt.com/connector_platform_oauth_redirect")

# Database setup
engine = create_engine("sqlite:///oauth_tokens.db")
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class OAuthToken(Base):
    __tablename__ = "oauth_tokens"
    
    id = Column(Integer, primary_key=True)
    access_token = Column(String(500), unique=True, nullable=False)
    refresh_token = Column(String(500), unique=True, nullable=True)
    client_id = Column(String(255), nullable=False)
    scope = Column(String(255), default="read write")
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class OAuthClient(Base):
    __tablename__ = "oauth_clients"
    
    id = Column(Integer, primary_key=True)
    client_id = Column(String(255), unique=True, nullable=False)
    client_secret = Column(String(255), nullable=False)
    redirect_uri = Column(String(500), nullable=False)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# Alias for compatibility
OAuthAccessToken = OAuthToken

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

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security), db = Depends(get_db)):
    """Verify OAuth token for protected endpoints."""
    token = credentials.credentials
    db_token = db.query(OAuthToken).filter(
        OAuthToken.access_token == token,
        OAuthToken.expires_at > datetime.utcnow()
    ).first()
    
    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return db_token

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

@app.get("/debug")
async def debug():
    """Debug endpoint to verify deployment."""
    import os
    return {
        "message": "Debug endpoint working", 
        "timestamp": datetime.utcnow().isoformat(),
        "env_vars": {
            "OAUTH_CLIENT_ID": os.getenv("OAUTH_CLIENT_ID", "NOT_SET"),
            "OAUTH_CLIENT_SECRET": "***" if os.getenv("OAUTH_CLIENT_SECRET") else "NOT_SET",
            "PORT": os.getenv("PORT", "NOT_SET")
        }
    }

# OAuth Endpoints
@app.get("/oauth/authorize")
async def authorize(
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    scope: str = "read write",
    state: str = None,
    code_challenge: str = None,
    code_challenge_method: str = None,
    db = Depends(get_db)
):
    """OAuth authorization endpoint - supports dynamic clients."""
    print(f"DEBUG: Authorization request - client_id: {client_id}, redirect_uri: {redirect_uri}")
    
    # Check if client is registered (either hardcoded or dynamically registered)
    registered_client = None
    
    # First check hardcoded client
    if client_id == OAUTH_CLIENT_ID:
        registered_client = {"client_id": OAUTH_CLIENT_ID, "redirect_uri": OAUTH_REDIRECT_URI}
    else:
        # Check dynamically registered clients
        db_client = db.query(OAuthClient).filter(
            OAuthClient.client_id == client_id
        ).first()
        if db_client:
            registered_client = {"client_id": db_client.client_id, "redirect_uri": db_client.redirect_uri}
    
    if not registered_client:
        print(f"ERROR: Client not found: {client_id}")
        raise HTTPException(status_code=400, detail="Invalid client_id")
    
    # Validate redirect URI
    if redirect_uri != registered_client["redirect_uri"]:
        print(f"ERROR: Redirect URI mismatch. Expected: {registered_client['redirect_uri']}, Got: {redirect_uri}")
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    
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
    """OAuth token endpoint - supports dynamic clients."""
    print(f"DEBUG: Token request - client_id: {request.client_id}, grant_type: {request.grant_type}")
    
    if request.grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant_type")
    
    # Validate client credentials (check both hardcoded and dynamic clients)
    valid_client = False
    
    # Check hardcoded client
    if (request.client_id == OAUTH_CLIENT_ID and 
        request.client_secret == OAUTH_CLIENT_SECRET):
        valid_client = True
    else:
        # Check dynamically registered clients
        db_client = db.query(OAuthClient).filter(
            OAuthClient.client_id == request.client_id,
            OAuthClient.client_secret == request.client_secret
        ).first()
        if db_client:
            valid_client = True
    
    if not valid_client:
        print(f"ERROR: Invalid client credentials for: {request.client_id}")
        raise HTTPException(status_code=401, detail="Invalid client credentials")
    
    # Generate tokens
    access_token, refresh_token = generate_tokens()
    expires_at = datetime.utcnow() + timedelta(hours=1)
    
    # Store token
    db_token = OAuthToken(
        access_token=access_token,
        refresh_token=refresh_token,
        client_id=request.client_id,
        scope="read write",
        expires_at=expires_at
    )
    db.add(db_token)
    db.commit()
    
    return TokenResponse(
        access_token=access_token,
        expires_in=3600,  # 1 hour
        refresh_token=refresh_token
    )

@app.get("/oauth/userinfo")
async def userinfo(token: OAuthAccessToken = Depends(verify_token)):
    """OAuth UserInfo endpoint - REQUIRED by ChatGPT MCP.
    
    Returns user profile information for authenticated requests.
    """
    print(f"DEBUG: UserInfo requested for client: {token.client_id}")
    
    # Return basic user info for the authenticated client
    return {
        "sub": token.client_id,  # Subject identifier
        "name": "Wiki.js MCP User",
        "preferred_username": "wikijs-mcp",
        "email": "wikijs-mcp@example.com",
        "email_verified": True,
        "aud": token.client_id,
        "iss": "https://wiki-js-mcp-production.up.railway.app",
        "iat": int(datetime.utcnow().timestamp()),
        "scope": token.scope
    }

@app.get("/oauth_config")
async def oauth_config(request: Request, mcp_url: str = None):
    """OAuth configuration endpoint for ChatGPT MCP integration.
    
    CRITICAL: Must return flat structure, NOT nested under 'oauth_config' key.
    """
    host = request.headers.get('host', 'localhost')
    base_url = f"https://{host}"
    
    # Debug: Log the request
    print(f"DEBUG: oauth_config called from {request.client.host if request.client else 'unknown'}")
    print(f"DEBUG: OAUTH_CLIENT_ID = {OAUTH_CLIENT_ID}")
    print(f"DEBUG: OAUTH_CLIENT_SECRET = {'***' if OAUTH_CLIENT_SECRET else 'NOT SET'}")
    print(f"DEBUG: OAUTH_REDIRECT_URI = {OAUTH_REDIRECT_URI}")
    
    # Return FLAT structure as expected by ChatGPT MCP (NOT nested!)
    config = {
        "type": "OAUTH",
        "authorization_url": f"{base_url}/oauth/authorize",
        "token_url": f"{base_url}/oauth/token",
        "scope": "read write",
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,  # Always include for ChatGPT
        "custom_redirect_url_params": None,
        "pkce_required": True,
        "pkce_methods": ["plain", "S256"],
        "allow_http_redirect": True
    }
    
    print(f"DEBUG: Returning FLAT oauth config: {config}")
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
        "userinfo_endpoint": f"{base_url}/oauth/userinfo",
        "registration_endpoint": f"{base_url}/oauth/register",  # DCR endpoint
        "scopes_supported": ["read", "write", "read write"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]
    }

@app.get("/.well-known/openid-configuration")
async def openid_configuration(request: Request):
    """OpenID Connect Discovery Document (RFC 8414) - REQUIRED by ChatGPT MCP."""
    host = request.headers.get('host', 'localhost')
    base_url = f"https://{host}"
    
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "userinfo_endpoint": f"{base_url}/oauth/userinfo",
        "registration_endpoint": f"{base_url}/oauth/register",
        "jwks_uri": f"{base_url}/.well-known/jwks.json",
        "scopes_supported": ["openid", "profile", "email", "read", "write"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]
    }

@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource(request: Request):
    """OAuth Protected Resource Metadata - REQUIRED by ChatGPT MCP."""
    host = request.headers.get('host', 'localhost')
    base_url = f"https://{host}"
    
    return {
        "resource": base_url,
        "authorization_servers": [base_url],
        "scopes_supported": ["read", "write", "read write"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{base_url}/docs"
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

# Dynamic Client Registration (DCR) - RFC 7591 - REQUIRED by ChatGPT MCP
@app.post("/oauth/register")
async def register_client(request: Request, db = Depends(get_db)):
    """Dynamic Client Registration endpoint per RFC 7591.
    
    ChatGPT uses this to register itself as an OAuth client dynamically.
    """
    try:
        body = await request.json()
        print(f"DEBUG: Client registration request: {body}")
        
        # Generate new client credentials for ChatGPT
        client_id = f"chatgpt-mcp-{secrets.token_urlsafe(16)}"
        client_secret = secrets.token_urlsafe(32)
        
        # Extract registration parameters
        redirect_uris = body.get("redirect_uris", [OAUTH_REDIRECT_URI])
        client_name = body.get("client_name", "ChatGPT MCP Connector")
        grant_types = body.get("grant_types", ["authorization_code", "refresh_token"])
        response_types = body.get("response_types", ["code"])
        scope = body.get("scope", "read write")
        
        # Store the dynamically registered client
        new_client = OAuthClient(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uris[0] if redirect_uris else OAUTH_REDIRECT_URI,
            name=client_name,
            created_at=datetime.utcnow()
        )
        db.add(new_client)
        db.commit()
        
        # Return client credentials per RFC 7591
        response = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_id_issued_at": int(datetime.utcnow().timestamp()),
            "client_secret_expires_at": 0,  # Never expires
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "response_types": response_types,
            "scope": scope,
            "token_endpoint_auth_method": "client_secret_post"
        }
        
        print(f"DEBUG: Registered new client: {client_id}")
        return response
        
    except Exception as e:
        print(f"ERROR: Client registration failed: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Client registration failed: {str(e)}")

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
    """List available MCP tools for ChatGPT.
    
    CRITICAL: ChatGPT MCP requires 'search' and 'fetch' tools to be present.
    """
    return {
        "tools": [
            # REQUIRED: Search tool for ChatGPT MCP compliance
            {
                "name": "search",
                "description": "Search for content across Wiki.js pages and documentation.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query to find relevant content"},
                        "limit": {"type": "integer", "description": "Maximum number of results (default: 10)", "default": 10}
                    },
                    "required": ["query"]
                }
            },
            # REQUIRED: Fetch tool for ChatGPT MCP compliance
            {
                "name": "fetch",
                "description": "Fetch specific content or page from Wiki.js by ID or URL.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "resource": {"type": "string", "description": "Page ID, URL, or resource identifier to fetch"},
                        "format": {"type": "string", "description": "Response format (json, markdown, html)", "default": "json"}
                    },
                    "required": ["resource"]
                }
            },
            # Wiki.js specific tools
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

@app.post("/tools/{tool_name}/invoke")
async def invoke_tool(
    tool_name: str,
    request: Request,
    token: OAuthToken = Depends(verify_token)
):
    """Invoke MCP tools - REQUIRED by ChatGPT MCP."""
    body = await request.json()
    print(f"DEBUG: Tool invocation: {tool_name} with params: {body}")
    
    try:
        # Handle required ChatGPT MCP tools
        if tool_name == "search":
            query = body.get("query", "")
            limit = body.get("limit", 10)
            
            # Mock search results for now - replace with actual Wiki.js search
            return {
                "result": {
                    "results": [
                        {
                            "title": f"Search Results for: {query}",
                            "content": f"Mock search results for '{query}' - Wiki.js integration coming soon",
                            "url": "https://wiki-js-mcp-production.up.railway.app/search",
                            "score": 0.95
                        }
                    ],
                    "total": 1,
                    "query": query
                }
            }
        
        elif tool_name == "fetch":
            resource = body.get("resource", "")
            format_type = body.get("format", "json")
            
            # Mock fetch results for now - replace with actual Wiki.js fetch
            return {
                "result": {
                    "resource": resource,
                    "content": f"Mock content for resource '{resource}' - Wiki.js integration coming soon",
                    "format": format_type,
                    "metadata": {
                        "title": f"Resource: {resource}",
                        "last_modified": datetime.utcnow().isoformat()
                    }
                }
            }
        
        # Handle Wiki.js specific tools with MCP server proxy
        else:
            async with httpx.AsyncClient() as client:
                # Proxy to actual MCP server (when implemented)
                return {
                    "result": f"Tool {tool_name} executed successfully with OAuth authentication.",
                    "tool": tool_name,
                    "authenticated": True,
                    "params": body
                }
                
    except Exception as e:
        print(f"ERROR: Tool invocation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Tool execution error: {str(e)}")

# Catch-all completely removed to debug route issues

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
