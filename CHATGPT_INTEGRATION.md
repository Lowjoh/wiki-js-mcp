# ChatGPT Integration for Wiki.js MCP

This guide shows how to make your Wiki.js MCP server accessible to ChatGPT for mobile and web usage.

## 🚀 **SUCCESS! ChatGPT Integration Added**

Your MCP server now includes a **standalone web API** that ChatGPT can access directly!

### ✅ **What's New**

- **Standalone Web Server**: `src/chatgpt_web_server.py`
- **Search API**: `/search?q=your_query` endpoint for ChatGPT
- **Plugin Manifest**: `/ai-plugin.json` for ChatGPT integration
- **Health Check**: `/health` endpoint for monitoring
- **Railway Deployment**: Ready-to-deploy Dockerfile

### 🌐 **Deployment Options**

#### **Option 1: Railway (Recommended)**
1. Create new Railway project
2. Connect your GitHub repository
3. Use `railway.dockerfile` as Dockerfile
4. Set environment variables:
   ```
   WIKIJS_API_URL=https://wiki-js-mcp-production.up.railway.app
   WIKIJS_TOKEN=your_api_token_here
   PUBLIC_URL=https://your-app-name.railway.app
   ```
5. Deploy and get your public URL

#### **Option 2: Other Platforms**
- **Render**: Use `railway.dockerfile`
- **Fly.io**: Convert to fly.toml
- **DigitalOcean App Platform**: Use Docker deployment
- **Heroku**: Add Procfile: `web: python src/chatgpt_web_server.py`

### 📱 **ChatGPT Mobile Integration**

Once deployed, ChatGPT can access your Wiki.js via:

#### **Search Endpoint**
```
GET https://your-domain.com/search?q=search_term
```

**Response:**
```json
{
  "results": [
    {
      "title": "Page Title",
      "link": "https://wiki-js-mcp-production.up.railway.app/page-path",
      "snippet": "Page description or content snippet",
      "score": 1.0
    }
  ],
  "total": 1
}
```

#### **Plugin Manifest**
```
GET https://your-domain.com/ai-plugin.json
```

### 🔧 **Local Testing**

Test the web server locally:

```bash
# Start the web server
python src/chatgpt_web_server.py

# Test endpoints
curl "http://localhost:8000/search?q=test"
curl "http://localhost:8000/health"
curl "http://localhost:8000/ai-plugin.json"
```

### 🎯 **ChatGPT Usage Examples**

Once deployed, you can use ChatGPT to:

1. **Search Documentation**: "Search my Wiki.js for authentication examples"
2. **Find Specific Pages**: "Look up API documentation in my knowledge base"
3. **Browse Content**: "What pages do I have about React components?"
4. **Mobile Access**: Use ChatGPT app on your phone to search your docs

### 📊 **API Endpoints**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API information |
| `/search` | GET | Search Wiki.js pages |
| `/health` | GET | Health check |
| `/ai-plugin.json` | GET | ChatGPT plugin manifest |
| `/docs` | GET | Auto-generated API docs |

### 🔒 **Security Notes**

- The API uses your existing Wiki.js authentication
- No additional authentication required for ChatGPT
- CORS enabled for ChatGPT access
- All requests logged for monitoring

### 🎉 **Benefits**

✅ **Mobile Access**: Use ChatGPT on phone to search your docs  
✅ **Always Available**: Access from anywhere with internet  
✅ **No VPN Required**: Public API accessible globally  
✅ **Fast Search**: Direct GraphQL integration with Wiki.js  
✅ **Scalable**: Handle multiple concurrent ChatGPT requests  

### 📋 **Deployment Checklist**

- [ ] Deploy web server to Railway/Render/etc
- [ ] Set environment variables
- [ ] Test search endpoint
- [ ] Verify plugin manifest
- [ ] Test with ChatGPT mobile app

### 🆘 **Troubleshooting**

**Connection Errors**: Check `WIKIJS_API_URL` is correct  
**Authentication Errors**: Verify `WIKIJS_TOKEN` is valid  
**No Results**: Ensure Wiki.js has searchable content  
**CORS Issues**: Web server includes CORS headers for ChatGPT

---

**Ready for ChatGPT!** 🤖 Deploy the web server and start using your Wiki.js from ChatGPT on any device! 📱✨
