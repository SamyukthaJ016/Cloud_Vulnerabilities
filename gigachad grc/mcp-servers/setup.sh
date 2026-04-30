#!/bin/bash

# MCP Servers Setup Script
# This script installs dependencies and builds all custom MCP servers

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "GigaChad GRC - MCP Servers Setup"
echo "=========================================="
echo ""

# Function to setup a single server
setup_server() {
    local server_name=$1
    local server_path="$SCRIPT_DIR/$server_name"
    
    if [ ! -d "$server_path" ]; then
        echo "❌ Server directory not found: $server_path"
        return 1
    fi
    
    echo "📦 Setting up $server_name..."
    cd "$server_path"
    
    # Install dependencies
    echo "   Installing dependencies..."
    npm install --prefer-offline --no-audit --progress=false
    
    # Build TypeScript
    echo "   Building TypeScript..."
    npm run build
    
    # Verify build
    if [ -f "dist/index.js" ]; then
        echo "✅ $server_name built successfully"
    else
        echo "❌ $server_name build failed - dist/index.js not found"
        return 1
    fi
    
    echo ""
}

# Setup each MCP server
echo "Setting up GRC Evidence Collection Server..."
setup_server "grc-evidence"

echo "Setting up GRC Compliance Automation Server..."
setup_server "grc-compliance"

echo "Setting up GRC AI Assistant Server..."
setup_server "grc-ai-assistant"

echo "=========================================="
echo "✅ All MCP servers setup complete!"
echo "=========================================="
echo ""
echo "Available MCP Servers:"
echo "  • grc-evidence    - Evidence collection from AWS, Azure, GitHub, Okta, etc."
echo "  • grc-compliance  - Compliance checks, control testing, gap analysis"
echo "  • grc-ai-assistant - AI-powered risk analysis and policy drafting"
echo ""
echo "To start a server manually:"
echo "  cd mcp-servers/grc-evidence && npm start"
echo ""
echo "Configure servers in the GigaChad GRC UI:"
echo "  Settings → MCP Servers → Add Server"
echo ""




