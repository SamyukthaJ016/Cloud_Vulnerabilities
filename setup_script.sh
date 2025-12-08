#!/bin/bash

# Multi-Cloud MCP Security Scanner - Setup Script
# This script sets up the entire environment

set -e  # Exit on error

echo "🚀 Multi-Cloud MCP Security Scanner - Setup"
echo "==========================================="
echo ""

# Check Python version
echo "📋 Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.10+"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "✓ Found Python $PYTHON_VERSION"
echo ""

# Check PostgreSQL
echo "📋 Checking PostgreSQL..."
if ! command -v psql &> /dev/null; then
    echo "⚠️  PostgreSQL client not found."
    echo "   Install: brew install postgresql (macOS) or apt install postgresql (Linux)"
else
    echo "✓ PostgreSQL found"
fi
echo ""

# Create virtual environment
echo "📦 Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi
echo ""

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate
echo "✓ Virtual environment activated"
echo ""

# Install dependencies
echo "📚 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
echo "✓ Dependencies installed"
echo ""

# Setup .env file
echo "⚙️  Setting up environment configuration..."
if [ ! -f ".env" ]; then
    cp .env.template .env
    echo "✓ Created .env file"
    echo "⚠️  Please edit .env with your credentials:"
    echo "   - DATABASE_URL"
    echo "   - OPENAI_API_KEY"
    echo "   - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY"
    echo "   - GCP_PROJECT_ID / GCP_SERVICE_ACCOUNT_JSON"
else
    echo "✓ .env file already exists"
fi
echo ""

# Setup database
echo "🗄️  Setting up database..."
echo "Please run these SQL commands manually:"
echo ""
echo "  psql -U postgres"
echo "  CREATE DATABASE mcp_scanner;"
echo "  \\c mcp_scanner"
echo ""
cat << 'EOF'
  CREATE TABLE scans (
      id SERIAL PRIMARY KEY,
      account_id VARCHAR(255),
      cloud VARCHAR(50),
      status VARCHAR(50),
      started_at TIMESTAMP DEFAULT NOW()
  );

  CREATE TABLE resources (
      id SERIAL PRIMARY KEY,
      scan_id INTEGER REFERENCES scans(id),
      cloud VARCHAR(50),
      type VARCHAR(100),
      name VARCHAR(500),
      config JSONB,
      public BOOLEAN DEFAULT FALSE
  );

  CREATE TABLE findings (
      id SERIAL PRIMARY KEY,
      scan_id INTEGER REFERENCES scans(id),
      resource_id INTEGER REFERENCES resources(id),
      severity VARCHAR(20),
      description TEXT,
      validated_by VARCHAR(100)
  );

  CREATE INDEX idx_scans_cloud ON scans(cloud);
  CREATE INDEX idx_resources_scan ON resources(scan_id);
  CREATE INDEX idx_findings_severity ON findings(severity);
EOF
echo ""

# File structure
echo "📁 Project structure:"
echo ""
echo "mcp-security-scanner/"
echo "├── mcp_base.py              # Universal MCP interface"
echo "├── mcp_aws_plugin.py        # AWS security scanner"
echo "├── mcp_gcp_plugin.py        # GCP security scanner"
echo "├── mcp_openai_plugin.py     # OpenAI security scanner"
echo "├── ai_recommender.py        # AI recommendation engine"
echo "├── app_refactored.py        # FastAPI orchestrator"
echo "├── database.py              # Database module (your existing)"
echo "├── requirements.txt         # Python dependencies"
echo "├── .env                     # Environment variables"
echo "├── test_scanner.py          # Integration tests"
echo "└── README.md                # Documentation"
echo ""

# Test installation
echo "🧪 Running quick test..."
python3 -c "
import sys
try:
    import fastapi
    import openai
    import boto3
    import google.cloud.storage
    import psycopg2
    print('✓ All required packages imported successfully')
except ImportError as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
"
echo ""

# Instructions
echo "==========================================="
echo "✅ Setup Complete!"
echo "==========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Configure credentials:"
echo "   nano .env  # Add your API keys and credentials"
echo ""
echo "2. Setup database:"
echo "   # Run the SQL commands shown above"
echo ""
echo "3. Test the scanner:"
echo "   python test_scanner.py"
echo ""
echo "4. Start the API server:"
echo "   python app_refactored.py"
echo ""
echo "5. Test the API:"
echo "   curl http://localhost:8000/"
echo "   curl -X POST http://localhost:8000/scan \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"message\": \"Scan my AWS account\"}'"
echo ""
echo "Documentation: http://localhost:8000/docs"
echo ""
echo "Happy scanning! 🛡️"
echo ""
