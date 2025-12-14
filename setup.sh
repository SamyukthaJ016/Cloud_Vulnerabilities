#!/bin/bash
# ============================================================================
# Cloud Security Scanner - Automated Setup Script
# ============================================================================
# This script automates the initial setup process for the security scanner
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh [development|production]

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_MODE="${1:-development}"

# ============================================================================
# Helper Functions
# ============================================================================

print_header() {
    echo ""
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}============================================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

check_command() {
    if ! command -v $1 &> /dev/null; then
        print_error "$1 is not installed"
        return 1
    else
        print_success "$1 is installed"
        return 0
    fi
}

generate_secret() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-32
}

# ============================================================================
# Pre-flight Checks
# ============================================================================

print_header "Pre-flight Checks"

# Check Docker
if ! check_command docker; then
    print_error "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check Docker Compose
if ! check_command "docker compose"; then
    print_error "Please install Docker Compose v2"
    exit 1
fi

# Check system resources
# Check system resources (Linux + macOS compatible)
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS uses sysctl instead of free/nproc
    TOTAL_MEM=$(($(sysctl -n hw.memsize) / 1024 / 1024 / 1024))
    CPU_CORES=$(sysctl -n hw.ncpu)
else
    TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
    CPU_CORES=$(nproc)
fi

if [ "$TOTAL_MEM" -lt 8 ]; then
    print_warning "System has less than 8GB RAM. Scanner may run slowly."
fi

if [ "$CPU_CORES" -lt 4 ]; then
    print_warning "System has less than 4 CPU cores. Scanner may run slowly."
fi

print_success "All prerequisites met!"

# ============================================================================
# Environment Setup
# ============================================================================

print_header "Environment Configuration"

# Check if .env exists
if [ -f "$SCRIPT_DIR/.env" ]; then
    print_warning ".env file already exists"
    read -p "Do you want to overwrite it? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Skipping .env creation"
        ENV_EXISTS=true
    fi
fi

if [ -z "$ENV_EXISTS" ]; then
    print_success "Creating .env file from template..."
    cp "$SCRIPT_DIR/.env.template" "$SCRIPT_DIR/.env"
    
    # Generate secure secrets
    print_success "Generating secure secrets..."
    SECRET_KEY=$(generate_secret)
    POSTGRES_PASSWORD=$(generate_secret)
    REDIS_PASSWORD=$(generate_secret)
    
    # Update .env file
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" "$SCRIPT_DIR/.env"
        sed -i '' "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$POSTGRES_PASSWORD/" "$SCRIPT_DIR/.env"
        sed -i '' "s/REDIS_PASSWORD=.*/REDIS_PASSWORD=$REDIS_PASSWORD/" "$SCRIPT_DIR/.env"
        sed -i '' "s/APP_ENV=.*/APP_ENV=$ENV_MODE/" "$SCRIPT_DIR/.env"
    else
        # Linux
        sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" "$SCRIPT_DIR/.env"
        sed -i "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$POSTGRES_PASSWORD/" "$SCRIPT_DIR/.env"
        sed -i "s/REDIS_PASSWORD=.*/REDIS_PASSWORD=$REDIS_PASSWORD/" "$SCRIPT_DIR/.env"
        sed -i "s/APP_ENV=.*/APP_ENV=$ENV_MODE/" "$SCRIPT_DIR/.env"
    fi
    
    print_success ".env file created with secure secrets"
fi

# ============================================================================
# Cloud Provider Credentials
# ============================================================================

print_header "Cloud Provider Credentials"

echo "Please configure your cloud provider credentials in .env file"
echo ""
echo "Required credentials:"
echo "  1. AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
echo "  2. GCP_PROJECT_ID and service account JSON"
echo "  3. OPENAI_API_KEY"
echo ""

read -p "Have you configured your cloud credentials in .env? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_warning "Please edit .env file and add your credentials"
    print_warning "Then run this script again or start services manually"
    exit 0
fi

# ============================================================================
# Directory Structure
# ============================================================================

print_header "Creating Directory Structure"

mkdir -p "$SCRIPT_DIR/logs"
mkdir -p "$SCRIPT_DIR/reports"
mkdir -p "$SCRIPT_DIR/backups"
mkdir -p "$SCRIPT_DIR/config/nginx"
mkdir -p "$SCRIPT_DIR/config/prometheus"
mkdir -p "$SCRIPT_DIR/config/grafana/dashboards"
mkdir -p "$SCRIPT_DIR/config/grafana/datasources"

print_success "Directory structure created"

# ============================================================================
# Nginx Configuration
# ============================================================================

print_header "Setting up Nginx Configuration"

if [ ! -f "$SCRIPT_DIR/config/nginx/default.conf" ]; then
    print_warning "Nginx configuration not found. Please create it manually."
else
    print_success "Nginx configuration exists"
fi

# ============================================================================
# Docker Build
# ============================================================================

print_header "Building Docker Images"

echo "This may take several minutes..."
echo ""

if [ "$ENV_MODE" == "production" ]; then
    docker compose --profile prod build --no-cache
    print_success "Production images built successfully"
else
    docker compose --profile dev build
    print_success "Development images built successfully"
fi

# ============================================================================
# Database Initialization
# ============================================================================

print_header "Initializing Database"

# Start PostgreSQL
docker compose up -d postgres
print_success "PostgreSQL container started"

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
for i in {1..30}; do
    if docker compose exec -T postgres pg_isready -U scanner_user > /dev/null 2>&1; then
        print_success "PostgreSQL is ready"
        break
    fi
    echo -n "."
    sleep 1
done
echo ""

# Run init script if exists
if [ -f "$SCRIPT_DIR/init.sql" ]; then
    print_success "Running database initialization script..."
    docker compose exec -T postgres psql -U scanner_user scanner_db < "$SCRIPT_DIR/init.sql"
    print_success "Database initialized"
fi

# ============================================================================
# Start Services
# ============================================================================

print_header "Starting Services"

if [ "$ENV_MODE" == "production" ]; then
    docker compose --profile prod up -d
    print_success "Production services started"
else
    docker compose --profile dev up -d
    print_success "Development services started"
fi

# ============================================================================
# Health Checks
# ============================================================================

print_header "Running Health Checks"

echo "Waiting for services to be healthy..."
sleep 10

# Check backend health
if curl -f http://localhost:8000/health > /dev/null 2>&1; then
    print_success "Backend API is healthy"
else
    print_warning "Backend API health check failed"
fi

# Check database connection
if docker compose exec -T postgres pg_isready -U scanner_user > /dev/null 2>&1; then
    print_success "Database is healthy"
else
    print_warning "Database health check failed"
fi

# Check Redis
if docker compose exec -T redis redis-cli ping > /dev/null 2>&1; then
    print_success "Redis is healthy"
else
    print_warning "Redis health check failed"
fi

# ============================================================================
# Display Access Information
# ============================================================================

print_header "Setup Complete!"

echo ""
echo -e "${GREEN}Services are running and accessible at:${NC}"
echo ""
echo -e "  ${BLUE}Backend API:${NC}       http://localhost:8000"
echo -e "  ${BLUE}API Docs:${NC}          http://localhost:8000/docs"
echo -e "  ${BLUE}Frontend:${NC}          http://localhost:3000"
echo -e "  ${BLUE}Database:${NC}          localhost:5432"
echo -e "  ${BLUE}Redis:${NC}             localhost:6379"
echo ""

if [ "$ENV_MODE" == "production" ]; then
    echo -e "${GREEN}Additional Production Services:${NC}"
    echo ""
    echo -e "  ${BLUE}Prometheus:${NC}        http://localhost:9090"
    echo -e "  ${BLUE}Grafana:${NC}           http://localhost:3001 (admin/admin)"
    echo -e "  ${BLUE}Jaeger:${NC}            http://localhost:16686"
    echo ""
fi

echo -e "${GREEN}Useful Commands:${NC}"
echo ""
echo -e "  View logs:           ${BLUE}make logs${NC}"
echo -e "  Stop services:       ${BLUE}make down${NC}"
echo -e "  Restart services:    ${BLUE}make restart${NC}"
echo -e "  Run tests:           ${BLUE}make test${NC}"
echo -e "  Database backup:     ${BLUE}make db-backup${NC}"
echo -e "  Open shell:          ${BLUE}make shell${NC}"
echo ""

echo -e "${YELLOW}Next Steps:${NC}"
echo ""
echo "  1. Test the API: curl http://localhost:8000/health"
echo "  2. View logs: make logs"
echo "  3. Access the dashboard: http://localhost:3000"
echo "  4. Read the documentation: ./docs/README.md"
echo ""

# ============================================================================
# Optional: Install monitoring
# ============================================================================

if [ "$ENV_MODE" == "production" ]; then
    echo ""
    read -p "Do you want to enable monitoring (Prometheus/Grafana)? (Y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        print_header "Starting Monitoring Stack"
        docker compose --profile monitoring up -d
        print_success "Monitoring stack started"
        echo ""
        echo -e "  ${BLUE}Prometheus:${NC}        http://localhost:9090"
        echo -e "  ${BLUE}Grafana:${NC}           http://localhost:3001 (admin/admin)"
        echo ""
    fi
fi

# ============================================================================
# Save setup info
# ============================================================================

cat > "$SCRIPT_DIR/.setup-info" <<EOF
Setup completed: $(date)
Environment: $ENV_MODE
Docker version: $(docker --version)
Docker Compose version: $(docker compose version)
EOF

print_success "Setup information saved to .setup-info"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Cloud Security Scanner is ready to use! 🚀             ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""