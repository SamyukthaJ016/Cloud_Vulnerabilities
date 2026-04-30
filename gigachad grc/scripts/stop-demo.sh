#!/bin/bash
#
# ============================================================================
# GigaChad GRC - Stop Demo
# ============================================================================
#
# Stops all demo services cleanly.
#
# USAGE:
#   ./scripts/stop-demo.sh
#
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${YELLOW}🛑 Stopping GigaChad GRC Demo...${NC}"
echo ""

cd "$PROJECT_ROOT"

# Kill any running frontend processes
echo "Stopping frontend..."
pkill -f "vite" 2>/dev/null || true
pkill -f "npm run dev" 2>/dev/null || true

# Stop Docker containers
echo "Stopping Docker services..."
docker compose down 2>/dev/null || docker-compose down 2>/dev/null || true

echo ""
echo -e "${GREEN}✓ Demo stopped successfully${NC}"
echo ""
echo "To start the demo again, run:"
echo "  ./scripts/start-demo.sh"
echo ""

