# ============================================================================
# Makefile for Cloud Security Scanner - Docker Management
# ============================================================================

.PHONY: help build up down restart logs clean test migrate backup restore

# Variables
DOCKER_COMPOSE = docker compose
PROJECT_NAME = security-scanner
ENV_FILE = .env

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[0;33m
NC = \033[0m # No Color

# ============================================================================
# Help
# ============================================================================
help:
	@echo "$(GREEN)Cloud Security Scanner - Docker Commands$(NC)"
	@echo ""
	@echo "$(YELLOW)Development:$(NC)"
	@echo "  make dev-build          - Build development images"
	@echo "  make dev-up             - Start development environment"
	@echo "  make dev-down           - Stop development environment"
	@echo "  make dev-logs           - View development logs"
	@echo ""
	@echo "$(YELLOW)Production:$(NC)"
	@echo "  make prod-build         - Build production images"
	@echo "  make prod-up            - Start production environment"
	@echo "  make prod-down          - Stop production environment"
	@echo "  make prod-logs          - View production logs"
	@echo ""
	@echo "$(YELLOW)Database:$(NC)"
	@echo "  make db-migrate         - Run database migrations"
	@echo "  make db-backup          - Backup database"
	@echo "  make db-restore         - Restore database from backup"
	@echo "  make db-shell           - Open PostgreSQL shell"
	@echo ""
	@echo "$(YELLOW)Monitoring:$(NC)"
	@echo "  make monitoring-up      - Start monitoring stack"
	@echo "  make monitoring-down    - Stop monitoring stack"
	@echo ""
	@echo "$(YELLOW)Scanning:$(NC)"
	@echo "  make scanning-up        - Start scanning services"
	@echo "  make scanning-down      - Stop scanning services"
	@echo ""
	@echo "$(YELLOW)Utilities:$(NC)"
	@echo "  make test               - Run tests"
	@echo "  make clean              - Clean up containers and volumes"
	@echo "  make clean-all          - Clean everything including images"
	@echo "  make shell              - Open shell in backend container"
	@echo "  make install-tools      - Install security tools in container"

# ============================================================================
# Development Commands
# ============================================================================
dev-build:
	@echo "$(GREEN)Building development images...$(NC)"
	$(DOCKER_COMPOSE) --profile dev build --no-cache

dev-up:
	@echo "$(GREEN)Starting development environment...$(NC)"
	$(DOCKER_COMPOSE) --profile dev up -d
	@echo "$(GREEN)Services started!$(NC)"
	@echo "Backend API: http://localhost:8000"
	@echo "Frontend: http://localhost:3000"
	@echo "Database: localhost:5432"

dev-down:
	@echo "$(YELLOW)Stopping development environment...$(NC)"
	$(DOCKER_COMPOSE) --profile dev down

dev-restart:
	@make dev-down
	@make dev-up

dev-logs:
	$(DOCKER_COMPOSE) --profile dev logs -f

dev-logs-backend:
	$(DOCKER_COMPOSE) --profile dev logs -f backend-dev

# ============================================================================
# Production Commands
# ============================================================================
prod-build:
	@echo "$(GREEN)Building production images...$(NC)"
	$(DOCKER_COMPOSE) --profile prod build --no-cache
	@echo "$(GREEN)Build complete!$(NC)"

prod-up:
	@echo "$(GREEN)Starting production environment...$(NC)"
	$(DOCKER_COMPOSE) --profile prod up -d
	@echo "$(GREEN)Production services started!$(NC)"
	@echo "Backend API: http://localhost:8000"
	@echo "Frontend: http://localhost:80"

prod-down:
	@echo "$(YELLOW)Stopping production environment...$(NC)"
	$(DOCKER_COMPOSE) --profile prod down

prod-restart:
	@make prod-down
	@make prod-up

prod-logs:
	$(DOCKER_COMPOSE) --profile prod logs -f

prod-logs-backend:
	$(DOCKER_COMPOSE) --profile prod logs -f backend

prod-scale:
	@echo "$(GREEN)Scaling backend to 4 instances...$(NC)"
	$(DOCKER_COMPOSE) --profile prod up -d --scale backend=4

# ============================================================================
# Database Commands
# ============================================================================
db-migrate:
	@echo "$(GREEN)Running database migrations...$(NC)"
	$(DOCKER_COMPOSE) exec backend python -m backend.scripts.migrate

db-backup:
	@echo "$(GREEN)Backing up database...$(NC)"
	@mkdir -p ./backups
	$(DOCKER_COMPOSE) exec -T postgres pg_dump -U scanner_user scanner_db > ./backups/backup_$$(date +%Y%m%d_%H%M%S).sql
	@echo "$(GREEN)Backup complete: ./backups/backup_$$(date +%Y%m%d_%H%M%S).sql$(NC)"

db-restore:
	@echo "$(YELLOW)Restoring database from latest backup...$(NC)"
	@LATEST=$$(ls -t ./backups/*.sql | head -1) && \
	echo "Restoring from $$LATEST" && \
	$(DOCKER_COMPOSE) exec -T postgres psql -U scanner_user scanner_db < $$LATEST
	@echo "$(GREEN)Restore complete!$(NC)"

db-shell:
	@echo "$(GREEN)Opening PostgreSQL shell...$(NC)"
	$(DOCKER_COMPOSE) exec postgres psql -U scanner_user scanner_db

db-reset:
	@echo "$(RED)WARNING: This will delete all data!$(NC)"
	@echo "Press Ctrl+C to cancel, or wait 5 seconds to continue..."
	@sleep 5
	$(DOCKER_COMPOSE) down -v
	$(DOCKER_COMPOSE) up -d postgres
	@sleep 5
	@make db-migrate

# ============================================================================
# Monitoring Commands
# ============================================================================
monitoring-up:
	@echo "$(GREEN)Starting monitoring stack...$(NC)"
	$(DOCKER_COMPOSE) --profile monitoring up -d
	@echo "$(GREEN)Monitoring services started!$(NC)"
	@echo "Prometheus: http://localhost:9090"
	@echo "Grafana: http://localhost:3001 (admin/admin)"
	@echo "Jaeger: http://localhost:16686"

monitoring-down:
	$(DOCKER_COMPOSE) --profile monitoring down

monitoring-logs:
	$(DOCKER_COMPOSE) --profile monitoring logs -f

# ============================================================================
# Scanning Commands
# ============================================================================
scanning-up:
	@echo "$(GREEN)Starting scanning services...$(NC)"
	$(DOCKER_COMPOSE) --profile scanning up -d
	@echo "$(GREEN)Scanning services started!$(NC)"

scanning-down:
	$(DOCKER_COMPOSE) --profile scanning down

scanning-logs:
	$(DOCKER_COMPOSE) --profile scanning logs -f

# ============================================================================
# Testing Commands
# ============================================================================
test:
	@echo "$(GREEN)Running tests...$(NC)"
	$(DOCKER_COMPOSE) run --rm backend pytest tests/ -v --cov=backend --cov-report=html

test-unit:
	@echo "$(GREEN)Running unit tests...$(NC)"
	$(DOCKER_COMPOSE) run --rm backend pytest tests/unit/ -v

test-integration:
	@echo "$(GREEN)Running integration tests...$(NC)"
	$(DOCKER_COMPOSE) run --rm backend pytest tests/integration/ -v

# ============================================================================
# Utility Commands
# ============================================================================
shell:
	@echo "$(GREEN)Opening shell in backend container...$(NC)"
	$(DOCKER_COMPOSE) exec backend-dev /bin/bash

shell-prod:
	@echo "$(GREEN)Opening shell in production backend container...$(NC)"
	$(DOCKER_COMPOSE) exec backend /bin/bash

install-tools:
	@echo "$(GREEN)Installing additional security tools...$(NC)"
	$(DOCKER_COMPOSE) exec backend bash -c "trivy --version && gitleaks version && grype version && cloudfox --version"

logs:
	$(DOCKER_COMPOSE) logs -f

logs-backend:
	$(DOCKER_COMPOSE) logs -f backend

logs-db:
	$(DOCKER_COMPOSE) logs -f postgres

logs-redis:
	$(DOCKER_COMPOSE) logs -f redis

ps:
	$(DOCKER_COMPOSE) ps

top:
	docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# ============================================================================
# Cleanup Commands
# ============================================================================
clean:
	@echo "$(YELLOW)Cleaning up containers and volumes...$(NC)"
	$(DOCKER_COMPOSE) down -v
	@echo "$(GREEN)Cleanup complete!$(NC)"

clean-all:
	@echo "$(RED)WARNING: This will remove all images, containers, and volumes!$(NC)"
	@echo "Press Ctrl+C to cancel, or wait 5 seconds to continue..."
	@sleep 5
	$(DOCKER_COMPOSE) down -v --rmi all
	docker system prune -af
	@echo "$(GREEN)Deep cleanup complete!$(NC)"

clean-logs:
	@echo "$(YELLOW)Cleaning log files...$(NC)"
	rm -rf logs/*.log
	rm -rf logs/nginx/*.log

clean-reports:
	@echo "$(YELLOW)Cleaning report files...$(NC)"
	rm -rf reports/*.html reports/*.json reports/*.pdf

# ============================================================================
# Build & Deploy Pipeline
# ============================================================================
deploy-staging:
	@echo "$(GREEN)Deploying to staging...$(NC)"
	@make prod-build
	@make prod-up
	@make db-migrate
	@echo "$(GREEN)Staging deployment complete!$(NC)"

deploy-production:
	@echo "$(RED)WARNING: Deploying to production!$(NC)"
	@echo "Press Ctrl+C to cancel, or wait 10 seconds to continue..."
	@sleep 10
	@make prod-build
	@make db-backup
	@make prod-up
	@make db-migrate
	@make monitoring-up
	@echo "$(GREEN)Production deployment complete!$(NC)"

# ============================================================================
# Health Checks
# ============================================================================
health:
	@echo "$(GREEN)Checking service health...$(NC)"
	@curl -f http://localhost:8000/health || echo "$(RED)Backend is down$(NC)"
	@curl -f http://localhost:80 || echo "$(RED)Frontend is down$(NC)"
	@docker exec security-scanner-db pg_isready -U scanner_user || echo "$(RED)Database is down$(NC)"

# ============================================================================
# Security Scan (scan the scanner!)
# ============================================================================
security-scan:
	@echo "$(GREEN)Running security scan on Docker images...$(NC)"
	@docker scan security-scanner-backend || true
	@trivy image security-scanner-backend || true
	@echo "$(GREEN)Security scan complete!$(NC)"

# ============================================================================
# Development workflow
# ============================================================================
dev: dev-build dev-up dev-logs

prod: prod-build prod-up monitoring-up

quick-start:
	@echo "$(GREEN)Quick start: Development environment$(NC)"
	@make dev-up
	@sleep 10
	@make health
	@echo "$(GREEN)All systems ready!$(NC)"
