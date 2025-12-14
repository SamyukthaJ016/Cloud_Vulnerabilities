# ============================================================================
# Multi-Stage Dockerfile for Cloud Security Scanner (FIXED)
# ============================================================================

# ============================================================================
# Stage 1: Base Image with System Dependencies
# ============================================================================
FROM python:3.11-slim-bookworm as base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    curl \
    wget \
    git \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ============================================================================
# Stage 2: Security Tools
# ============================================================================
FROM base as security-tools

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# Install Gitleaks
RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz \
    && tar -xzf gitleaks_8.18.1_linux_x64.tar.gz \
    && mv gitleaks /usr/local/bin/ \
    && chmod +x /usr/local/bin/gitleaks \
    && rm gitleaks_8.18.1_linux_x64.tar.gz

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Safety
RUN pip install --no-cache-dir safety

# ============================================================================
# Stage 3: Python Dependencies
# ============================================================================
FROM security-tools as python-deps

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# ============================================================================
# Stage 4: Development Image
# ============================================================================
FROM python-deps as development

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash scanner \
    && mkdir -p /app/logs /app/reports /app/config \
    && chown -R scanner:scanner /app

# Install development tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    vim less htop net-tools iputils-ping \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    pytest pytest-cov pytest-asyncio black flake8 mypy ipython

WORKDIR /app

# Copy application code (will be overridden by volume mount in dev)
COPY --chown=scanner:scanner backend/ /app/backend/
COPY --chown=scanner:scanner frontend/ /app/frontend/

# CRITICAL FIX: Set PYTHONPATH so Python can find modules
ENV PYTHONPATH=/app

USER scanner

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Development mode with hot reload
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ============================================================================
# Stage 5: Production Image (minimal)
# ============================================================================
FROM python:3.11-slim as production

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 -s /bin/bash scanner \
    && mkdir -p /app/logs /app/reports /app/config \
    && chown -R scanner:scanner /app

WORKDIR /app

# Copy security tools
COPY --from=security-tools /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=security-tools /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=security-tools /usr/local/bin/grype /usr/local/bin/grype

# Copy Python packages
COPY --from=python-deps /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=python-deps /usr/local/bin /usr/local/bin

# Copy application
COPY --chown=scanner:scanner backend/ /app/backend/
COPY --chown=scanner:scanner frontend/ /app/frontend/

# Set permissions
RUN chmod -R 755 /app/backend /app/frontend

USER scanner

# CRITICAL: Set PYTHONPATH
ENV PYTHONPATH=/app/backend

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]