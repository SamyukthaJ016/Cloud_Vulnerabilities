# ============================================================================
# Multi-Stage Dockerfile for Cloud Security Scanner with CloudFox (FIXED)
# ============================================================================

# ============================================================================
# Stage 1: Base Image with System Dependencies
# ============================================================================
FROM python:3.11-slim-bookworm AS base

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
    ca-certificates \
    unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ============================================================================
# Stage 2: Security Tools (CloudFox + trivy/gitleaks/grype)
# ============================================================================
FROM base AS security-tools
ARG TARGETARCH

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# Install Gitleaks (Architecture-aware)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
        GITLEAKS_ARCH="arm64"; \
    else \
        GITLEAKS_ARCH="x64"; \
    fi && \
    wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_${GITLEAKS_ARCH}.tar.gz -O gitleaks.tar.gz && \
    tar -xzf gitleaks.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    chmod +x /usr/local/bin/gitleaks && \
    rm gitleaks.tar.gz

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Safety
RUN pip install --no-cache-dir safety

# Install CloudFox (Architecture-aware binary)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
        CLOUDFOX_ARCH="arm64"; \
    else \
        CLOUDFOX_ARCH="amd64"; \
    fi && \
    wget https://github.com/BishopFox/cloudfox/releases/download/v1.17.0/cloudfox-linux-${CLOUDFOX_ARCH}.zip -O cloudfox.zip && \
    unzip cloudfox.zip && \
    echo "DEBUG: CloudFox unzip contents:" && ls -R && \
    # Find the executable (it might be named cloudfox or cloudfox-linux-amd64)
    # Search recursively in case it's in a subdirectory
    EXE_PATH=$(find . -type f -name "cloudfox*" | head -n 1) && \
    if [ -z "$EXE_PATH" ]; then echo "❌ Could not find cloudfox binary!"; ls -la; exit 1; fi && \
    echo "DEBUG: Found binary at $EXE_PATH" && \
    mv "$EXE_PATH" /usr/local/bin/cloudfox && \
    chmod +x /usr/local/bin/cloudfox && \
    rm cloudfox.zip

# Verify all tools
RUN trivy --version && \
    gitleaks version && \
    grype version && \
    cloudfox --version && \
    echo "✅ All security tools verified"

# ============================================================================
# Stage 3: Python Dependencies
# ============================================================================
FROM security-tools AS python-deps

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# ============================================================================
# Stage 4: Development Image
# ============================================================================
FROM python-deps AS development

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

# Copy application code
COPY --chown=scanner:scanner backend/ /app/backend/
COPY --chown=scanner:scanner frontend/ /app/frontend/

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
FROM python:3.11-slim-bookworm AS production

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install minimal runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash scanner \
    && mkdir -p /app/logs /app/reports /app/config \
    && chown -R scanner:scanner /app

WORKDIR /app

# Copy ALL security tools from security-tools stage (including CloudFox)
COPY --from=security-tools /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=security-tools /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=security-tools /usr/local/bin/grype /usr/local/bin/grype
COPY --from=security-tools /usr/local/bin/cloudfox /usr/local/bin/cloudfox

# Verify tools work in production image
RUN trivy --version && \
    gitleaks version && \
    grype version && \
    cloudfox --version && \
    echo "✅ Production: All security tools verified"

# Copy Python packages
COPY --from=python-deps /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=python-deps /usr/local/bin /usr/local/bin

# Copy application code as scanner user
COPY --chown=scanner:scanner backend/ /app/backend/
COPY --chown=scanner:scanner frontend/ /app/frontend/

# Fix permissions (run as root before switching user)
RUN chmod -R 755 /app/backend /app/frontend

# Set PYTHONPATH
ENV PYTHONPATH=/app

USER scanner

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Production mode
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
