# =============================================================================
# GigaChad GRC Frontend - Multi-stage Docker Build
# =============================================================================
# This Dockerfile builds the React frontend and serves it via Nginx.
# Build args are used to configure the frontend at build time.
# =============================================================================

# Build stage
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS builder

WORKDIR /repo

# Install from the monorepo's canonical lockfile so container builds use the
# same audited dependency graph as local and CI builds.
COPY package.json package-lock.json ./
COPY frontend/package.json ./frontend/package.json
COPY services/shared/package.json ./services/shared/package.json
COPY services/controls/package.json ./services/controls/package.json
COPY services/frameworks/package.json ./services/frameworks/package.json
COPY services/policies/package.json ./services/policies/package.json
COPY services/tprm/package.json ./services/tprm/package.json
COPY services/trust/package.json ./services/trust/package.json
COPY services/audit/package.json ./services/audit/package.json

# Install ALL dependencies (including devDependencies) for build.
# --ignore-scripts blocks postinstall hooks, the main supply-chain attack
# vector via npm. The repo .npmrc sets ignore-scripts=true but isn't
# COPY'd into the build context, so we pass the flag explicitly here.
RUN npm ci --workspace frontend --include-workspace-root=false --ignore-scripts

# Copy frontend source
COPY frontend/ ./frontend/

WORKDIR /repo/frontend

# Build-time environment variables
# These are baked into the static build
# Empty API URL means requests go to the same origin (nginx) which proxies them
ARG VITE_API_URL=
ARG VITE_ENABLE_AI_MODULE=true
ARG VITE_KEYCLOAK_URL
ARG VITE_KEYCLOAK_REALM=gigachad-grc
ARG VITE_KEYCLOAK_CLIENT_ID=grc-frontend

ENV VITE_API_URL=$VITE_API_URL
ENV VITE_ENABLE_AI_MODULE=$VITE_ENABLE_AI_MODULE
ENV VITE_KEYCLOAK_URL=$VITE_KEYCLOAK_URL
ENV VITE_KEYCLOAK_REALM=$VITE_KEYCLOAK_REALM
ENV VITE_KEYCLOAK_CLIENT_ID=$VITE_KEYCLOAK_CLIENT_ID

# Limit Node.js heap to prevent OOM kills during parallel Docker builds
ENV NODE_OPTIONS=--max-old-space-size=2048

RUN npm run build -- --mode production

# Production stage - Nginx
FROM nginx:alpine@sha256:dc48b7a872a79fb541ba5081d320b11b549231bc63ba465a7495afaa7d2ebcb8 AS production

# Patch OS-level CVEs (zlib CVE-2026-22184, CVE-2026-27171)
RUN apk upgrade --no-cache

# Copy built assets from builder
COPY --from=builder /repo/frontend/dist /usr/share/nginx/html

# Copy nginx config (path relative to context which is repo root)
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

# Nginx runs on port 80 by default
EXPOSE 80

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget -q --spider http://127.0.0.1/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
