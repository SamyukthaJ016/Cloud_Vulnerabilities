# SSL/TLS Configuration Guide

This guide explains how to configure SSL/TLS for all GigaChad GRC services in production.

## Overview

In production, all connections should be encrypted:
- **Database connections** (PostgreSQL)
- **Object storage connections** (RustFS/S3)
- **Redis connections** (Cache/Queue)
- **Frontend** (HTTPS via Traefik)
- **API endpoints** (HTTPS via Traefik)

## Database SSL Configuration

### PostgreSQL Connection String

Add `?sslmode=require` to your DATABASE_URL:

```bash
# Development (no SSL)
DATABASE_URL=postgresql://user:pass@localhost:5432/db

# Production (with SSL)
DATABASE_URL=postgresql://user:pass@host:5432/db?sslmode=require
```

### SSL Modes

| Mode | Description | Recommended |
|------|-------------|-------------|
| `disable` | No SSL | ❌ Never |
| `allow` | Try SSL, fall back to non-SSL | ❌ Insecure |
| `prefer` | Try SSL, fall back to non-SSL (default) | ⚠️ Dev only |
| `require` | Require SSL, don't verify cert | ✅ Internal network |
| `verify-ca` | Require SSL, verify CA | ✅ Production |
| `verify-full` | Require SSL, verify CA and hostname | ✅ External DB |

### Using Custom Certificates

If your PostgreSQL server uses a custom CA:

```bash
DATABASE_URL=postgresql://user:pass@host:5432/db?sslmode=verify-ca&sslrootcert=/path/to/ca.crt
```

### Prisma Configuration

The Prisma client automatically uses SSL settings from DATABASE_URL. No additional configuration needed.

## Object Storage SSL Configuration

### RustFS with SSL

1. Enable SSL in `.env.prod`:

```bash
MINIO_USE_SSL=true
```

2. If using a custom certificate, mount it in Docker:

```yaml
# docker-compose.prod.yml
rustfs:
  volumes:
    - ./certs/rustfs:/root/.rustfs/certs
```

3. Place certificates:
```
certs/rustfs/
├── public.crt    # Server certificate
├── private.key   # Private key
└── CAs/          # CA certificates (optional)
    └── ca.crt
```

### AWS S3

AWS S3 uses SSL by default. No additional configuration needed.

### Azure Blob Storage

Azure Blob Storage uses SSL by default. Ensure your connection string starts with `https://`.

## Redis SSL Configuration

### Redis with TLS

1. Update Redis URL:

```bash
# Without SSL
REDIS_URL=redis://:password@host:6379

# With SSL
REDIS_URL=rediss://:password@host:6379
```

Note the `rediss://` protocol (double 's').

2. For custom certificates, configure in Docker:

```yaml
# docker-compose.prod.yml
redis:
  command: >
    redis-server 
    --tls-port 6379 
    --port 0 
    --tls-cert-file /tls/redis.crt 
    --tls-key-file /tls/redis.key 
    --tls-ca-cert-file /tls/ca.crt
```

## Traefik SSL Configuration

### Automatic SSL with Let's Encrypt

The production Docker Compose automatically configures SSL via Let's Encrypt:

```yaml
# docker-compose.prod.yml
traefik:
  command:
    - "--certificatesresolvers.letsencrypt.acme.email=${ACME_EMAIL}"
    - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
    - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
```

### Manual SSL Certificates

For custom certificates:

1. Create a dynamic configuration file:

```yaml
# traefik/dynamic/certs.yml
tls:
  certificates:
    - certFile: /certs/server.crt
      keyFile: /certs/server.key
```

2. Mount certificates in Docker:

```yaml
traefik:
  volumes:
    - ./certs:/certs:ro
    - ./traefik/dynamic:/etc/traefik/dynamic:ro
```

## Verification

### Check Database SSL

```bash
# Connect and verify SSL
docker compose exec postgres psql -U $POSTGRES_USER -d $POSTGRES_DB -c "SHOW ssl;"

# Should return: on
```

### Check Traefik SSL

```bash
# Test SSL certificate
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com

# Or use curl
curl -vvv https://yourdomain.com 2>&1 | grep -A 5 "SSL connection"
```

### Check RustFS SSL

```bash
# Test RustFS endpoint
curl -vvv https://storage.yourdomain.com/health/live
```

## Production Checklist

- [ ] DATABASE_URL includes `?sslmode=require` or stricter
- [ ] MINIO_USE_SSL=true
- [ ] REDIS_URL uses `rediss://` protocol
- [ ] Traefik has valid SSL certificates
- [ ] All internal service-to-service communication uses internal network
- [ ] Frontend served over HTTPS only
- [ ] HSTS headers enabled
- [ ] API endpoints only accessible via HTTPS

## Troubleshooting

### "SSL connection required" error

Your client is trying to connect without SSL. Ensure:
1. The connection string includes SSL parameters
2. The client library supports SSL
3. The server is configured to accept SSL connections

### "Certificate verify failed" error

1. Check if using self-signed certificate
2. Add CA certificate to trusted store
3. Use `sslmode=require` instead of `verify-full` for internal networks

### "Connection refused on port 443"

1. Verify Traefik is running and bound to port 443
2. Check firewall rules allow inbound 443
3. Verify DNS resolves to correct IP

## References

- [PostgreSQL SSL Support](https://www.postgresql.org/docs/current/libpq-ssl.html)
- [RustFS GitHub](https://github.com/rustfs/rustfs) - S3-compatible storage
- [Redis TLS Support](https://redis.io/docs/management/security/encryption/)
- [Traefik HTTPS & TLS](https://doc.traefik.io/traefik/https/overview/)

