#!/bin/bash
# Migration script for Configuration as Code module

set -e

echo "Running Prisma migrations for Configuration as Code module..."

cd "$(dirname "$0")/../services/shared"

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
  # Try to get it from docker-compose or .env
  if [ -f "../../.env" ]; then
    export $(grep DATABASE_URL ../../.env | xargs)
  fi
  
  # Default to docker-compose values if still not set
  if [ -z "$DATABASE_URL" ]; then
    export DATABASE_URL="postgresql://grc:grc_secret@localhost:5433/gigachad_grc"
  fi
fi

echo "Using DATABASE_URL: ${DATABASE_URL//:\/\/[^:]*:[^@]*@/:\/\/***:***@}"

# Generate Prisma client
echo "Generating Prisma client..."
npx prisma generate

# Run migrations
echo "Running migrations..."
npx prisma migrate dev --name add_config_as_code || npx prisma db push

echo "Migration complete!"
echo ""
echo "You can now:"
echo "1. Refresh the Configuration as Code page"
echo "2. Click 'Initialize from platform state' if files don't appear automatically"

