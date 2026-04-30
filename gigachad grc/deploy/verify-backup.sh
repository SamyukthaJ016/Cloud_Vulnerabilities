#!/bin/bash

################################################################################
# GigaChad GRC - Backup Verification Script
################################################################################
#
# This script verifies the integrity of the most recent backup by:
# 1. Checking the archive can be extracted
# 2. Verifying the manifest is present
# 3. Checking critical files exist
# 4. Validating the database dump
#
# Usage: ./verify-backup.sh [backup_directory]
#
################################################################################

set -euo pipefail

BACKUP_ROOT="${1:-/backups/gigachad-grc}"
VERIFY_DIR="/tmp/backup-verify-$$"
LOG_FILE="/var/log/grc-backup-verify-$(date +%Y%m%d-%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$LOG_FILE"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }

cleanup() {
    rm -rf "$VERIFY_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# Find most recent backup
LATEST_BACKUP=$(find "$BACKUP_ROOT" -name "backup-*.tar.gz" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2)

if [ -z "$LATEST_BACKUP" ]; then
    log_error "No backup files found in $BACKUP_ROOT"
    exit 1
fi

log_info "Verifying backup: $LATEST_BACKUP"

# Test 1: Archive integrity
log_info "Test 1: Checking archive integrity..."
if gzip -t "$LATEST_BACKUP" 2>/dev/null; then
    log_success "Archive integrity check passed"
else
    log_error "Archive is corrupted"
    exit 1
fi

# Test 2: Extract to temp directory
log_info "Test 2: Extracting backup..."
mkdir -p "$VERIFY_DIR"
if tar -xzf "$LATEST_BACKUP" -C "$VERIFY_DIR" 2>/dev/null; then
    log_success "Archive extraction successful"
else
    log_error "Failed to extract archive"
    exit 1
fi

# Find extracted directory
BACKUP_DIR=$(find "$VERIFY_DIR" -maxdepth 1 -type d -name "backup-*" | head -1)
if [ -z "$BACKUP_DIR" ]; then
    BACKUP_DIR="$VERIFY_DIR"
fi

# Test 3: Manifest check
log_info "Test 3: Checking backup manifest..."
if [ -f "$BACKUP_DIR/manifest.json" ]; then
    log_success "Manifest file present"
    
    # Parse and display manifest info
    if command -v jq >/dev/null 2>&1; then
        BACKUP_DATE=$(jq -r '.backup_date // "unknown"' "$BACKUP_DIR/manifest.json")
        log_info "  Backup date: $BACKUP_DATE"
    fi
else
    log_warning "Manifest file not found (older backup format)"
fi

# Test 4: Critical files check
log_info "Test 4: Checking critical files..."
CRITICAL_FILES=(
    "postgres_backup.dump"
    "configs/.env.prod"
)

MISSING_FILES=0
for file in "${CRITICAL_FILES[@]}"; do
    if [ -f "$BACKUP_DIR/$file" ]; then
        log_success "Found: $file"
    else
        log_warning "Missing: $file"
        ((MISSING_FILES++))
    fi
done

# Test 5: Database dump validation
log_info "Test 5: Validating database dump..."
if [ -f "$BACKUP_DIR/postgres_backup.dump" ]; then
    # Check dump header
    if file "$BACKUP_DIR/postgres_backup.dump" | grep -q "PostgreSQL"; then
        log_success "Database dump appears valid"
    else
        log_warning "Database dump format unrecognized"
    fi
    
    # Check size
    DUMP_SIZE=$(du -h "$BACKUP_DIR/postgres_backup.dump" | cut -f1)
    log_info "  Database dump size: $DUMP_SIZE"
elif [ -f "$BACKUP_DIR/postgres_backup.sql.gz" ]; then
    log_success "Compressed SQL dump found"
    SQL_SIZE=$(du -h "$BACKUP_DIR/postgres_backup.sql.gz" | cut -f1)
    log_info "  SQL dump size: $SQL_SIZE"
else
    log_error "No database dump found"
    exit 1
fi

# Calculate backup age
BACKUP_TIMESTAMP=$(stat -c %Y "$LATEST_BACKUP" 2>/dev/null || stat -f %m "$LATEST_BACKUP" 2>/dev/null)
CURRENT_TIMESTAMP=$(date +%s)
BACKUP_AGE_HOURS=$(( (CURRENT_TIMESTAMP - BACKUP_TIMESTAMP) / 3600 ))

log_info "Backup age: ${BACKUP_AGE_HOURS} hours"

if [ "$BACKUP_AGE_HOURS" -gt 48 ]; then
    log_warning "Backup is more than 48 hours old!"
fi

# Summary
echo ""
echo "======================================"
log_info "Verification Summary"
echo "======================================"
log_info "Backup file: $(basename "$LATEST_BACKUP")"
log_info "Backup size: $(du -h "$LATEST_BACKUP" | cut -f1)"
log_info "Backup age: ${BACKUP_AGE_HOURS} hours"

if [ "$MISSING_FILES" -eq 0 ]; then
    log_success "All verification checks passed!"
    
    # Send success notification if configured
    if [ "${SLACK_ENABLED:-false}" = "true" ] && [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
        curl -X POST "$SLACK_WEBHOOK_URL" \
            -H 'Content-Type: application/json' \
            -d "{\"text\": \"✅ GigaChad GRC backup verification passed\nBackup: $(basename "$LATEST_BACKUP")\nAge: ${BACKUP_AGE_HOURS} hours\"}" \
            >/dev/null 2>&1 || true
    fi
    
    exit 0
else
    log_warning "Verification completed with $MISSING_FILES missing files"
    exit 1
fi
