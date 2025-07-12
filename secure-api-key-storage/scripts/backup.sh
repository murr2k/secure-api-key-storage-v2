#!/bin/bash
# Backup Script for Secure API Key Storage

set -e

# Configuration
BACKUP_DIR="/backups"
BACKUP_RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-30}
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_NAME="secure-api-backup-${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

# Create backup directory
mkdir -p "${BACKUP_PATH}"

echo "[$(date)] Starting backup to ${BACKUP_PATH}"

# Backup database
echo "[$(date)] Backing up PostgreSQL database..."
PGPASSWORD="${DB_PASSWORD}" pg_dump \
    -h postgres \
    -U "${POSTGRES_USER}" \
    -d "${POSTGRES_DB}" \
    -f "${BACKUP_PATH}/database.sql"

# Backup Redis data
echo "[$(date)] Backing up Redis data..."
redis-cli -h redis -a "${REDIS_PASSWORD}" --rdb "${BACKUP_PATH}/redis.rdb"

# Backup application data
echo "[$(date)] Backing up application data..."
if [ -d "/app/keys" ]; then
    cp -r /app/keys "${BACKUP_PATH}/"
fi

if [ -d "/app/config" ]; then
    cp -r /app/config "${BACKUP_PATH}/"
fi

# Create tarball
echo "[$(date)] Creating compressed archive..."
cd "${BACKUP_DIR}"
tar -czf "${BACKUP_NAME}.tar.gz" "${BACKUP_NAME}"
rm -rf "${BACKUP_NAME}"

# Calculate backup size
BACKUP_SIZE=$(du -h "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" | cut -f1)
echo "[$(date)] Backup completed: ${BACKUP_NAME}.tar.gz (${BACKUP_SIZE})"

# Clean up old backups
echo "[$(date)] Cleaning up old backups..."
find "${BACKUP_DIR}" -name "secure-api-backup-*.tar.gz" -mtime +${BACKUP_RETENTION_DAYS} -delete

# List remaining backups
echo "[$(date)] Current backups:"
ls -lh "${BACKUP_DIR}"/secure-api-backup-*.tar.gz 2>/dev/null || echo "No backups found"

echo "[$(date)] Backup process completed successfully"