# Multi-stage Dockerfile for Secure API Key Storage v2

# Stage 1: Python base with security tools
FROM python:3.11-slim AS python-base

# Security: Create non-root user
RUN useradd -m -s /bin/bash keymanager && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        libffi-dev \
        libssl-dev \
        curl \
        git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Stage 2: Backend builder
FROM python-base AS backend-builder

WORKDIR /app

# Copy Python requirements
COPY secure-api-key-storage/requirements.txt ./
COPY secure-api-key-storage/dashboard/backend/requirements.txt ./backend-requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r backend-requirements.txt

# Stage 3: Frontend builder
FROM node:18-alpine AS frontend-builder

WORKDIR /app

# Copy frontend files
COPY secure-api-key-storage/dashboard/frontend/package*.json ./
RUN npm ci --only=production

COPY secure-api-key-storage/dashboard/frontend/ ./
RUN npm run build

# Stage 4: Final production image
FROM python-base AS production

# Install runtime dependencies including Node.js
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nginx \
        supervisor \
        postgresql-client \
        netcat-openbsd \
        openssl \
        curl \
        ca-certificates && \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=backend-builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=backend-builder /usr/local/bin /usr/local/bin

# Create necessary directories
RUN mkdir -p /app /data /logs /etc/nginx/sites-available /var/log/supervisor && \
    chown -R keymanager:keymanager /app /data /logs

WORKDIR /app

# Copy application code
COPY --chown=keymanager:keymanager secure-api-key-storage/ ./

# Copy frontend build
COPY --from=frontend-builder --chown=keymanager:keymanager /app/.next ./dashboard/frontend/.next
COPY --from=frontend-builder --chown=keymanager:keymanager /app/public ./dashboard/frontend/public
COPY --from=frontend-builder --chown=keymanager:keymanager /app/node_modules ./dashboard/frontend/node_modules

# Copy configuration files
COPY --chown=keymanager:keymanager docker/nginx.conf /etc/nginx/sites-available/default
COPY --chown=keymanager:keymanager docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY --chown=keymanager:keymanager docker/entrypoint.sh /entrypoint.sh

# Set permissions
RUN chmod +x /entrypoint.sh && \
    chmod 700 /app && \
    chmod 700 /data

# Security: Set file permissions
RUN find /app -type f -name "*.py" -exec chmod 644 {} \; && \
    find /app -type d -exec chmod 755 {} \;

# Expose ports
EXPOSE 80 443 8000 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Switch to non-root user
USER keymanager

# Environment variables
ENV PYTHONPATH=/app \
    NODE_ENV=production \
    SECURE_STORAGE_PATH=/data \
    LOG_PATH=/logs

# Entry point
ENTRYPOINT ["/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]