# Deployment Guide - Secure API Key Storage v2

This guide covers the complete deployment process for the Secure API Key Storage v2 application using Docker and CI/CD pipelines.

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Docker Deployment](#docker-deployment)
4. [CI/CD Pipeline](#cicd-pipeline)
5. [Configuration](#configuration)
6. [SSL/TLS Setup](#ssltls-setup)
7. [Monitoring Setup](#monitoring-setup)
8. [Backup and Recovery](#backup-and-recovery)
9. [Scaling](#scaling)
10. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements
- Linux server (Ubuntu 20.04+ recommended)
- 4GB RAM minimum (8GB recommended)
- 20GB storage minimum
- Docker 20.10+
- Docker Compose 2.0+
- Git

### Required Ports
- 80 (HTTP)
- 443 (HTTPS)
- 8000 (API - internal)
- 3000 (Frontend - internal)
- 9090 (Prometheus)
- 3001 (Grafana)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/murr2k/secure-api-key-storage-v2.git
cd secure-api-key-storage-v2

# Make deployment script executable
chmod +x deploy.sh

# Run deployment
./deploy.sh deploy
```

## Docker Deployment

### 1. Environment Setup

Copy and configure the environment file:

```bash
cp .env.example .env
nano .env
```

Key configurations to update:
- Database passwords
- JWT secret keys
- Admin credentials
- Email settings
- Domain names

### 2. Build and Deploy

```bash
# Build Docker images
docker-compose build

# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

### 3. Service Architecture

The deployment includes:
- **secure-key-storage**: Main application container
- **postgres**: PostgreSQL database
- **redis**: Redis cache
- **nginx**: Reverse proxy
- **prometheus**: Metrics collection
- **grafana**: Metrics visualization
- **backup**: Automated backup service

## CI/CD Pipeline

### GitHub Actions Setup

1. **Configure Repository Secrets**:
   Go to Settings > Secrets and add:
   ```
   STAGING_HOST
   STAGING_USER
   STAGING_SSH_KEY
   PRODUCTION_HOST
   PRODUCTION_USER
   PRODUCTION_SSH_KEY
   SLACK_WEBHOOK (optional)
   ```

2. **Workflow Triggers**:
   - Push to `develop` → Deploy to staging
   - Push to `main`/`master` → Deploy to production
   - Pull requests → Run tests only

3. **Pipeline Stages**:
   ```
   Security Scan → Lint & Test → Build → Deploy → Validate
   ```

### Manual Deployment

For manual deployments to specific environments:

```bash
# Deploy to staging
git push origin develop

# Deploy to production
git push origin main

# Trigger deployment manually
# Go to Actions tab > Select workflow > Run workflow
```

## Configuration

### Security Configuration

1. **Generate Secure Keys**:
   ```bash
   # Generate JWT secret
   openssl rand -hex 32

   # Generate encryption key
   openssl rand -hex 32

   # Generate strong passwords
   openssl rand -base64 24
   ```

2. **Update .env file** with generated values

### Application Configuration

Edit `config/audit_config.yaml` for audit settings:

```yaml
audit:
  retention_days: 365
  signing_enabled: true
  rotation_policy:
    max_age_days: 90
    warning_days: 14
```

### Database Configuration

PostgreSQL is automatically configured. For production:

1. **Enable backups**:
   ```bash
   docker-compose exec postgres pg_dump -U keymanager secure_keys > backup.sql
   ```

2. **Performance tuning**:
   Edit `docker-compose.yml` to add PostgreSQL configurations

## SSL/TLS Setup

### Self-Signed Certificates (Development)

Certificates are auto-generated. To regenerate:

```bash
rm -rf docker/ssl/*
./deploy.sh deploy
```

### Production Certificates

1. **Using Let's Encrypt**:
   ```bash
   # Install certbot
   sudo apt install certbot

   # Generate certificates
   sudo certbot certonly --standalone -d yourdomain.com

   # Update docker-compose.yml volumes
   volumes:
     - /etc/letsencrypt/live/yourdomain.com/fullchain.pem:/etc/nginx/ssl/cert.pem:ro
     - /etc/letsencrypt/live/yourdomain.com/privkey.pem:/etc/nginx/ssl/key.pem:ro
   ```

2. **Using Custom Certificates**:
   ```bash
   # Copy certificates
   cp your-cert.pem docker/ssl/cert.pem
   cp your-key.pem docker/ssl/key.pem
   ```

## Monitoring Setup

### Prometheus

Access at: http://localhost:9090

Key metrics:
- `auth_failed_attempts_total`
- `key_access_total`
- `http_request_duration_seconds`
- `audit_log_entries_total`

### Grafana

Access at: http://localhost:3001

1. **Login** with credentials from .env
2. **Import dashboards** from `docker/grafana/dashboards/`
3. **Configure alerts** in Alerting > Alert rules

### Custom Alerts

Edit `docker/prometheus/alerts.yml` to add custom alerts:

```yaml
- alert: CustomAlert
  expr: your_metric > threshold
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Alert summary"
```

## Backup and Recovery

### Automated Backups

Backups run daily at 2 AM. Configure in .env:

```bash
BACKUP_ENABLED=true
BACKUP_SCHEDULE="0 2 * * *"
BACKUP_RETENTION_DAYS=30
```

### Manual Backup

```bash
# Create backup
./deploy.sh backup

# List backups
ls -la backups/

# Backup to S3
docker-compose exec backup aws s3 sync /backups s3://your-bucket/
```

### Recovery

```bash
# Stop services
./deploy.sh stop

# Restore from backup
./deploy.sh restore backup-20240111-020000.tar.gz

# Verify restoration
./deploy.sh deploy
```

## Scaling

### Horizontal Scaling

1. **API Servers**:
   ```yaml
   # docker-compose.yml
   secure-key-storage:
     scale: 3  # Run 3 instances
   ```

2. **Load Balancing**:
   Nginx automatically load balances between instances

### Vertical Scaling

Adjust resource limits in docker-compose.yml:

```yaml
secure-key-storage:
  deploy:
    resources:
      limits:
        cpus: '2.0'
        memory: 4G
      reservations:
        cpus: '1.0'
        memory: 2G
```

## Troubleshooting

### Common Issues

1. **Services not starting**:
   ```bash
   # Check logs
   docker-compose logs service-name

   # Restart service
   docker-compose restart service-name
   ```

2. **Database connection issues**:
   ```bash
   # Check PostgreSQL
   docker-compose exec postgres pg_isready

   # Reset database
   docker-compose down -v
   docker-compose up -d
   ```

3. **Permission errors**:
   ```bash
   # Fix permissions
   sudo chown -R $(id -u):$(id -g) data/ logs/
   ```

### Debug Mode

Enable debug logging:

```bash
# Set in .env
LOG_LEVEL=debug

# Restart services
docker-compose restart
```

### Health Checks

```bash
# Check all services
curl http://localhost:8000/health
curl http://localhost:3000
curl http://localhost:9090/-/healthy

# Check specific service
docker-compose exec secure-key-storage curl localhost:8000/health
```

## Security Best Practices

1. **Regular Updates**:
   ```bash
   # Update images
   docker-compose pull
   docker-compose up -d
   ```

2. **Security Scanning**:
   ```bash
   # Scan images
   docker scan secure-api-key-storage-v2:latest
   ```

3. **Network Isolation**:
   - Use internal networks
   - Limit exposed ports
   - Configure firewall rules

4. **Secrets Management**:
   - Never commit .env files
   - Rotate keys regularly
   - Use Docker secrets in production

## Production Checklist

- [ ] Configure production domain
- [ ] Set up SSL certificates
- [ ] Configure firewall rules
- [ ] Set up monitoring alerts
- [ ] Configure backup strategy
- [ ] Test disaster recovery
- [ ] Enable audit logging
- [ ] Configure log rotation
- [ ] Set up health monitoring
- [ ] Document runbooks

---

For additional support, refer to the main [README](README.md) or open an issue on GitHub.