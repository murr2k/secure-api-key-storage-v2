# Hosting Instructions for secure.murraykopit.com

## Overview
This document provides step-by-step instructions for deploying the Secure API Key Storage system as a subdomain (secure.murraykopit.com) on HostPapa hosting.

## Prerequisites
- HostPapa hosting account with SSH access
- Domain murraykopit.com configured in HostPapa
- SSL certificate support (Let's Encrypt or custom)
- VPS or dedicated server (shared hosting won't work due to Docker requirements)

## Part 1: HostPapa Configuration (For Murray)

### 1.1 Create Subdomain
1. Log into HostPapa control panel
2. Navigate to "Domains" → "Subdomains"
3. Create subdomain: `secure.murraykopit.com`
4. Point it to a directory (e.g., `/home/username/secure-api`)

### 1.2 Configure DNS
1. Add A record for `secure.murraykopit.com` pointing to your server IP
2. If using Cloudflare, add the subdomain there as well
3. Wait for DNS propagation (5-30 minutes)

### 1.3 Enable SSH Access
1. Ensure SSH access is enabled for your account
2. Note down SSH credentials:
   - Host: `murraykopit.com` or server IP
   - Port: 22 (or custom if changed)
   - Username: Your HostPapa username
   - Password/Key: Your SSH password or private key

### 1.4 Server Requirements Check
Verify your hosting plan supports:
- Docker and Docker Compose
- At least 2GB RAM
- 10GB free disk space
- Ability to run background processes
- Access to ports 80, 443, and custom ports

## Part 2: Deployment Preparation (For Claude)

### 2.1 Create Production Configuration
```bash
# Create production environment file
cat > .env.production << EOF
# Production Environment Configuration
NODE_ENV=production
MASTER_PASSWORD=\${MASTER_PASSWORD}
API_KEY_MASTER=\${MASTER_PASSWORD}

# Database Configuration
DB_PASSWORD=\${DB_PASSWORD}
POSTGRES_USER=keymanager
POSTGRES_DB=secure_keys

# Redis Configuration
REDIS_PASSWORD=\${REDIS_PASSWORD}

# JWT Configuration
JWT_SECRET_KEY=\${JWT_SECRET_KEY}

# Domain Configuration
DOMAIN=secure.murraykopit.com
FRONTEND_URL=https://secure.murraykopit.com
API_URL=https://secure.murraykopit.com/api

# SSL Configuration
SSL_CERT_PATH=/etc/letsencrypt/live/secure.murraykopit.com/fullchain.pem
SSL_KEY_PATH=/etc/letsencrypt/live/secure.murraykopit.com/privkey.pem

# CORS Configuration
CORS_ORIGINS=https://secure.murraykopit.com,https://murraykopit.com
EOF
```

### 2.2 Create Production Docker Compose
```yaml
# docker-compose.production.yml
version: '3.8'

services:
  secure-key-storage:
    image: ghcr.io/murr2k/secure-api-key-storage:latest
    container_name: secure-key-storage
    restart: always
    environment:
      - NODE_ENV=production
      - DOMAIN=\${DOMAIN}
      - MASTER_PASSWORD=\${MASTER_PASSWORD}
      - DB_PASSWORD=\${DB_PASSWORD}
      - REDIS_PASSWORD=\${REDIS_PASSWORD}
      - JWT_SECRET_KEY=\${JWT_SECRET_KEY}
    volumes:
      - ./keys:/app/keys
      - ./backups:/app/backups
      - ./logs:/app/logs
      - /etc/letsencrypt:/etc/letsencrypt:ro
    ports:
      - "127.0.0.1:8000:8000"
      - "127.0.0.1:3000:3000"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - secure-network

  postgres:
    image: postgres:15-alpine
    container_name: secure-key-postgres
    restart: always
    environment:
      - POSTGRES_USER=\${POSTGRES_USER}
      - POSTGRES_PASSWORD=\${DB_PASSWORD}
      - POSTGRES_DB=\${POSTGRES_DB}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - secure-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keymanager"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: secure-key-redis
    restart: always
    command: redis-server --requirepass \${REDIS_PASSWORD} --maxmemory 256mb
    volumes:
      - redis-data:/data
    networks:
      - secure-network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  nginx:
    image: nginx:alpine
    container_name: secure-key-nginx
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/production.conf:/etc/nginx/nginx.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
    depends_on:
      - secure-key-storage
    networks:
      - secure-network

volumes:
  postgres-data:
  redis-data:

networks:
  secure-network:
    driver: bridge
```

### 2.3 Create Nginx Configuration
```nginx
# nginx/production.conf
events {
    worker_connections 1024;
}

http {
    upstream frontend {
        server secure-key-storage:3000;
    }

    upstream backend {
        server secure-key-storage:8000;
    }

    server {
        listen 80;
        server_name secure.murraykopit.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name secure.murraykopit.com;

        ssl_certificate /etc/letsencrypt/live/secure.murraykopit.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/secure.murraykopit.com/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        # Security headers
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;

        location /api {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /ws {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }

        location / {
            proxy_pass http://frontend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

### 2.4 Create Deployment Script
```bash
#!/bin/bash
# deploy.sh

# Exit on error
set -e

echo "🚀 Deploying Secure API Key Storage to Production"

# Load environment variables
source .env.production

# Pull latest images
echo "📦 Pulling latest Docker images..."
docker-compose -f docker-compose.production.yml pull

# Stop existing containers
echo "🛑 Stopping existing containers..."
docker-compose -f docker-compose.production.yml down

# Start new containers
echo "▶️ Starting new containers..."
docker-compose -f docker-compose.production.yml up -d

# Wait for services to be healthy
echo "⏳ Waiting for services to be healthy..."
sleep 30

# Check health
echo "🏥 Checking service health..."
curl -f https://secure.murraykopit.com/api/health || exit 1

echo "✅ Deployment complete!"
```

## Part 3: SSL Certificate Setup

### 3.1 Install Certbot
```bash
# On the server
sudo apt-get update
sudo apt-get install certbot

# Generate SSL certificate
sudo certbot certonly --standalone -d secure.murraykopit.com
```

### 3.2 Auto-renewal Setup
```bash
# Add to crontab
0 2 * * * /usr/bin/certbot renew --quiet --post-hook "docker restart secure-key-nginx"
```

## Part 4: Deployment Steps

### 4.1 Initial Server Setup
```bash
# SSH into HostPapa server
ssh username@murraykopit.com

# Install Docker (if not already installed)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### 4.2 Clone and Configure
```bash
# Clone repository
cd ~
git clone https://github.com/murr2k/secure-api-key-storage-v2.git
cd secure-api-key-storage-v2

# Create production environment
cp .env.production.example .env.production
nano .env.production  # Edit with secure passwords

# Create required directories
mkdir -p nginx logs backups keys
```

### 4.3 Deploy Application
```bash
# Make deployment script executable
chmod +x deploy.sh

# Run deployment
./deploy.sh
```

## Part 5: Security Hardening

### 5.1 Firewall Configuration
```bash
# Configure UFW firewall
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

### 5.2 Secure Environment Variables
```bash
# Set restrictive permissions
chmod 600 .env.production
chmod 700 keys/ backups/
```

### 5.3 Backup Configuration
```bash
# Create backup script
cat > backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/home/username/backups/secure-api-$(date +%Y%m%d-%H%M%S)"
mkdir -p $BACKUP_DIR

# Backup database
docker exec secure-key-postgres pg_dump -U keymanager secure_keys > $BACKUP_DIR/database.sql

# Backup keys
cp -r keys/ $BACKUP_DIR/

# Backup configuration
cp .env.production $BACKUP_DIR/

# Compress
tar -czf $BACKUP_DIR.tar.gz $BACKUP_DIR
rm -rf $BACKUP_DIR

# Keep only last 30 days of backups
find /home/username/backups -name "secure-api-*.tar.gz" -mtime +30 -delete
EOF

chmod +x backup.sh

# Add to crontab
0 3 * * * /home/username/secure-api-key-storage-v2/backup.sh
```

## Part 6: Monitoring Setup

### 6.1 Health Check Monitoring
```bash
# Create health check script
cat > healthcheck.sh << 'EOF'
#!/bin/bash
if ! curl -f https://secure.murraykopit.com/api/health; then
    echo "Health check failed at $(date)" | mail -s "Secure API Key Storage Down" murray@murraykopit.com
    docker-compose -f docker-compose.production.yml restart
fi
EOF

chmod +x healthcheck.sh

# Add to crontab (every 5 minutes)
*/5 * * * * /home/username/secure-api-key-storage-v2/healthcheck.sh
```

### 6.2 Log Rotation
```bash
# Create logrotate configuration
sudo tee /etc/logrotate.d/secure-api-storage << EOF
/home/username/secure-api-key-storage-v2/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 username username
    sharedscripts
    postrotate
        docker exec secure-key-storage kill -USR1 1
    endscript
}
EOF
```

## Part 7: Maintenance Commands

### Common Operations
```bash
# View logs
docker-compose -f docker-compose.production.yml logs -f

# Restart services
docker-compose -f docker-compose.production.yml restart

# Update application
git pull
docker-compose -f docker-compose.production.yml pull
./deploy.sh

# Backup database
docker exec secure-key-postgres pg_dump -U keymanager secure_keys > backup.sql

# Restore database
docker exec -i secure-key-postgres psql -U keymanager secure_keys < backup.sql
```

## Part 8: Troubleshooting

### Common Issues

1. **Port conflicts**
   - Check: `sudo netstat -tlnp | grep -E '80|443|3000|8000'`
   - Solution: Modify port mappings in docker-compose

2. **SSL certificate issues**
   - Check: `sudo certbot certificates`
   - Solution: Renew with `sudo certbot renew`

3. **Database connection issues**
   - Check: `docker logs secure-key-postgres`
   - Solution: Verify passwords match in .env.production

4. **Permission issues**
   - Check: `ls -la keys/ backups/`
   - Solution: `sudo chown -R $USER:$USER .`

## Part 9: Final Checklist

- [ ] Subdomain DNS configured
- [ ] SSL certificate obtained
- [ ] Docker & Docker Compose installed
- [ ] Repository cloned
- [ ] Environment variables configured
- [ ] Firewall rules applied
- [ ] Backup script scheduled
- [ ] Health monitoring active
- [ ] Test login working
- [ ] API endpoints accessible

## Support Contacts

- **HostPapa Support**: For server/hosting issues
- **GitHub Issues**: For application bugs
- **Murray Kopit**: murray@murraykopit.com