#!/bin/bash
set -e

# Secure API Key Storage v2 Deployment Script

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="secure-api-key-storage-v2"
COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"

# Functions
print_banner() {
    echo -e "${GREEN}"
    echo "================================================"
    echo "  Secure API Key Storage v2 Deployment"
    echo "================================================"
    echo -e "${NC}"
}

check_requirements() {
    echo -e "${YELLOW}Checking requirements...${NC}"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Error: Docker is not installed${NC}"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}Error: Docker Compose is not installed${NC}"
        exit 1
    fi
    
    # Check if .env exists
    if [ ! -f "$ENV_FILE" ]; then
        echo -e "${YELLOW}Warning: .env file not found. Creating from example...${NC}"
        cp .env.example .env
        echo -e "${RED}Please edit .env file with your configuration before continuing${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}All requirements satisfied!${NC}"
}

generate_secrets() {
    echo -e "${YELLOW}Generating secure secrets...${NC}"
    
    # Check if secrets already exist
    if grep -q "your_jwt_secret_key_here" "$ENV_FILE"; then
        JWT_SECRET=$(openssl rand -hex 32)
        sed -i "s/your_jwt_secret_key_here/$JWT_SECRET/" "$ENV_FILE"
        echo -e "${GREEN}Generated JWT secret${NC}"
    fi
    
    if grep -q "your_encryption_key_here" "$ENV_FILE"; then
        ENCRYPTION_KEY=$(openssl rand -hex 32)
        sed -i "s/your_encryption_key_here/$ENCRYPTION_KEY/" "$ENV_FILE"
        echo -e "${GREEN}Generated encryption key${NC}"
    fi
    
    if grep -q "your_secure_database_password" "$ENV_FILE"; then
        DB_PASSWORD=$(openssl rand -base64 24)
        sed -i "s/your_secure_database_password/$DB_PASSWORD/" "$ENV_FILE"
        echo -e "${GREEN}Generated database password${NC}"
    fi
    
    if grep -q "your_secure_redis_password" "$ENV_FILE"; then
        REDIS_PASSWORD=$(openssl rand -base64 24)
        sed -i "s/your_secure_redis_password/$REDIS_PASSWORD/" "$ENV_FILE"
        echo -e "${GREEN}Generated Redis password${NC}"
    fi
}

create_ssl_certificates() {
    echo -e "${YELLOW}Creating SSL certificates...${NC}"
    
    if [ ! -f "docker/ssl/cert.pem" ]; then
        mkdir -p docker/ssl
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout docker/ssl/key.pem \
            -out docker/ssl/cert.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
            2>/dev/null
        echo -e "${GREEN}Generated self-signed SSL certificates${NC}"
    else
        echo -e "${GREEN}SSL certificates already exist${NC}"
    fi
}

build_images() {
    echo -e "${YELLOW}Building Docker images...${NC}"
    docker-compose build --no-cache
    echo -e "${GREEN}Images built successfully!${NC}"
}

deploy() {
    echo -e "${YELLOW}Deploying application...${NC}"
    
    # Create necessary directories
    mkdir -p data logs backups config
    
    # Set permissions
    chmod 700 data
    chmod 755 logs backups config
    
    # Start services
    docker-compose up -d
    
    echo -e "${GREEN}Application deployed successfully!${NC}"
}

health_check() {
    echo -e "${YELLOW}Performing health check...${NC}"
    
    # Wait for services to start
    sleep 30
    
    # Check backend health
    if curl -f http://localhost:8000/health &>/dev/null; then
        echo -e "${GREEN}Backend API is healthy${NC}"
    else
        echo -e "${RED}Backend API health check failed${NC}"
        docker-compose logs backend
        exit 1
    fi
    
    # Check frontend
    if curl -f http://localhost:3000 &>/dev/null; then
        echo -e "${GREEN}Frontend is healthy${NC}"
    else
        echo -e "${RED}Frontend health check failed${NC}"
        docker-compose logs frontend
        exit 1
    fi
    
    echo -e "${GREEN}All services are healthy!${NC}"
}

show_info() {
    echo -e "${GREEN}"
    echo "================================================"
    echo "  Deployment Complete!"
    echo "================================================"
    echo -e "${NC}"
    echo "Access the application at:"
    echo "  - Frontend: https://localhost"
    echo "  - API: https://localhost/api"
    echo "  - API Docs: https://localhost/docs"
    echo "  - Prometheus: http://localhost:9090"
    echo "  - Grafana: http://localhost:3001"
    echo ""
    echo "Default credentials:"
    echo "  - Admin: Check ADMIN_USERNAME and ADMIN_PASSWORD in .env"
    echo "  - Grafana: admin / (check GRAFANA_PASSWORD in .env)"
    echo ""
    echo "Useful commands:"
    echo "  - View logs: docker-compose logs -f"
    echo "  - Stop services: docker-compose down"
    echo "  - Backup data: docker-compose exec backup /backup.sh"
    echo "  - Update: git pull && ./deploy.sh"
}

# Main execution
case "${1:-deploy}" in
    deploy)
        print_banner
        check_requirements
        generate_secrets
        create_ssl_certificates
        build_images
        deploy
        health_check
        show_info
        ;;
    update)
        echo -e "${YELLOW}Updating application...${NC}"
        git pull
        docker-compose pull
        docker-compose up -d --remove-orphans
        health_check
        echo -e "${GREEN}Update complete!${NC}"
        ;;
    backup)
        echo -e "${YELLOW}Creating backup...${NC}"
        docker-compose exec backup tar -czf /backups/manual-backup-$(date +%Y%m%d-%H%M%S).tar.gz /data
        echo -e "${GREEN}Backup created in ./backups/${NC}"
        ;;
    restore)
        if [ -z "$2" ]; then
            echo -e "${RED}Usage: $0 restore <backup-file>${NC}"
            exit 1
        fi
        echo -e "${YELLOW}Restoring from backup: $2${NC}"
        docker-compose down
        tar -xzf "backups/$2" -C .
        docker-compose up -d
        echo -e "${GREEN}Restore complete!${NC}"
        ;;
    stop)
        echo -e "${YELLOW}Stopping services...${NC}"
        docker-compose down
        echo -e "${GREEN}Services stopped${NC}"
        ;;
    logs)
        docker-compose logs -f "${2:-}"
        ;;
    shell)
        docker-compose exec "${2:-secure-key-storage}" /bin/bash
        ;;
    *)
        echo "Usage: $0 {deploy|update|backup|restore|stop|logs|shell}"
        exit 1
        ;;
esac