# Secure API Key Storage v2 Project Context

## Project Overview
This is a secure API key storage system with enterprise-grade encryption, RBAC, and comprehensive security features.

### Repository
- GitHub: https://github.com/murr2k/secure-api-key-storage-v2
- User: murr2k (Murray Kopit)
- Email: murr2k@gmail.com

## Architecture
- **Backend**: FastAPI with Python 3.11
- **Frontend**: Next.js 14 with TypeScript
- **Database**: PostgreSQL 15 
- **Cache**: Redis 7
- **Monitoring**: Prometheus + Grafana
- **Container**: Docker + Docker Compose

## Key Features Implemented
1. **Security Enhancements**:
   - AES-256-GCM encryption for API keys
   - Secure memory management with constant-time comparisons
   - Memory clearing after use
   - RBAC (Role-Based Access Control)
   - Multi-factor authentication support (TOTP)
   - Certificate-based authentication
   - Tamper-proof audit logging
   - Automated key rotation policies

2. **API Endpoints**:
   - `/api/health` - Health check
   - `/api/auth/login` - Authentication
   - `/api/keys` - Key management
   - `/api/audit` - Audit logs
   - `/api/analytics/overview` - Dashboard analytics

## Docker Setup
The project is containerized with the following services:
- `secure-key-storage`: Main application (ports 80, 443, 3000, 8000)
- `postgres`: Database
- `redis`: Cache
- `prometheus`: Metrics collection
- `grafana`: Metrics visualization (port 3001)
- `backup`: Automated backup service

## Access Points
- Frontend Dashboard: http://localhost:3000
- Backend API: http://localhost:8000
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3001

## Default Credentials
- Username: `admin`
- Password: Set via `API_KEY_MASTER` environment variable

## Common Commands
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f secure-key-storage

# Rebuild after changes
docker-compose down && docker-compose build --no-cache && docker-compose up -d

# Check service health
docker-compose ps
```

## CI/CD Pipeline
The project uses GitHub Actions for continuous integration and deployment:
- **Workflow file**: `.github/workflows/deploy.yml`
- **Stages**: Security Scan → Lint & Test → Build → Deploy → Validate
- **Python**: Black formatting, Flake8 linting, Pytest, Bandit security scanning
- **Docker**: Multi-platform builds (amd64/arm64) pushed to GitHub Container Registry

### Pipeline Configuration Required:
1. Set deployment secrets in GitHub repository settings:
   - `STAGING_HOST`, `STAGING_USER`, `STAGING_SSH_KEY`
   - `PRODUCTION_HOST`, `PRODUCTION_USER`, `PRODUCTION_SSH_KEY`
   - `SLACK_WEBHOOK` (optional)
2. Update deployment URLs in workflow file (currently using example.com placeholders)

## Known Issues
1. Nginx fails to start due to permission issues when running as non-root user (not critical - services are accessible directly)
2. Some audit and monitoring modules are temporarily disabled in supervisord.conf
3. CI/CD validate-deployment job uses placeholder URLs that need updating

## Recent Work (July 11, 2025)
- Implemented all critical security enhancements from QA audit
- Created comprehensive documentation
- Set up CI/CD pipeline with GitHub Actions
- Containerized the entire application
- Fixed multiple import and dependency issues
- Successfully deployed all services
- **Fixed CI/CD Pipeline Issues**:
  - Formatted all Python code with Black (line length 100)
  - Fixed 71 flake8 violations (unused imports, line length, f-strings)
  - Added basic test file for pytest
  - Resolved all Bandit security scan issues
  - Updated .gitignore for backups and security reports

## Code Quality Standards
- **Python Formatting**: Black with `--line-length 100`
- **Python Linting**: Flake8 with `--max-line-length=100`
- **Security**: Bandit scan (no medium/high severity issues allowed)
- **Testing**: Pytest with coverage reporting
- **Frontend**: ESLint and Next.js standards

## Next Steps
- Configure GitHub repository secrets for deployments
- Update deployment URLs from example.com to actual domains
- Fix nginx permission issues for proper reverse proxy
- Enable audit and monitoring modules
- Add more comprehensive tests
- Implement backup restoration functionality
- Add support for more cloud providers (AWS KMS, Azure Key Vault)