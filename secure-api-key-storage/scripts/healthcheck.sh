#!/bin/bash
# Health Check Script for Secure API Key Storage

# Configuration
DOMAIN=${DOMAIN:-"secure.murraykopit.com"}
ALERT_EMAIL=${ALERT_EMAIL:-"murray@murraykopit.com"}
HEALTH_ENDPOINT="https://${DOMAIN}/api/health"
FALLBACK_ENDPOINT="http://localhost:8000/api/health"
MAX_RETRIES=3
RETRY_DELAY=10

# Function to send alert
send_alert() {
    local subject="$1"
    local message="$2"
    
    # Check if mail command exists
    if command -v mail &> /dev/null; then
        echo "${message}" | mail -s "${subject}" "${ALERT_EMAIL}"
    fi
    
    # Log to file
    echo "[$(date)] ALERT: ${subject} - ${message}" >> /var/log/health-check.log
}

# Function to check health
check_health() {
    local endpoint="$1"
    local response
    local http_code
    
    response=$(curl -s -w "\n%{http_code}" "${endpoint}" 2>/dev/null)
    http_code=$(echo "${response}" | tail -n1)
    
    if [ "${http_code}" = "200" ]; then
        return 0
    else
        return 1
    fi
}

# Main health check logic
echo "[$(date)] Starting health check..." >> /var/log/health-check.log

# Try primary endpoint
if check_health "${HEALTH_ENDPOINT}"; then
    echo "[$(date)] Health check passed (HTTPS)" >> /var/log/health-check.log
    exit 0
fi

# Try fallback endpoint
if check_health "${FALLBACK_ENDPOINT}"; then
    echo "[$(date)] Health check passed (HTTP fallback)" >> /var/log/health-check.log
    exit 0
fi

# Health check failed, try to restart
echo "[$(date)] Health check failed, attempting restart..." >> /var/log/health-check.log

# Send alert
send_alert "Secure API Key Storage - Health Check Failed" \
"The health check for ${DOMAIN} failed at $(date). Attempting automatic restart..."

# Restart containers
cd /home/$(whoami)/secure-api-key-storage-v2
docker-compose -f docker-compose.production.yml restart

# Wait for services to come up
sleep 30

# Check again
retry_count=0
while [ ${retry_count} -lt ${MAX_RETRIES} ]; do
    if check_health "${FALLBACK_ENDPOINT}"; then
        echo "[$(date)] Service recovered after restart" >> /var/log/health-check.log
        send_alert "Secure API Key Storage - Service Recovered" \
        "The service at ${DOMAIN} has been successfully restarted and is now healthy."
        exit 0
    fi
    
    sleep ${RETRY_DELAY}
    ((retry_count++))
done

# Service still down after restart
echo "[$(date)] Service failed to recover after restart" >> /var/log/health-check.log
send_alert "Secure API Key Storage - Service Down" \
"CRITICAL: The service at ${DOMAIN} is down and failed to recover after automatic restart. Manual intervention required."

# Get container logs for debugging
docker-compose -f docker-compose.production.yml logs --tail=50 >> /var/log/health-check-debug.log 2>&1

exit 1