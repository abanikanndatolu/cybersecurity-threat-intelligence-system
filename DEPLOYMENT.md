# 🚀 Deployment Guide - Advanced Threat Intelligence Platform

This comprehensive deployment guide covers all aspects of deploying the Advanced Threat Intelligence Platform, from development environments to enterprise-scale production deployments with high availability and security considerations.

## 📋 System Requirements

### Minimum Requirements

**Development Environment:**
- CPU: 2 cores, 2.0 GHz
- RAM: 4 GB
- Storage: 10 GB free space
- Network: Broadband internet connection
- OS: Linux (Ubuntu 20.04+), macOS 11+, Windows 10+

**Production Environment:**
- CPU: 4 cores, 2.5 GHz
- RAM: 8 GB
- Storage: 50 GB free space (SSD recommended)
- Network: High-speed internet with low latency
- OS: Linux (Ubuntu 22.04 LTS recommended)

**Enterprise Environment:**
- CPU: 8+ cores, 3.0 GHz
- RAM: 16+ GB
- Storage: 100+ GB SSD with backup storage
- Network: Redundant high-speed connections
- OS: Linux (Ubuntu 22.04 LTS or RHEL 8+)

### Software Dependencies

**Core Requirements:**
- Python 3.11 or higher
- pip (Python package installer)
- Git (version control)
- SQLite 3.35+ (development) or PostgreSQL 13+ (production)
- Modern web browser (Chrome 90+, Firefox 88+, Safari 14+, Edge 90+)

**Optional Components:**
- Docker and Docker Compose (containerized deployment)
- Nginx (reverse proxy and load balancing)
- Redis (caching and session storage)
- Elasticsearch (advanced search and analytics)
- Grafana and Prometheus (monitoring and alerting)

## 🏠 Development Environment Setup

### Quick Start Development

1. **Repository Clone and Setup**
   ```bash
   git clone https://github.com/your-username/threat-intelligence-platform.git
   cd threat-intelligence-platform
   ```

2. **Python Environment Configuration**
   ```bash
   python3.11 -m venv venv
   source venv/bin/activate  # Linux/macOS
   # venv\Scripts\activate  # Windows
   ```

3. **Dependency Installation**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Database Initialization**
   ```bash
   python database.py
   ```

5. **Application Launch**
   ```bash
   streamlit run app.py --server.port=8501 --server.address=localhost
   ```

6. **Access and Verification**
   - Open browser to `http://localhost:8501`
   - Verify dashboard loads correctly
   - Test basic functionality

### Development Configuration

**Environment Variables (.env file):**
```bash
# Application Configuration
TIP_DEBUG=true
TIP_LOG_LEVEL=DEBUG
TIP_DATABASE_URL=sqlite:///threat_intelligence.db
TIP_SECRET_KEY=development-secret-key-change-in-production

# API Configuration
VIRUSTOTAL_API_KEY=your-virustotal-api-key
SHODAN_API_KEY=your-shodan-api-key
MISP_URL=https://your-misp-instance.com
MISP_API_KEY=your-misp-api-key

# Collection Configuration
TIP_COLLECTION_INTERVAL=3600
TIP_MAX_CONCURRENT_COLLECTIONS=5
TIP_COLLECTION_TIMEOUT=300

# Performance Configuration
TIP_CACHE_TTL=1800
TIP_MAX_IOCS_PER_PAGE=100
TIP_ENABLE_CACHING=true
```

**Development Utilities:**
```bash
# Database reset (development only)
python -c "from database import init_database; init_database()"

# Sample data generation
python -c "from utils import generate_sample_data; generate_sample_data()"

# Run tests
python -m pytest tests/ -v

# Code quality checks
flake8 .
black .
isort .
```

## 🐳 Containerized Deployment

### Docker Configuration

**Dockerfile:**
```dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd -m -u 1000 tipuser && \
    chown -R tipuser:tipuser /app && \
    mkdir -p /app/data /app/logs && \
    chown -R tipuser:tipuser /app/data /app/logs

USER tipuser

# Expose application port
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Initialize database and start application
CMD ["sh", "-c", "python database.py && streamlit run app.py --server.port=8501 --server.address=0.0.0.0"]
```

**Docker Compose for Development:**
```yaml
version: '3.8'

services:
  threat-intelligence-platform:
    build: .
    ports:
      - "8501:8501"
    environment:
      - TIP_DEBUG=true
      - TIP_DATABASE_URL=sqlite:///data/threat_intelligence.db
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./config:/app/config
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8501/_stcore/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped
    command: redis-server --appendonly yes

volumes:
  redis_data:
```

**Production Docker Compose:**
```yaml
version: '3.8'

services:
  threat-intelligence-platform:
    build: .
    environment:
      - TIP_DEBUG=false
      - TIP_DATABASE_URL=postgresql://tipuser:${DB_PASSWORD}@postgres:5432/threat_intelligence
      - TIP_REDIS_URL=redis://redis:6379/0
      - TIP_SECRET_KEY=${SECRET_KEY}
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
      - SHODAN_API_KEY=${SHODAN_API_KEY}
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./config:/app/config
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=threat_intelligence
      - POSTGRES_USER=tipuser
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 2G

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped
    command: redis-server --appendonly yes --maxmemory 512mb --maxmemory-policy allkeys-lru

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
      - nginx_cache:/var/cache/nginx
    depends_on:
      - threat-intelligence-platform
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  nginx_cache:
```

### Container Deployment Commands

```bash
# Development deployment
docker-compose -f docker-compose.dev.yml up -d

# Production deployment
docker-compose -f docker-compose.prod.yml up -d

# Scale application instances
docker-compose -f docker-compose.prod.yml up -d --scale threat-intelligence-platform=3

# View logs
docker-compose logs -f threat-intelligence-platform

# Update deployment
docker-compose pull
docker-compose up -d --force-recreate

# Backup database
docker-compose exec postgres pg_dump -U tipuser threat_intelligence > backup.sql
```

## 🌐 Production Deployment

### Server Preparation

**Ubuntu 22.04 LTS Setup:**
```bash
# System update
sudo apt update && sudo apt upgrade -y

# Install essential packages
sudo apt install -y \
    python3.11 \
    python3.11-venv \
    python3.11-dev \
    python3-pip \
    git \
    nginx \
    postgresql \
    postgresql-contrib \
    redis-server \
    certbot \
    python3-certbot-nginx \
    htop \
    iotop \
    nethogs \
    fail2ban \
    ufw

# Create application user
sudo useradd -m -s /bin/bash tipuser
sudo usermod -aG sudo tipuser

# Create application directories
sudo mkdir -p /opt/threat-intelligence-platform/{app,data,logs,config,backups}
sudo chown -R tipuser:tipuser /opt/threat-intelligence-platform
```

### Database Setup

**PostgreSQL Configuration:**
```bash
# Switch to postgres user
sudo -u postgres psql

# Create database and user
CREATE DATABASE threat_intelligence;
CREATE USER tipuser WITH ENCRYPTED PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE threat_intelligence TO tipuser;
ALTER USER tipuser CREATEDB;
\q

# Configure PostgreSQL
sudo nano /etc/postgresql/14/main/postgresql.conf
# Uncomment and modify:
# listen_addresses = 'localhost'
# max_connections = 100
# shared_buffers = 256MB
# effective_cache_size = 1GB

sudo nano /etc/postgresql/14/main/pg_hba.conf
# Add line:
# local   threat_intelligence   tipuser   md5

sudo systemctl restart postgresql
sudo systemctl enable postgresql
```

**Redis Configuration:**
```bash
# Configure Redis
sudo nano /etc/redis/redis.conf
# Modify:
# maxmemory 512mb
# maxmemory-policy allkeys-lru
# save 900 1
# save 300 10
# save 60 10000

sudo systemctl restart redis-server
sudo systemctl enable redis-server
```

### Application Deployment

**Code Deployment:**
```bash
# Switch to application user
sudo -u tipuser -i

# Clone repository
cd /opt/threat-intelligence-platform
git clone https://github.com/your-username/threat-intelligence-platform.git app
cd app

# Setup Python environment
python3.11 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Configure environment
cp .env.example .env
nano .env
# Configure production settings

# Initialize database
python database.py

# Test application
streamlit run app.py --server.port=8501 --server.address=127.0.0.1
```

**Production Environment Configuration (.env):**
```bash
# Application Configuration
TIP_DEBUG=false
TIP_LOG_LEVEL=INFO
TIP_DATABASE_URL=postgresql://tipuser:secure_password_here@localhost:5432/threat_intelligence
TIP_REDIS_URL=redis://localhost:6379/0
TIP_SECRET_KEY=very-secure-secret-key-for-production

# Security Configuration
TIP_SESSION_TIMEOUT=3600
TIP_MAX_LOGIN_ATTEMPTS=5
TIP_ENABLE_RATE_LIMITING=true
TIP_ALLOWED_HOSTS=your-domain.com,www.your-domain.com

# API Configuration
VIRUSTOTAL_API_KEY=your-production-virustotal-key
SHODAN_API_KEY=your-production-shodan-key
MISP_URL=https://your-misp-instance.com
MISP_API_KEY=your-production-misp-key

# Performance Configuration
TIP_COLLECTION_INTERVAL=1800
TIP_MAX_CONCURRENT_COLLECTIONS=10
TIP_COLLECTION_TIMEOUT=600
TIP_CACHE_TTL=3600
TIP_MAX_IOCS_PER_PAGE=50
TIP_ENABLE_CACHING=true

# Monitoring Configuration
TIP_ENABLE_METRICS=true
TIP_METRICS_PORT=9090
TIP_LOG_TO_FILE=true
TIP_LOG_ROTATION_SIZE=100MB
TIP_LOG_RETENTION_DAYS=30
```

### Systemd Service Configuration

**Create Service File (/etc/systemd/system/threat-intelligence-platform.service):**
```ini
[Unit]
Description=Advanced Threat Intelligence Platform
After=network.target postgresql.service redis-server.service
Wants=postgresql.service redis-server.service

[Service]
Type=simple
User=tipuser
Group=tipuser
WorkingDirectory=/opt/threat-intelligence-platform/app
Environment=PATH=/opt/threat-intelligence-platform/app/venv/bin
EnvironmentFile=/opt/threat-intelligence-platform/app/.env
ExecStart=/opt/threat-intelligence-platform/app/venv/bin/streamlit run app.py --server.port=8501 --server.address=127.0.0.1
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tip

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/threat-intelligence-platform

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

**Service Management:**
```bash
# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable threat-intelligence-platform
sudo systemctl start threat-intelligence-platform

# Check service status
sudo systemctl status threat-intelligence-platform

# View logs
sudo journalctl -u threat-intelligence-platform -f
```

### Nginx Reverse Proxy

**Nginx Configuration (/etc/nginx/sites-available/threat-intelligence-platform):**
```nginx
# Rate limiting
limit_req_zone $binary_remote_addr zone=tip_login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=tip_api:10m rate=30r/m;

# Upstream configuration
upstream tip_backend {
    least_conn;
    server 127.0.0.1:8501 max_fails=3 fail_timeout=30s;
    # Add more servers for load balancing
    # server 127.0.0.1:8502 max_fails=3 fail_timeout=30s;
    # server 127.0.0.1:8503 max_fails=3 fail_timeout=30s;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;
    return 301 https://$server_name$request_uri;
}

# Main HTTPS server
server {
    listen 443 ssl http2;
    server_name your-domain.com www.your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss: https:;" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Logging
    access_log /var/log/nginx/tip_access.log;
    error_log /var/log/nginx/tip_error.log;

    # Main application
    location / {
        # Rate limiting for general access
        limit_req zone=tip_api burst=10 nodelay;

        proxy_pass http://tip_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        proxy_connect_timeout 60;

        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }

    # API endpoints with stricter rate limiting
    location /api/ {
        limit_req zone=tip_api burst=5 nodelay;
        
        proxy_pass http://tip_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300;
        proxy_send_timeout 300;
        proxy_connect_timeout 60;
    }

    # Static files (if any)
    location /static/ {
        alias /opt/threat-intelligence-platform/app/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://tip_backend;
        access_log off;
    }

    # Deny access to sensitive files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    location ~ \.(env|ini|conf|log)$ {
        deny all;
        access_log off;
        log_not_found off;
    }
}
```

**Enable Site and SSL:**
```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/threat-intelligence-platform /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Enable automatic renewal
sudo systemctl enable certbot.timer
```

## 🔒 Security Hardening

### Firewall Configuration

**UFW Setup:**
```bash
# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (change port if needed)
sudo ufw allow 22/tcp

# Allow HTTP/HTTPS
sudo ufw allow 'Nginx Full'

# Allow database access (if external)
# sudo ufw allow from 10.0.0.0/8 to any port 5432

# Enable firewall
sudo ufw enable
sudo ufw status verbose
```

### Fail2Ban Configuration

**Fail2Ban Setup (/etc/fail2ban/jail.local):**
```ini
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/tip_error.log
maxretry = 3

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
logpath = /var/log/nginx/tip_error.log
maxretry = 10
```

### Application Security

**Database Security:**
```bash
# Set proper file permissions
sudo chmod 600 /opt/threat-intelligence-platform/app/.env
sudo chown tipuser:tipuser /opt/threat-intelligence-platform/app/.env

# PostgreSQL security
sudo -u postgres psql
ALTER USER tipuser WITH PASSWORD 'new_secure_password';
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO tipuser;
\q
```

**Log Security:**
```bash
# Setup log rotation
sudo nano /etc/logrotate.d/threat-intelligence-platform

/opt/threat-intelligence-platform/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su tipuser tipuser
}
```

## 📊 Monitoring and Alerting

### Application Monitoring

**Health Check Script (/opt/threat-intelligence-platform/scripts/health_check.sh):**
```bash
#!/bin/bash

# Health check script
HEALTH_URL="http://localhost:8501/_stcore/health"
LOG_FILE="/opt/threat-intelligence-platform/logs/health_check.log"

# Check application health
if curl -f -s $HEALTH_URL > /dev/null; then
    echo "$(date): Application is healthy" >> $LOG_FILE
    exit 0
else
    echo "$(date): Application health check failed" >> $LOG_FILE
    # Send alert (email, Slack, etc.)
    # systemctl restart threat-intelligence-platform
    exit 1
fi
```

**System Monitoring Script:**
```bash
#!/bin/bash
# system_monitor.sh

LOG_FILE="/opt/threat-intelligence-platform/logs/system_monitor.log"

while true; do
    # CPU usage
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    
    # Memory usage
    MEMORY_USAGE=$(free | grep Mem | awk '{printf("%.2f", $3/$2 * 100.0)}')
    
    # Disk usage
    DISK_USAGE=$(df -h / | awk 'NR==2{print $5}' | cut -d'%' -f1)
    
    # Database connections
    DB_CONNECTIONS=$(sudo -u postgres psql -t -c "SELECT count(*) FROM pg_stat_activity WHERE datname='threat_intelligence';" | xargs)
    
    # Log metrics
    echo "$(date): CPU: ${CPU_USAGE}%, Memory: ${MEMORY_USAGE}%, Disk: ${DISK_USAGE}%, DB Connections: ${DB_CONNECTIONS}" >> $LOG_FILE
    
    # Alert thresholds
    if (( $(echo "$CPU_USAGE > 80" | bc -l) )); then
        echo "$(date): HIGH CPU USAGE ALERT: ${CPU_USAGE}%" >> $LOG_FILE
    fi
    
    if (( $(echo "$MEMORY_USAGE > 85" | bc -l) )); then
        echo "$(date): HIGH MEMORY USAGE ALERT: ${MEMORY_USAGE}%" >> $LOG_FILE
    fi
    
    if [ "$DISK_USAGE" -gt 85 ]; then
        echo "$(date): HIGH DISK USAGE ALERT: ${DISK_USAGE}%" >> $LOG_FILE
    fi
    
    sleep 300  # Check every 5 minutes
done
```

### Prometheus Integration

**Metrics Endpoint (metrics.py):**
```python
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time

# Metrics
REQUEST_COUNT = Counter('tip_requests_total', 'Total requests', ['method', 'endpoint'])
REQUEST_DURATION = Histogram('tip_request_duration_seconds', 'Request duration')
IOC_COUNT = Gauge('tip_iocs_total', 'Total IOCs in database')
COLLECTION_ERRORS = Counter('tip_collection_errors_total', 'Collection errors', ['source'])

def start_metrics_server(port=9090):
    start_http_server(port)

def update_ioc_count(count):
    IOC_COUNT.set(count)

def record_request(method, endpoint, duration):
    REQUEST_COUNT.labels(method=method, endpoint=endpoint).inc()
    REQUEST_DURATION.observe(duration)

def record_collection_error(source):
    COLLECTION_ERRORS.labels(source=source).inc()
```

## 🔄 Backup and Disaster Recovery

### Automated Backup System

**Database Backup Script (/opt/threat-intelligence-platform/scripts/backup.sh):**
```bash
#!/bin/bash

# Configuration
BACKUP_DIR="/opt/threat-intelligence-platform/backups"
DB_NAME="threat_intelligence"
DB_USER="tipuser"
RETENTION_DAYS=30
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Database backup
echo "Starting database backup..."
pg_dump -h localhost -U $DB_USER -d $DB_NAME | gzip > $BACKUP_DIR/db_backup_$DATE.sql.gz

# Application data backup
echo "Starting application data backup..."
tar -czf $BACKUP_DIR/app_data_$DATE.tar.gz -C /opt/threat-intelligence-platform data/ logs/ config/

# Configuration backup
echo "Starting configuration backup..."
tar -czf $BACKUP_DIR/config_backup_$DATE.tar.gz -C /opt/threat-intelligence-platform/app .env

# Remove old backups
find $BACKUP_DIR -name "*.gz" -mtime +$RETENTION_DAYS -delete

# Verify backup integrity
if [ -f "$BACKUP_DIR/db_backup_$DATE.sql.gz" ]; then
    echo "Database backup completed successfully: db_backup_$DATE.sql.gz"
else
    echo "Database backup failed!"
    exit 1
fi

echo "Backup process completed at $(date)"
```

**Cron Job Setup:**
```bash
# Add to crontab
sudo crontab -e

# Daily backup at 2 AM
0 2 * * * /opt/threat-intelligence-platform/scripts/backup.sh >> /opt/threat-intelligence-platform/logs/backup.log 2>&1

# Weekly full system backup
0 3 * * 0 /opt/threat-intelligence-platform/scripts/full_backup.sh >> /opt/threat-intelligence-platform/logs/backup.log 2>&1
```

### Disaster Recovery Procedures

**Recovery Script (/opt/threat-intelligence-platform/scripts/restore.sh):**
```bash
#!/bin/bash

# Disaster recovery script
BACKUP_FILE=$1
BACKUP_DIR="/opt/threat-intelligence-platform/backups"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

echo "Starting disaster recovery process..."

# Stop services
sudo systemctl stop threat-intelligence-platform
sudo systemctl stop nginx

# Restore database
echo "Restoring database..."
gunzip -c $BACKUP_DIR/$BACKUP_FILE | sudo -u postgres psql -d threat_intelligence

# Restore application data
echo "Restoring application data..."
tar -xzf $BACKUP_DIR/app_data_*.tar.gz -C /opt/threat-intelligence-platform/

# Set permissions
sudo chown -R tipuser:tipuser /opt/threat-intelligence-platform/data
sudo chown -R tipuser:tipuser /opt/threat-intelligence-platform/logs

# Start services
sudo systemctl start threat-intelligence-platform
sudo systemctl start nginx

# Verify recovery
sleep 10
if curl -f http://localhost:8501/_stcore/health; then
    echo "Disaster recovery completed successfully"
else
    echo "Disaster recovery failed - manual intervention required"
    exit 1
fi
```

## 🔧 Maintenance and Updates

### Regular Maintenance Tasks

**Weekly Maintenance Script:**
```bash
#!/bin/bash
# weekly_maintenance.sh

echo "Starting weekly maintenance..."

# Update system packages
sudo apt update && sudo apt upgrade -y

# Clean old logs
find /opt/threat-intelligence-platform/logs -name "*.log" -mtime +7 -exec gzip {} \;
find /opt/threat-intelligence-platform/logs -name "*.gz" -mtime +30 -delete

# Database maintenance
sudo -u postgres psql -d threat_intelligence -c "VACUUM ANALYZE;"
sudo -u postgres psql -d threat_intelligence -c "REINDEX DATABASE threat_intelligence;"

# Clear old cache
redis-cli FLUSHDB

# Restart services
sudo systemctl restart threat-intelligence-platform
sudo systemctl restart nginx

echo "Weekly maintenance completed"
```

**Application Updates:**
```bash
#!/bin/bash
# update.sh

echo "Starting application update..."

# Backup current version
cp -r /opt/threat-intelligence-platform/app /opt/threat-intelligence-platform/app.backup.$(date +%Y%m%d)

# Pull latest code
cd /opt/threat-intelligence-platform/app
sudo -u tipuser git pull origin main

# Update dependencies
sudo -u tipuser ./venv/bin/pip install -r requirements.txt

# Run database migrations (if any)
sudo -u tipuser ./venv/bin/python database.py

# Restart application
sudo systemctl restart threat-intelligence-platform

# Verify update
sleep 10
if curl -f http://localhost:8501/_stcore/health; then
    echo "Application update completed successfully"
    # Remove backup
    rm -rf /opt/threat-intelligence-platform/app.backup.*
else
    echo "Application update failed - rolling back"
    sudo systemctl stop threat-intelligence-platform
    rm -rf /opt/threat-intelligence-platform/app
    mv /opt/threat-intelligence-platform/app.backup.* /opt/threat-intelligence-platform/app
    sudo systemctl start threat-intelligence-platform
    exit 1
fi
```

## 🚨 Troubleshooting Guide

### Common Issues and Solutions

**Application Won't Start:**
```bash
# Check service status
sudo systemctl status threat-intelligence-platform

# Check logs
sudo journalctl -u threat-intelligence-platform -n 50

# Check port availability
sudo netstat -tlnp | grep 8501

# Check database connectivity
sudo -u tipuser psql -h localhost -U tipuser -d threat_intelligence -c "SELECT 1;"
```

**Database Connection Issues:**
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check database logs
sudo tail -f /var/log/postgresql/postgresql-14-main.log

# Test connection
sudo -u postgres psql -l
```

**Performance Issues:**
```bash
# Monitor system resources
htop
iotop
df -h

# Check database performance
sudo -u postgres psql -d threat_intelligence -c "SELECT * FROM pg_stat_activity;"

# Check slow queries
sudo -u postgres psql -d threat_intelligence -c "SELECT query, calls, total_time, mean_time FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;"
```

**Memory Issues:**
```bash
# Check memory usage
free -h
ps aux --sort=-%mem | head -10

# Clear cache
echo 3 | sudo tee /proc/sys/vm/drop_caches

# Restart services
sudo systemctl restart threat-intelligence-platform
```

### Emergency Procedures

**Service Recovery:**
```bash
# Emergency restart
sudo systemctl stop threat-intelligence-platform
sudo systemctl start threat-intelligence-platform

# Force kill if needed
sudo pkill -f "streamlit run app.py"
```

**Database Recovery:**
```bash
# Stop application
sudo systemctl stop threat-intelligence-platform

# Restore from backup
gunzip -c /opt/threat-intelligence-platform/backups/db_backup_latest.sql.gz | sudo -u postgres psql -d threat_intelligence

# Start application
sudo systemctl start threat-intelligence-platform
```

## 📞 Support and Documentation

### Support Channels

- **Documentation**: Comprehensive guides and API documentation
- **Issue Tracker**: GitHub issues for bug reports and feature requests
- **Community Forum**: User discussions and knowledge sharing
- **Enterprise Support**: Professional support for production deployments

### Additional Resources

- **Security Best Practices**: Detailed security implementation guide
- **Performance Tuning**: Optimization guide for large-scale deployments
- **Integration Guide**: Instructions for integrating with existing security tools
- **API Documentation**: Complete API reference and examples

---

**Note**: This deployment guide provides comprehensive instructions for various deployment scenarios. Always test deployments in a staging environment before production deployment. Customize configurations based on your specific requirements and security policies.

