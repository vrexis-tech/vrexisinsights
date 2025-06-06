# 🚀 Production Deployment Guide

## 📋 Quick Setup Checklist

### Step 1: Environment Setup
```bash
# 1. Generate secure secrets
openssl rand -hex 32  # Use this for JWT_SECRET
openssl rand -hex 32  # Use this for JWT_REFRESH_SECRET

# 2. Create .env file in your backend directory
cp .env.example .env

# 3. Update .env with your values
```

### Step 2: Backend Deployment
```bash
# 1. Install dependencies
go mod tidy

# 2. Build for production
CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o vrexis-insights main.go

# 3. Set environment variables (production)
export ENVIRONMENT=production
export JWT_SECRET=your-generated-secret-here
export JWT_REFRESH_SECRET=your-other-generated-secret-here
export ALLOWED_ORIGINS=https://yourdomain.com
export PORT=8080

# 4. Run the server
./vrexis-insights
```

### Step 3: Frontend Deployment
```bash
# 1. Set production environment variables
echo "REACT_APP_API_URL=https://your-api-domain.com" > .env.production

# 2. Build for production
npm run build

# 3. Serve with a production server (nginx, Apache, or CDN)
```

---

## 🐳 Docker Configuration

### Dockerfile (Backend)
```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies for SQLite
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o vrexis-insights main.go

# Production stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/

# Create data directory
RUN mkdir -p /data

# Copy the binary
COPY --from=builder /app/vrexis-insights .

# Create non-root user for security
RUN adduser -D -s /bin/sh vrexis
USER vrexis

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

CMD ["./vrexis-insights"]
```

### docker-compose.yml
```yaml
version: '3.8'

services:
  vrexis-backend:
    build: .
    ports:
      - "8080:8080"
    environment:
      - ENVIRONMENT=production
      - PORT=8080
      - DB_PATH=/data/vrexis_insights.db
      - JWT_SECRET=${JWT_SECRET}
      - JWT_REFRESH_SECRET=${JWT_REFRESH_SECRET}
      - ALLOWED_ORIGINS=${ALLOWED_ORIGINS}
      - LOG_LEVEL=info
    volumes:
      - vrexis_data:/data
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETGID
      - SETUID
    networks:
      - vrexis_network

  # Optional: Add nginx reverse proxy
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - vrexis-backend
    restart: unless-stopped
    networks:
      - vrexis_network

volumes:
  vrexis_data:

networks:
  vrexis_network:
    driver: bridge
```

---

## 🌐 Nginx Configuration

### nginx.conf
```nginx
events {
    worker_connections 1024;
}

http {
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:" always;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=general:10m rate=30r/m;

    upstream backend {
        server vrexis-backend:8080;
    }

    server {
        listen 80;
        server_name yourdomain.com www.yourdomain.com;
        
        # Redirect HTTP to HTTPS
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name yourdomain.com www.yourdomain.com;

        # SSL configuration
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;

        # HSTS
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        # API routes
        location /api/ {
            limit_req zone=general burst=10 nodelay;
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Auth routes with stricter rate limiting
        location /auth/ {
            limit_req zone=auth burst=3 nodelay;
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health check
        location /health {
            proxy_pass http://backend;
            access_log off;
        }

        # Frontend static files
        location / {
            root /var/www/html;
            try_files $uri $uri/ /index.html;
            
            # Cache static assets
            location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
                expires 1y;
                add_header Cache-Control "public, immutable";
            }
        }
    }
}
```

---

## ☁️ Cloud Deployment Options

### 1. DigitalOcean App Platform
```yaml
# .do/app.yaml
name: vrexis-insights
services:
- name: backend
  source_dir: /
  github:
    repo: your-username/vrexis-insights
    branch: main
  run_command: ./vrexis-insights
  environment_slug: go
  instance_count: 1
  instance_size_slug: basic-xxs
  envs:
  - key: ENVIRONMENT
    value: production
  - key: JWT_SECRET
    value: ${JWT_SECRET}
  - key: JWT_REFRESH_SECRET
    value: ${JWT_REFRESH_SECRET}
  - key: ALLOWED_ORIGINS
    value: https://vrexis-insights.ondigitalocean.app
  http_port: 8080

static_sites:
- name: frontend
  source_dir: /build
  github:
    repo: your-username/vrexis-insights-frontend
    branch: main
  build_command: npm run build
```

### 2. AWS ECS with Fargate
```json
{
  "family": "vrexis-insights",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "vrexis-backend",
      "image": "your-account.dkr.ecr.region.amazonaws.com/vrexis-insights:latest",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "ENVIRONMENT", "value": "production"},
        {"name": "PORT", "value": "8080"}
      ],
      "secrets": [
        {"name": "JWT_SECRET", "valueFrom": "arn:aws:secretsmanager:region:account:secret:vrexis/jwt-secret"},
        {"name": "JWT_REFRESH_SECRET", "valueFrom": "arn:aws:secretsmanager:region:account:secret:vrexis/refresh-secret"}
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/vrexis-insights",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### 3. Google Cloud Run
```yaml
# cloudbuild.yaml
steps:
- name: 'gcr.io/cloud-builders/docker'
  args: ['build', '-t', 'gcr.io/$PROJECT_ID/vrexis-insights', '.']
- name: 'gcr.io/cloud-builders/docker'
  args: ['push', 'gcr.io/$PROJECT_ID/vrexis-insights']
- name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
  entrypoint: gcloud
  args:
  - 'run'
  - 'deploy'
  - 'vrexis-insights'
  - '--image'
  - 'gcr.io/$PROJECT_ID/vrexis-insights'
  - '--region'
  - 'us-central1'
  - '--platform'
  - 'managed'
  - '--port'
  - '8080'
  - '--set-env-vars'
  - 'ENVIRONMENT=production'
  - '--max-instances'
  - '10'
```

---

## 📊 Monitoring Setup

### Prometheus Metrics (Optional)
```go
// Add to main.go
import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

// Add metrics endpoint
r.Handle("/metrics", promhttp.Handler())
```

### Health Check Monitoring
```bash
#!/bin/bash
# healthcheck.sh - Add to your monitoring system

HEALTH_URL="https://yourdomain.com/health"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL)

if [ $RESPONSE -eq 200 ]; then
    echo "✅ Service healthy"
    exit 0
else
    echo "❌ Service unhealthy (HTTP $RESPONSE)"
    exit 1
fi
```

---

## 🔐 SSL Certificate Setup

### Let's Encrypt with Certbot
```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### Self-signed for Development
```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

---

## 🗃️ Database Migration

### PostgreSQL Production Setup
```sql
-- Create production database
CREATE DATABASE vrexis_insights;
CREATE USER vrexis_user WITH ENCRYPTED PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE vrexis_insights TO vrexis_user;

-- Migration script
-- Add to your Go application for PostgreSQL support
```

---

## 📋 Production Checklist

### Security ✅
- [ ] Environment variables configured
- [ ] Strong JWT secrets (32+ characters)
- [ ] HTTPS enabled with valid certificates
- [ ] Rate limiting configured
- [ ] Security headers enabled
- [ ] Input validation implemented
- [ ] CORS properly configured
- [ ] Database secured

### Performance ✅
- [ ] Static assets cached
- [ ] Gzip compression enabled
- [ ] Database connection pooling
- [ ] Health checks implemented
- [ ] Graceful shutdown configured
- [ ] Resource limits set

### Monitoring ✅
- [ ] Structured logging enabled
- [ ] Health check endpoint available
- [ ] Error tracking configured
- [ ] Uptime monitoring setup
- [ ] Performance monitoring
- [ ] Security monitoring

### Backup & Recovery ✅
- [ ] Database backups automated
- [ ] Backup restoration tested
- [ ] Disaster recovery plan
- [ ] Configuration backed up
- [ ] SSL certificates backed up

---

## 🚀 Deployment Commands

### Quick Production Deploy
```bash
# 1. Clone and setup
git clone your-repo
cd vrexis-insights

# 2. Configure environment
cp .env.example .env
nano .env  # Edit with your values

# 3. Generate secrets
openssl rand -hex 32  # Copy to JWT_SECRET
openssl rand -hex 32  # Copy to JWT_REFRESH_SECRET

# 4. Build and deploy
docker-compose up -d

# 5. Verify deployment
curl https://yourdomain.com/health
```

Your production-ready Vrexis Insights is now deployed! 🎉