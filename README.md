# 🚀 Vrexis Insights

**Enterprise-grade service monitoring platform with real-time dashboards and secure monitoring capabilities**

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![React](https://img.shields.io/badge/React-18+-blue.svg)](https://reactjs.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-green.svg)](#security)

Vrexis Insights is a modern, secure service monitoring solution that tracks the health and performance of your web services, APIs, servers, and network equipment. Built with Go and React, it provides real-time monitoring with enterprise-grade security features.

## ✨ Features

### 🔍 **Comprehensive Monitoring**
- **Multi-Protocol Support**: HTTP/HTTPS URLs, raw IP addresses, and hostnames
- **Dual Monitoring**: HTTP response monitoring + ICMP ping checks
- **Real-time Updates**: WebSocket-based live dashboard updates
- **Network Equipment**: Monitor routers, switches, printers, and IoT devices
- **Custom Intervals**: Configurable check frequencies (default: 30s)

### 📊 **Rich Dashboards**
- **Live Metrics**: Real-time latency charts and status indicators
- **Service Overview**: Comprehensive stats with uptime percentages
- **Security Status**: HTTPS vs HTTP monitoring with security badges
- **Dark/Light Mode**: Modern UI with theme switching
- **Responsive Design**: Works on desktop, tablet, and mobile

### 🔒 **Enterprise Security**
- **Input Validation**: XSS and injection protection
- **Secure Headers**: HSTS, CSP, X-Frame-Options, and more
- **CORS Protection**: Origin validation and secure cross-origin requests
- **URL Sanitization**: Dangerous host and protocol blocking
- **Encrypted Connections**: Optional HTTPS/WSS support
- **Request Limiting**: Protection against DoS attacks

### 🛠 **Developer-Friendly**
- **RESTful API**: Full CRUD operations for services
- **WebSocket API**: Real-time monitoring data streams
- **Database Migrations**: Automatic schema upgrades
- **Cross-Platform**: Runs on Windows, macOS, and Linux
- **Easy Deployment**: Single binary with embedded frontend

## 🏗 Architecture

```
┌─────────────────┐    WebSocket    ┌──────────────────┐
│   React Client  │◄──────────────►│   Go Backend     │
│                 │                 │                  │
│ • Dashboard     │    REST API     │ • Service Store  │
│ • Real-time UI  │◄──────────────►│ • Monitoring     │
│ • Charts        │                 │ • WebSocket Hub  │
└─────────────────┘                 └──────────────────┘
                                              │
                                              ▼
                                    ┌──────────────────┐
                                    │   SQLite DB      │
                                    │                  │
                                    │ • Services       │
                                    │ • Metrics        │
                                    │ • History        │
                                    └──────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- **Go 1.21+** - [Download](https://golang.org/dl/)
- **Node.js 18+** (for frontend development) - [Download](https://nodejs.org/)
- **Git** - [Download](https://git-scm.com/)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/vrexis-insights.git
   cd vrexis-insights
   ```

2. **Backend Setup**
   ```bash
   cd backend
   go mod download
   go run main.go
   ```

3. **Frontend Setup** (development)
   ```bash
   cd frontend
   npm install
   npm start
   ```

4. **Access the application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8080
   - WebSocket: ws://localhost:8080/ws

### Production Deployment

```bash
# Build backend
cd backend
go build -o vrexis-monitor main.go

# Start with custom configuration
PORT=8080 DB_PATH=/data/monitor.db ./vrexis-monitor
```

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |
| `DB_PATH` | `services.db` | SQLite database file path |
| `ENABLE_HTTPS` | `false` | Enable HTTPS (requires certs) |
| `ENV` | `development` | Environment mode |
| `REQUIRE_AUTH` | `false` | Enable authentication (future) |

### HTTPS Configuration

```bash
# Generate self-signed certificates (development)
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes

# Start with HTTPS
ENABLE_HTTPS=true go run main.go
```

## 📡 API Documentation

### REST Endpoints

#### Services API

**GET /services** - List all services
```bash
curl http://localhost:8080/services
```

**POST /services** - Add new service
```bash
curl -X POST http://localhost:8080/services \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My API",
    "url": "https://api.example.com",
    "type": "website",
    "enabled": true
  }'
```

**PUT /services/{id}** - Update service
```bash
curl -X PUT http://localhost:8080/services/{id} \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated API",
    "url": "https://api.example.com",
    "type": "website",
    "enabled": true
  }'
```

**DELETE /services/{id}** - Delete service
```bash
curl -X DELETE http://localhost:8080/services/{id}
```

#### Secure API (v1)

All endpoints are also available under `/api/v1/` with enhanced security:
- `/api/v1/services`
- `/api/v1/services/{id}`

### WebSocket API

Connect to `ws://localhost:8080/ws` for real-time updates.

**Message Format:**
```json
{
  "id": "service-uuid",
  "name": "Service Name",
  "url": "https://example.com",
  "type": "website",
  "status": "up",
  "latency": 245,
  "ping_latency": 12,
  "last_checked": "2025-05-29T14:30:00Z"
}
```

## 🔒 Security

### Current Security Features

- ✅ **Input Validation**: XSS and injection protection
- ✅ **CORS Protection**: Secure cross-origin requests
- ✅ **Security Headers**: HSTS, CSP, X-Frame-Options
- ✅ **URL Sanitization**: Dangerous host blocking
- ✅ **SQL Injection Protection**: Parameterized queries
- ✅ **Request Size Limiting**: 1MB maximum
- ✅ **Protocol Restrictions**: HTTP/HTTPS only for URLs
- ✅ **UUID Validation**: Secure ID handling

### Security Best Practices

1. **Use HTTPS in production**
   ```bash
   ENABLE_HTTPS=true ./vrexis-monitor
   ```

2. **Set secure database permissions**
   ```bash
   chmod 600 /data/services.db
   ```

3. **Configure firewall rules**
   ```bash
   # Allow only necessary ports
   ufw allow 8080/tcp
   ufw allow 22/tcp
   ufw enable
   ```

4. **Regular security updates**
   ```bash
   go mod update
   go mod verify
   ```

### Planned Security Enhancements

- 🔄 **Authentication & Authorization** (JWT-based)
- 🔄 **API Rate Limiting** (per-IP throttling)
- 🔄 **Audit Logging** (security event tracking)
- 🔄 **Data Encryption at Rest** (database encryption)
- 🔄 **Secrets Management** (environment-based config)

## 📊 Monitoring Capabilities

### Supported Service Types

| Type | URL Format | Monitoring Method |
|------|------------|-------------------|
| **Websites/APIs** | `https://api.example.com` | HTTP + Ping |
| **HTTP Services** | `http://192.168.1.100:3000` | HTTP + Ping |
| **IP Addresses** | `192.168.1.1` | Ping Only |
| **Hostnames** | `router.local` | Ping Only |
| **Custom Ports** | `192.168.1.1:22` | Ping Only |

### Metrics Collected

- **HTTP Response Time**: API/website response latency
- **Ping Latency**: ICMP round-trip time
- **Service Status**: Up/Down based on response
- **Last Check Time**: Timestamp of last monitoring attempt
- **Uptime Percentage**: Historical availability metrics

### Dashboard Features

- **Real-time Charts**: Live latency visualization
- **Status Overview**: Quick health summary
- **Security Indicators**: HTTPS vs HTTP services
- **Service Cards**: Detailed per-service metrics
- **Dark/Light Themes**: Modern UI experience

## 🔧 Development

### Project Structure

```
vrexis-insights/
├── backend/
│   ├── main.go                 # Main application server
│   ├── go.mod                  # Go dependencies
│   ├── go.sum                  # Dependency checksums
│   └── services.db             # SQLite database (auto-created)
├── frontend/
│   ├── src/
│   │   ├── components/         # React components
│   │   ├── hooks/              # Custom React hooks
│   │   └── utils/              # Utility functions
│   ├── package.json            # Node.js dependencies
│   └── public/                 # Static assets
├── docs/                       # Documentation
├── docker/                     # Container configs
└── README.md                   # This file
```

### Database Schema

```sql
CREATE TABLE services (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    type TEXT DEFAULT 'website',
    enabled INTEGER DEFAULT 1,
    status TEXT DEFAULT 'unknown',
    latency INTEGER DEFAULT 0,
    ping_latency INTEGER DEFAULT 0,
    last_checked DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Running Tests

```bash
# Backend tests
cd backend
go test ./...

# Frontend tests
cd frontend
npm test
```

### Building for Production

```bash
# Build backend binary
cd backend
go build -ldflags="-w -s" -o vrexis-monitor main.go

# Build frontend (for embedding)
cd frontend
npm run build
```

## 🐳 Docker Deployment

### Dockerfile Example

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY backend/ .
RUN go mod download
RUN go build -o vrexis-monitor main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/vrexis-monitor .
EXPOSE 8080
CMD ["./vrexis-monitor"]
```

### Docker Compose

```yaml
version: '3.8'
services:
  vrexis-monitor:
    build: .
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - DB_PATH=/data/services.db
    volumes:
      - ./data:/data
    restart: unless-stopped
```

## 🚢 Deployment Options

### 1. Traditional Server

```bash
# Upload binary to server
scp vrexis-monitor user@server:/opt/vrexis/

# Create systemd service
sudo nano /etc/systemd/system/vrexis-monitor.service

# Start service
sudo systemctl enable vrexis-monitor
sudo systemctl start vrexis-monitor
```

### 2. Cloud Platforms

- **AWS**: ECS, Lambda, or EC2
- **Google Cloud**: Cloud Run or Compute Engine
- **Azure**: Container Instances or App Service
- **DigitalOcean**: App Platform or Droplets

### 3. Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vrexis-monitor
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vrexis-monitor
  template:
    metadata:
      labels:
        app: vrexis-monitor
    spec:
      containers:
      - name: vrexis-monitor
        image: vrexis/monitor:latest
        ports:
        - containerPort: 8080
        env:
        - name: DB_PATH
          value: "/data/services.db"
```

## 🎯 Roadmap

### Version 1.1 (Q3 2025)
- [ ] User authentication & authorization
- [ ] API rate limiting
- [ ] Email/SMS alerting
- [ ] Custom check intervals
- [ ] Audit logging

### Version 1.2 (Q4 2025)
- [ ] Multi-tenancy support
- [ ] Webhook integrations
- [ ] SSL certificate monitoring
- [ ] Status page generation
- [ ] Prometheus metrics export

### Version 2.0 (Q1 2026)
- [ ] Advanced alerting rules
- [ ] Incident management
- [ ] SLA tracking
- [ ] Geographic monitoring
- [ ] AI-powered anomaly detection

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Add tests** for your changes
5. **Commit your changes**
   ```bash
   git commit -m "Add amazing feature"
   ```
6. **Push to your fork**
   ```bash
   git push origin feature/amazing-feature
   ```
7. **Open a Pull Request**

### Development Guidelines

- Follow Go best practices and conventions
- Write comprehensive tests for new features
- Update documentation for API changes
- Ensure security best practices are followed
- Use conventional commit messages

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

- **Documentation**: [GitHub Wiki](https://github.com/yourusername/vrexis-insights/wiki)
- **Issues**: [GitHub Issues](https://github.com/yourusername/vrexis-insights/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/vrexis-insights/discussions)

## 🙏 Acknowledgments

- **Gorilla WebSocket** - Real-time communication
- **Gorilla Mux** - HTTP routing
- **React** - Frontend framework
- **Recharts** - Data visualization
- **Bootstrap** - UI components
- **SQLite** - Embedded database

---

**Built with ❤️ by the Vrexis Team**

*Monitoring made simple, secure, and scalable.*