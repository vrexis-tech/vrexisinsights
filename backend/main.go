package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// Constants
const (
	defaultPort           = "8080"
	defaultDBPath         = "secure_services.db"
	jwtExpirationHours    = 1
	refreshExpirationDays = 7
	bcryptCost            = bcrypt.DefaultCost
	maxRequestSize        = 1024 * 1024 // 1MB
	pingTimeout           = 5 * time.Second
	httpTimeout           = 10 * time.Second
	monitorInterval       = 30 * time.Second
	concurrentChecks      = 10
)

// Global variables (minimize these in production)
var (
	jwtSecret         []byte
	jwtRefreshSecret  []byte
	jwtExpiration     = time.Duration(jwtExpirationHours) * time.Hour
	refreshExpiration = time.Duration(refreshExpirationDays) * 24 * time.Hour
)

// Server represents the main application server
type Server struct {
	config     *Config
	db         *sql.DB
	router     *mux.Router
	httpServer *http.Server
	stores     *Stores
	services   *Services
	monitor    *Monitor
	startTime  time.Time
}

// Config holds all application configuration
type Config struct {
	Port        string
	DBPath      string
	Security    SecurityConfig
	EnableHTTPS bool
	TLSCertFile string
	TLSKeyFile  string
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	MaxRequestSize     int64
	AllowedOrigins     []string
	RateLimit          RateLimitConfig
	Auth               AuthConfig
	DatabaseEncryption bool
	EncryptionKey      []byte
}

// RateLimitConfig defines rate limiting parameters
type RateLimitConfig struct {
	RPM                 int
	Burst               int
	AuthRPM             int
	AuthBurst           int
	WSConnections       int
	EnableLogging       bool
	SuspiciousThreshold int
}

// AuthConfig defines authentication parameters
type AuthConfig struct {
	MaxLoginAttempts   int
	LockoutDuration    time.Duration
	PasswordMinLength  int
	RequireComplexity  bool
	TokenRotationHours int
}

// Stores aggregates all data stores
type Stores struct {
	User    *UserStore
	Service *ServiceStore
	Auth    *AuthStore
}

// Services aggregates all services
type Services struct {
	RateLimiter *RateLimiter
	Monitor     *SecurityMonitor
	Clients     *ClientManager
}

// Initialize creates a new server instance
func Initialize() (*Server, error) {
	config := loadConfig()

	// Initialize JWT secrets
	if err := initJWT(); err != nil {
		return nil, fmt.Errorf("failed to initialize JWT: %w", err)
	}

	// Initialize security monitor
	monitor := NewSecurityMonitor()

	// Open database
	db, err := openDatabase(config.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Initialize stores
	userStore, err := NewUserStore(db, monitor)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize user store: %w", err)
	}

	serviceStore, err := NewServiceStore(db, monitor)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize service store: %w", err)
	}

	stores := &Stores{
		User:    userStore,
		Service: serviceStore,
		Auth:    userStore.authStore,
	}

	// Initialize services
	rateLimiter := NewRateLimiter(config.Security.RateLimit, monitor)
	clients := NewClientManager(monitor)

	services := &Services{
		RateLimiter: rateLimiter,
		Monitor:     monitor,
		Clients:     clients,
	}

	// Create server
	server := &Server{
		config:   config,
		db:       db,
		stores:   stores,
		services: services,
	}

	// Setup routes
	server.setupRoutes()

	// Configure HTTP server
	server.httpServer = &http.Server{
		Addr:              ":" + config.Port,
		Handler:           server.buildMiddlewareStack(),
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         configureTLS(),
	}

	// Initialize monitor
	server.monitor = &Monitor{
		store:       serviceStore,
		userStore:   userStore,
		clients:     clients,
		rateLimiter: rateLimiter,
		config:      &config.Security,
		monitor:     monitor,
	}

	return server, nil
}

// loadConfig loads configuration from environment variables
func loadConfig() *Config {
	config := &Config{
		Port:        getEnv("PORT", defaultPort),
		DBPath:      getEnv("DB_PATH", defaultDBPath),
		EnableHTTPS: getEnv("ENABLE_HTTPS", "false") == "true",
		TLSCertFile: getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:  getEnv("TLS_KEY_FILE", ""),
		Security: SecurityConfig{
			MaxRequestSize: maxRequestSize,
			AllowedOrigins: strings.Split(getEnv("ALLOWED_ORIGINS", "http://localhost:3000"), ","),
			RateLimit: RateLimitConfig{
				RPM:                 60,
				Burst:               10,
				AuthRPM:             10,
				AuthBurst:           3,
				WSConnections:       5,
				EnableLogging:       true,
				SuspiciousThreshold: 5,
			},
			Auth: AuthConfig{
				MaxLoginAttempts:   5,
				LockoutDuration:    30 * time.Minute,
				PasswordMinLength:  8,
				RequireComplexity:  true,
				TokenRotationHours: 1,
			},
			DatabaseEncryption: getEnv("ENABLE_DB_ENCRYPTION", "false") == "true",
		},
	}

	// Load encryption key if needed
	if config.Security.DatabaseEncryption {
		encKey := getEnv("DB_ENCRYPTION_KEY", "")
		if encKey == "" {
			key := make([]byte, 32)
			rand.Read(key)
			config.Security.EncryptionKey = key
			log.Println("🔑 Generated database encryption key (set DB_ENCRYPTION_KEY env var for production)")
		} else {
			if decoded, err := hex.DecodeString(encKey); err == nil {
				config.Security.EncryptionKey = decoded
			} else {
				log.Fatal("❌ Invalid DB_ENCRYPTION_KEY format")
			}
		}
	}

	return config
}

// Run starts the server
func (s *Server) Run(ctx context.Context) error {
	// Start background services
	go s.services.RateLimiter.StartCleanup(ctx)
	go s.monitor.startMonitoring(ctx)

	// Log security status
	s.logSecurityStatus()

	// Start server
	errChan := make(chan error, 1)
	go func() {
		if s.config.EnableHTTPS {
			log.Printf("🔒 Secure HTTPS server running on https://localhost:%s", s.config.Port)
			errChan <- s.httpServer.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
		} else {
			if getEnv("ENV", "") == "production" {
				log.Println("⚠️ WARNING: Running HTTP in production is not recommended")
			}
			log.Printf("🚀 HTTP server running on http://localhost:%s", s.config.Port)
			errChan <- s.httpServer.ListenAndServe()
		}
	}()

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		return s.Shutdown()
	case err := <-errChan:
		if err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	}
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	log.Println("🛑 Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("⚠️ Server shutdown error: %v", err)
	}

	if err := s.db.Close(); err != nil {
		log.Printf("⚠️ Database close error: %v", err)
	}

	log.Println("🔒 VrexisInsights Backend stopped securely")
	return nil
}

// setupRoutes configures all application routes
func (s *Server) setupRoutes() {
	s.router = mux.NewRouter()

	// Public endpoints
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")

	// Authentication routes
	auth := s.router.PathPrefix("/auth").Subrouter()
	auth.HandleFunc("/register", s.handleRegister).Methods("POST")
	auth.HandleFunc("/login", s.handleLogin).Methods("POST")
	auth.HandleFunc("/refresh", s.handleRefresh).Methods("POST")
	auth.HandleFunc("/logout", s.handleLogout).Methods("POST")

	// WebSocket endpoint
	s.router.HandleFunc("/ws", s.handleWebSocket)

	// API routes (protected)
	api := s.router.PathPrefix("/api/v1").Subrouter()
	api.Use(s.authMiddleware)

	api.HandleFunc("/services", s.handleGetServices).Methods("GET")
	api.HandleFunc("/services", s.handleCreateService).Methods("POST")
	api.HandleFunc("/services/{id}", s.handleUpdateService).Methods("PUT")
	api.HandleFunc("/services/{id}", s.handleDeleteService).Methods("DELETE")
	api.HandleFunc("/profile", s.handleGetProfile).Methods("GET")
	api.HandleFunc("/security/status", s.handleSecurityStatus).Methods("GET")
}

// buildMiddlewareStack creates the middleware chain
func (s *Server) buildMiddlewareStack() http.Handler {
	return s.securityMiddleware(
		s.rateLimitMiddleware(
			s.router))
}

// logSecurityStatus logs the current security configuration
func (s *Server) logSecurityStatus() {
	log.Printf("🛡️ Security Features Active:")
	log.Printf("   - Rate Limiting: %d req/min general, %d req/min auth",
		s.config.Security.RateLimit.RPM, s.config.Security.RateLimit.AuthRPM)
	log.Printf("   - JWT Authentication with %d hour expiration", jwtExpirationHours)
	log.Printf("   - Enhanced Security Headers")
	log.Printf("   - Input Validation & Sanitization")
	log.Printf("   - Database Encryption: %v", s.config.Security.DatabaseEncryption)
	log.Printf("   - Security Monitoring: Active")
	log.Printf("   - TLS Configuration: %v", s.config.EnableHTTPS)
}

// Utility functions

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func configureTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   false,
		Renegotiation:            tls.RenegotiateNever,
	}
}

func openDatabase(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(1 * time.Minute)

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		log.Printf("⚠️ Failed to enable WAL mode: %v", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		log.Printf("⚠️ Failed to enable foreign keys: %v", err)
	}

	return db, nil
}

// Main function
func main() {
	log.Println("🚀 Starting VrexisInsights Backend v2.0 with Enhanced Security")

	// Create context for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Initialize server
	server, err := Initialize()
	if err != nil {
		log.Fatalf("❌ Failed to initialize server: %v", err)
	}

	// Run server
	if err := server.Run(ctx); err != nil {
		log.Fatalf("❌ Server error: %v", err)
	}
}
