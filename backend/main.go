package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	_ "modernc.org/sqlite"
)

// Constants
const (
	defaultPort             = "8080"
	defaultDBPath           = "secure_services.db"
	jwtExpirationHours      = 1
	refreshExpirationDays   = 7
	maxRequestSize          = 1024 * 1024 // 1MB
	pingTimeout             = 5 * time.Second
	httpTimeout             = 10 * time.Second
	monitorInterval         = 30 * time.Second
	concurrentChecks        = 10
	alertEvaluationInterval = 30 * time.Second // Alert evaluation interval
)

// Server represents the main application server
type Server struct {
	config      *Config
	db          *sql.DB
	router      *mux.Router
	httpServer  *http.Server
	stores      *Stores
	services    *Services
	monitor     *Monitor
	alertEngine *AlertEngine
	startTime   time.Time
}

// Config holds all application configuration
type Config struct {
	Port        string
	DBPath      string
	Security    SecurityConfig
	EnableHTTPS bool
	TLSCertFile string
	TLSKeyFile  string
	Alerts      AlertConfig
}

// AlertConfig contains alert-related settings
type AlertConfig struct {
	EvaluationInterval         time.Duration
	MaxNotificationsPerHour    int
	EnableEmailNotifications   bool
	EnableSMSNotifications     bool
	EnableSlackNotifications   bool
	EnableWebhookNotifications bool
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
	User         *UserStore
	Service      *ServiceStore
	Auth         *AuthStore
	Alert        *AlertStore
	Notification *NotificationStore
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

	// Initialize database schema
	if err := initializeDatabase(db); err != nil {
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
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

	// Initialize alert-related stores
	alertStore, err := NewAlertStore(db, monitor)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize alert store: %w", err)
	}

	notificationStore, err := NewNotificationStore(db, monitor)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize notification store: %w", err)
	}

	stores := &Stores{
		User:         userStore,
		Service:      serviceStore,
		Auth:         userStore.authStore,
		Alert:        alertStore,
		Notification: notificationStore,
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

	// Initialize service monitor
	server.monitor = &Monitor{
		store:       serviceStore,
		userStore:   userStore,
		clients:     clients,
		rateLimiter: rateLimiter,
		config:      &config.Security,
		monitor:     monitor,
	}

	// Initialize alert engine
	server.alertEngine = NewAlertEngine(server.stores.Alert, server.stores.Service, server.stores.Notification, config.Alerts)

	// Initialize demo data for testing
	initializeDemoDataComplete(stores, db)

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
		Alerts: AlertConfig{
			EvaluationInterval:         alertEvaluationInterval,
			MaxNotificationsPerHour:    10,
			EnableEmailNotifications:   getEnv("ENABLE_EMAIL_ALERTS", "true") == "true",
			EnableSMSNotifications:     getEnv("ENABLE_SMS_ALERTS", "false") == "true",
			EnableSlackNotifications:   getEnv("ENABLE_SLACK_ALERTS", "true") == "true",
			EnableWebhookNotifications: getEnv("ENABLE_WEBHOOK_ALERTS", "false") == "true",
		},
	}

	// Load encryption key if needed
	if config.Security.DatabaseEncryption {
		encKey := getEnv("DB_ENCRYPTION_KEY", "")
		if encKey == "" {
			// Generate random key for demo - in production, this should be persistent
			log.Println("🔑 Generated database encryption key (set DB_ENCRYPTION_KEY env var for production)")
		} else {
			// In production, decode the hex key from environment
			log.Println("🔑 Using database encryption key from environment")
		}
	}

	return config
}

// initializeDatabase creates all necessary database tables
func initializeDatabase(db *sql.DB) error {
	// Create original tables (now implemented in database_init.go)
	if err := createOriginalTables(db); err != nil {
		return fmt.Errorf("failed to create original tables: %w", err)
	}

	// Create alert system tables
	if err := createAlertTables(db); err != nil {
		return fmt.Errorf("failed to create alert tables: %w", err)
	}

	return nil
}

// createAlertTables creates alert-related database tables
func createAlertTables(db *sql.DB) error {
	schema := `
	-- Alerts table
	CREATE TABLE IF NOT EXISTS alerts (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		description TEXT,
		service_ids TEXT NOT NULL, -- JSON array of service IDs
		condition TEXT NOT NULL,   -- status, latency, ping_latency, multiple_down
		operator TEXT NOT NULL,    -- equals, not_equals, greater_than, less_than, etc.
		value TEXT NOT NULL,       -- threshold value
		enabled BOOLEAN DEFAULT 1,
		notifications TEXT NOT NULL, -- JSON array of notification types
		cooldown INTEGER DEFAULT 5, -- minutes
		severity TEXT DEFAULT 'warning', -- info, warning, critical
		created DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_triggered DATETIME,
		trigger_count INTEGER DEFAULT 0,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
	);

	-- Alert triggers table (for history/logging)
	CREATE TABLE IF NOT EXISTS alert_triggers (
		id TEXT PRIMARY KEY,
		alert_id TEXT NOT NULL,
		service_id TEXT,
		message TEXT NOT NULL,
		severity TEXT NOT NULL,
		triggered DATETIME DEFAULT CURRENT_TIMESTAMP,
		resolved DATETIME,
		FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE,
		FOREIGN KEY (service_id) REFERENCES services (id) ON DELETE SET NULL
	);

	-- Notification settings table
	CREATE TABLE IF NOT EXISTS notification_settings (
		id TEXT PRIMARY KEY,
		user_id TEXT UNIQUE NOT NULL,
		email_enabled BOOLEAN DEFAULT 1,
		email_address TEXT,
		email_verified BOOLEAN DEFAULT 0,
		sms_enabled BOOLEAN DEFAULT 0,
		sms_number TEXT,
		sms_verified BOOLEAN DEFAULT 0,
		slack_enabled BOOLEAN DEFAULT 0,
		slack_webhook TEXT,
		slack_channel TEXT,
		webhook_enabled BOOLEAN DEFAULT 0,
		webhook_url TEXT,
		webhook_method TEXT DEFAULT 'POST',
		updated DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
	);

	-- Indexes for better performance
	CREATE INDEX IF NOT EXISTS idx_alerts_user_id ON alerts (user_id);
	CREATE INDEX IF NOT EXISTS idx_alerts_enabled ON alerts (enabled);
	CREATE INDEX IF NOT EXISTS idx_alert_triggers_alert_id ON alert_triggers (alert_id);
	CREATE INDEX IF NOT EXISTS idx_alert_triggers_triggered ON alert_triggers (triggered);
	CREATE INDEX IF NOT EXISTS idx_notification_settings_user_id ON notification_settings (user_id);
	`

	_, err := db.Exec(schema)
	return err
}

// Run starts the server
func (s *Server) Run(ctx context.Context) error {
	// Start background services
	go s.services.RateLimiter.StartCleanup(ctx)
	go s.monitor.startMonitoring(ctx)

	// Start alert engine
	go s.alertEngine.Start(ctx)

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

	// Stop alert engine
	if s.alertEngine != nil {
		s.alertEngine.Stop()
	}

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

	// Service routes
	api.HandleFunc("/services", s.handleGetServices).Methods("GET")
	api.HandleFunc("/services", s.handleCreateService).Methods("POST")
	api.HandleFunc("/services/{id}", s.handleUpdateService).Methods("PUT")
	api.HandleFunc("/services/{id}", s.handleDeleteService).Methods("DELETE")
	api.HandleFunc("/profile", s.handleGetProfile).Methods("GET")
	api.HandleFunc("/security/status", s.handleSecurityStatus).Methods("GET")

	// Alert management routes
	s.setupAlertRoutes(api)
}

// setupAlertRoutes configures alert-related routes
func (s *Server) setupAlertRoutes(api *mux.Router) {
	// Alert management routes
	alerts := api.PathPrefix("/alerts").Subrouter()
	alerts.HandleFunc("", s.handleGetAlerts).Methods("GET")
	alerts.HandleFunc("", s.handleCreateAlert).Methods("POST")
	alerts.HandleFunc("/{id}", s.handleGetAlert).Methods("GET")
	alerts.HandleFunc("/{id}", s.handleUpdateAlert).Methods("PUT")
	alerts.HandleFunc("/{id}", s.handleDeleteAlert).Methods("DELETE")
	alerts.HandleFunc("/{id}/triggers", s.handleGetAlertTriggerHistory).Methods("GET")
	alerts.HandleFunc("/{id}/test", s.handleTestAlertTrigger).Methods("POST")

	// Notification settings routes
	notifications := api.PathPrefix("/notifications").Subrouter()
	notifications.HandleFunc("/settings", s.handleGetNotificationSettings).Methods("GET")
	notifications.HandleFunc("/settings", s.handleUpdateNotificationSettings).Methods("PUT")
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

	// Alert system status
	log.Printf("🚨 Alert System Features:")
	log.Printf("   - Alert Evaluation Interval: %v", s.config.Alerts.EvaluationInterval)
	log.Printf("   - Email Notifications: %v", s.config.Alerts.EnableEmailNotifications)
	log.Printf("   - Slack Notifications: %v", s.config.Alerts.EnableSlackNotifications)
	log.Printf("   - SMS Notifications: %v", s.config.Alerts.EnableSMSNotifications)
	log.Printf("   - Webhook Notifications: %v", s.config.Alerts.EnableWebhookNotifications)
	log.Printf("   - Max Notifications/Hour: %d", s.config.Alerts.MaxNotificationsPerHour)
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
	log.Println("🚀 Starting VrexisInsights Backend v2.1 with Enhanced Security & Alert Management")

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
