package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// =============================================================================
// CONFIGURATION
// =============================================================================

type Config struct {
	Port             string
	DBPath           string
	JWTSecret        string
	JWTRefreshSecret string
	Environment      string
	AllowedOrigins   []string
	LogLevel         string
	RateLimitWindow  time.Duration
	RateLimitMax     int
}

func loadConfig() *Config {
	// Default to development settings, override with environment variables
	config := &Config{
		Port:             getEnv("PORT", "8080"),
		DBPath:           getEnv("DB_PATH", "vrexis_insights.db"),
		JWTSecret:        getEnv("JWT_SECRET", ""),
		JWTRefreshSecret: getEnv("JWT_REFRESH_SECRET", ""),
		Environment:      getEnv("ENVIRONMENT", "development"),
		LogLevel:         getEnv("LOG_LEVEL", "info"),
		RateLimitWindow:  time.Minute * 15,
		RateLimitMax:     5, // 5 attempts per 15 minutes
	}

	// Parse allowed origins
	originsStr := getEnv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
	config.AllowedOrigins = strings.Split(originsStr, ",")

	// Validate critical environment variables
	if config.JWTSecret == "" {
		if config.Environment == "production" {
			log.Fatal("❌ JWT_SECRET environment variable is required in production")
		}
		config.JWTSecret = "dev-jwt-secret-change-in-production"
		log.Println("⚠️  Using default JWT secret (development only)")
	}

	if config.JWTRefreshSecret == "" {
		if config.Environment == "production" {
			log.Fatal("❌ JWT_REFRESH_SECRET environment variable is required in production")
		}
		config.JWTRefreshSecret = "dev-refresh-secret-change-in-production"
		log.Println("⚠️  Using default refresh secret (development only)")
	}

	// Security warnings for production
	if config.Environment == "production" {
		if len(config.JWTSecret) < 32 {
			log.Fatal("❌ JWT_SECRET must be at least 32 characters in production")
		}
		if strings.Contains(originsStr, "localhost") {
			log.Println("⚠️  Warning: localhost origins detected in production")
		}
	}

	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// =============================================================================
// MODELS
// =============================================================================

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"password,omitempty"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	CreatedAt time.Time `json:"created_at"`
}

type Service struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	Latency     int       `json:"latency"`
	PingLatency int       `json:"ping_latency"`
	LastChecked time.Time `json:"last_checked"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type AuthResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	User         User   `json:"user"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

type HealthResponse struct {
	Status      string            `json:"status"`
	Version     string            `json:"version"`
	Environment string            `json:"environment"`
	Timestamp   time.Time         `json:"timestamp"`
	Checks      map[string]string `json:"checks"`
}

// =============================================================================
// RATE LIMITING
// =============================================================================

type RateLimiter struct {
	requests map[string][]time.Time
	mutex    sync.RWMutex
	window   time.Duration
	maxReqs  int
}

func NewRateLimiter(window time.Duration, maxReqs int) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		window:   window,
		maxReqs:  maxReqs,
	}

	// Cleanup old entries every minute
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Get existing requests for this key
	requests := rl.requests[key]

	// Filter out old requests
	validRequests := make([]time.Time, 0)
	for _, reqTime := range requests {
		if reqTime.After(cutoff) {
			validRequests = append(validRequests, reqTime)
		}
	}

	// Check if we're under the limit
	if len(validRequests) >= rl.maxReqs {
		rl.requests[key] = validRequests
		return false
	}

	// Add current request
	validRequests = append(validRequests, now)
	rl.requests[key] = validRequests
	return true
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mutex.Lock()
		cutoff := time.Now().Add(-rl.window)

		for key, requests := range rl.requests {
			validRequests := make([]time.Time, 0)
			for _, reqTime := range requests {
				if reqTime.After(cutoff) {
					validRequests = append(validRequests, reqTime)
				}
			}

			if len(validRequests) == 0 {
				delete(rl.requests, key)
			} else {
				rl.requests[key] = validRequests
			}
		}
		rl.mutex.Unlock()
	}
}

// =============================================================================
// MIDDLEWARE
// =============================================================================

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:")

		// HSTS header for HTTPS (only in production)
		if r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

func httpsRedirectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Force HTTPS in production
		if os.Getenv("ENVIRONMENT") == "production" {
			if r.Header.Get("X-Forwarded-Proto") != "https" && r.TLS == nil {
				target := "https://" + r.Host + r.URL.Path
				if r.URL.RawQuery != "" {
					target += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, target, http.StatusPermanentRedirect)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func rateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use IP address as the key
			key := getClientIP(r)

			if !limiter.Allow(key) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "900") // 15 minutes
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(ErrorResponse{
					Error:   "Rate limit exceeded. Too many requests.",
					Code:    "RATE_LIMIT_EXCEEDED",
					Details: "Please wait 15 minutes before trying again",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func validationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic request validation
		if r.ContentLength > 1024*1024 { // 1MB limit
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Request body too large",
				Code:  "REQUEST_TOO_LARGE",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a custom ResponseWriter to capture the status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		// Structured logging
		duration := time.Since(start)
		logEntry := map[string]interface{}{
			"timestamp":   start.Format(time.RFC3339),
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      wrapped.statusCode,
			"duration_ms": duration.Milliseconds(),
			"user_agent":  r.UserAgent(),
			"ip":          getClientIP(r),
		}

		// Log as JSON
		logJSON, _ := json.Marshal(logEntry)
		log.Printf("HTTP %s", string(logJSON))
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func getClientIP(r *http.Request) string {
	// Check various headers for the real IP
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

func jwtMiddleware(config *Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString := r.Header.Get("Authorization")
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")

			if tokenString == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(ErrorResponse{
					Error: "Missing authorization token",
					Code:  "MISSING_TOKEN",
				})
				return
			}

			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(config.JWTSecret), nil
			})

			if err != nil || !token.Valid {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(ErrorResponse{
					Error: "Invalid or expired token",
					Code:  "INVALID_TOKEN",
				})
				return
			}

			// Add user ID to context
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				if userID, ok := claims["sub"].(string); ok {
					ctx := context.WithValue(r.Context(), "userID", userID)
					r = r.WithContext(ctx)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// VALIDATION
// =============================================================================

var (
	emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)
)

func validateEmail(email string) bool {
	return emailRegex.MatchString(strings.ToLower(email))
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	hasUpper := false
	hasLower := false
	hasDigit := false

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one number")
	}

	return nil
}

func sanitizeString(input string, maxLength int) string {
	// Basic HTML/script tag removal
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")
	input = strings.ReplaceAll(input, "\"", "&quot;")
	input = strings.ReplaceAll(input, "'", "&#x27;")
	input = strings.ReplaceAll(input, "&", "&amp;")

	// Trim and limit length
	input = strings.TrimSpace(input)
	if len(input) > maxLength {
		input = input[:maxLength]
	}

	return input
}

// =============================================================================
// DATABASE
// =============================================================================

var globalDB *sql.DB

func initDatabase(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	// Enable WAL mode for better concurrency
	_, err = db.Exec("PRAGMA journal_mode=WAL")
	if err != nil {
		log.Printf("Warning: Could not enable WAL mode: %v", err)
	}

	// Create tables
	err = createTables(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return db, nil
}

func createTables(db *sql.DB) error {
	userTable := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		first_name TEXT NOT NULL,
		last_name TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	serviceTable := `
	CREATE TABLE IF NOT EXISTS services (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		url TEXT NOT NULL,
		type TEXT NOT NULL,
		status TEXT DEFAULT 'unknown',
		latency INTEGER DEFAULT 0,
		ping_latency INTEGER DEFAULT 0,
		last_checked DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
	);`

	// Create indexes for performance
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
		"CREATE INDEX IF NOT EXISTS idx_services_user_id ON services(user_id);",
		"CREATE INDEX IF NOT EXISTS idx_services_status ON services(status);",
	}

	if _, err := db.Exec(userTable); err != nil {
		return err
	}

	if _, err := db.Exec(serviceTable); err != nil {
		return err
	}

	for _, indexSQL := range indexes {
		if _, err := db.Exec(indexSQL); err != nil {
			log.Printf("Warning: Could not create index: %v", err)
		}
	}

	return nil
}

// =============================================================================
// HANDLERS
// =============================================================================

func healthHandler(w http.ResponseWriter, r *http.Request) {
	checks := make(map[string]string)

	// Check database connection
	if err := globalDB.Ping(); err != nil {
		checks["database"] = "unhealthy: " + err.Error()
	} else {
		checks["database"] = "healthy"
	}

	// Check disk space (basic check)
	if stat, err := os.Stat("."); err != nil {
		checks["filesystem"] = "unhealthy: " + err.Error()
	} else {
		checks["filesystem"] = "healthy"
		_ = stat // Use stat if needed for more detailed checks
	}

	status := "healthy"
	for _, check := range checks {
		if strings.Contains(check, "unhealthy") {
			status = "unhealthy"
			break
		}
	}

	response := HealthResponse{
		Status:      status,
		Version:     "1.0.0", // Replace with actual version
		Environment: os.Getenv("ENVIRONMENT"),
		Timestamp:   time.Now(),
		Checks:      checks,
	}

	w.Header().Set("Content-Type", "application/json")
	if status == "unhealthy" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(response)
}

func loginHandler(config *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Invalid request format",
				Code:  "INVALID_JSON",
			})
			return
		}

		// Validate and sanitize input
		req.Email = sanitizeString(strings.ToLower(req.Email), 255)
		req.Password = sanitizeString(req.Password, 255)

		if !validateEmail(req.Email) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Invalid email format",
				Code:  "INVALID_EMAIL",
			})
			return
		}

		// Get user from database
		user, err := getUserByEmail(r.Context(), req.Email)
		if err != nil {
			// Log the attempt for security monitoring
			log.Printf("Failed login attempt for email: %s from IP: %s", req.Email, getClientIP(r))

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Invalid email or password",
				Code:  "INVALID_CREDENTIALS",
			})
			return
		}

		// Verify password
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			log.Printf("Failed login attempt for email: %s from IP: %s", req.Email, getClientIP(r))

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Invalid email or password",
				Code:  "INVALID_CREDENTIALS",
			})
			return
		}

		// Generate tokens
		token, err := generateJWT(user, config.JWTSecret, time.Hour*24)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Failed to generate authentication token",
				Code:  "TOKEN_GENERATION_FAILED",
			})
			return
		}

		refreshToken, err := generateJWT(user, config.JWTRefreshSecret, time.Hour*24*7) // 7 days
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Failed to generate refresh token",
				Code:  "REFRESH_TOKEN_GENERATION_FAILED",
			})
			return
		}

		// Set secure cookie for refresh token
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    refreshToken,
			Path:     "/",
			MaxAge:   int((time.Hour * 24 * 7).Seconds()), // 7 days
			HttpOnly: true,
			Secure:   config.Environment == "production",
			SameSite: http.SameSiteStrictMode,
		})

		// Remove password from response
		user.Password = ""

		// Log successful login
		log.Printf("Successful login for user: %s from IP: %s", user.Email, getClientIP(r))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AuthResponse{
			Token:        token,
			RefreshToken: refreshToken,
			User:         *user,
		})
	}
}

func registerHandler(config *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Invalid request format",
				Code:  "INVALID_JSON",
			})
			return
		}

		// Validate and sanitize input
		req.Email = sanitizeString(strings.ToLower(req.Email), 255)
		req.FirstName = sanitizeString(req.FirstName, 50)
		req.LastName = sanitizeString(req.LastName, 50)
		req.Password = sanitizeString(req.Password, 255)

		// Validate email
		if !validateEmail(req.Email) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Invalid email format",
				Code:  "INVALID_EMAIL",
			})
			return
		}

		// Validate password
		if err := validatePassword(req.Password); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: err.Error(),
				Code:  "WEAK_PASSWORD",
			})
			return
		}

		// Validate names
		if len(req.FirstName) < 1 || len(req.LastName) < 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "First name and last name are required",
				Code:  "MISSING_REQUIRED_FIELDS",
			})
			return
		}

		// Check if user already exists
		_, err := getUserByEmail(r.Context(), req.Email)
		if err == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "An account with this email already exists",
				Code:  "USER_ALREADY_EXISTS",
			})
			return
		}

		// Hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Failed to secure password",
				Code:  "PASSWORD_HASH_FAILED",
			})
			return
		}

		// Create user
		user := &User{
			ID:        uuid.New().String(),
			Email:     req.Email,
			Password:  string(hashedPassword),
			FirstName: req.FirstName,
			LastName:  req.LastName,
			CreatedAt: time.Now(),
		}

		if err := createUser(r.Context(), user); err != nil {
			log.Printf("Failed to create user: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Failed to create account",
				Code:  "USER_CREATION_FAILED",
			})
			return
		}

		// Generate tokens
		token, err := generateJWT(user, config.JWTSecret, time.Hour*24)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Failed to generate authentication token",
				Code:  "TOKEN_GENERATION_FAILED",
			})
			return
		}

		refreshToken, err := generateJWT(user, config.JWTRefreshSecret, time.Hour*24*7)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Failed to generate refresh token",
				Code:  "REFRESH_TOKEN_GENERATION_FAILED",
			})
			return
		}

		// Set secure cookie for refresh token
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    refreshToken,
			Path:     "/",
			MaxAge:   int((time.Hour * 24 * 7).Seconds()),
			HttpOnly: true,
			Secure:   config.Environment == "production",
			SameSite: http.SameSiteStrictMode,
		})

		// Remove password from response
		user.Password = ""

		// Log successful registration
		log.Printf("New user registered: %s from IP: %s", user.Email, getClientIP(r))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(AuthResponse{
			Token:        token,
			RefreshToken: refreshToken,
			User:         *user,
		})
	}
}

// =============================================================================
// DATABASE FUNCTIONS
// =============================================================================

func getUserByEmail(ctx context.Context, email string) (*User, error) {
	query := `SELECT id, email, password, first_name, last_name, created_at FROM users WHERE email = ?`
	var user User
	err := globalDB.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to query user: %w", err)
	}
	return &user, nil
}

func createUser(ctx context.Context, user *User) error {
	query := `INSERT INTO users (id, email, password, first_name, last_name, created_at) VALUES (?, ?, ?, ?, ?, ?)`
	_, err := globalDB.ExecContext(ctx, query, user.ID, user.Email, user.Password, user.FirstName, user.LastName, user.CreatedAt)
	return err
}

func generateJWT(user *User, secret string, duration time.Duration) (string, error) {
	claims := &jwt.RegisteredClaims{
		Subject:   user.ID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "vrexis-insights",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// =============================================================================
// SETUP AND MAIN
// =============================================================================

func setupRoutes(config *Config) http.Handler {
	r := mux.NewRouter()

	// Create rate limiter for auth endpoints
	authLimiter := NewRateLimiter(config.RateLimitWindow, config.RateLimitMax)

	// Apply global middleware
	r.Use(securityHeadersMiddleware)
	r.Use(httpsRedirectMiddleware)
	r.Use(loggingMiddleware)
	r.Use(validationMiddleware)

	// Health check endpoint (no rate limiting)
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/api/health", healthHandler).Methods("GET") // Alternative path

	// Auth routes with rate limiting
	authRouter := r.PathPrefix("/auth").Subrouter()
	authRouter.Use(rateLimitMiddleware(authLimiter))
	authRouter.HandleFunc("/login", loginHandler(config)).Methods("POST")
	authRouter.HandleFunc("/register", registerHandler(config)).Methods("POST")

	// Protected API routes
	apiRouter := r.PathPrefix("/api/v1").Subrouter()
	apiRouter.Use(jwtMiddleware(config))
	apiRouter.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value("userID").(string)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Protected route accessed successfully",
			"user_id": userID,
		})
	}).Methods("GET")

	// CORS configuration
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   config.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           300, // 5 minutes
	}).Handler(r)

	return corsHandler
}

func createDemoUser(config *Config) {
	// Only create demo user in development
	if config.Environment == "production" {
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error creating demo user: %v", err)
		return
	}

	user := &User{
		ID:        uuid.New().String(),
		Email:     "admin@vrexisinsights.com",
		Password:  string(hashedPassword),
		FirstName: "Admin",
		LastName:  "User",
		CreatedAt: time.Now(),
	}

	// Check if user already exists
	_, err = getUserByEmail(context.Background(), user.Email)
	if err == nil {
		return // User already exists
	}

	err = createUser(context.Background(), user)
	if err != nil {
		log.Printf("Error creating demo user: %v", err)
	} else {
		log.Printf("✅ Demo user created: %s / admin123", user.Email)
	}
}

func main() {
	// Load configuration
	config := loadConfig()

	// Initialize database
	db, err := initDatabase(config.DBPath)
	if err != nil {
		log.Fatalf("❌ Database initialization failed: %v", err)
	}
	globalDB = db
	defer db.Close()

	// Create demo user for development
	createDemoUser(config)

	// Setup routes
	handler := setupRoutes(config)

	// Create server with timeouts
	srv := &http.Server{
		Addr:         ":" + config.Port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("🚀 Vrexis Insights server starting...")
		log.Printf("📍 Environment: %s", config.Environment)
		log.Printf("🌐 Port: %s", config.Port)
		log.Printf("🔒 Security headers enabled")
		log.Printf("⚡ Rate limiting: %d requests per %v", config.RateLimitMax, config.RateLimitWindow)

		if config.Environment == "development" {
			log.Printf("👤 Demo login: admin@vrexisinsights.com / admin123")
		}

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ Server startup failed: %v", err)
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop

	log.Println("🛑 Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("❌ Server shutdown error: %v", err)
	} else {
		log.Println("✅ Server stopped gracefully")
	}
}
