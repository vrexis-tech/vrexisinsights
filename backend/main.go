package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
)

// Rate Limiting Structures
type RateLimiter struct {
	mu      sync.RWMutex
	clients map[string]*ClientBucket
	config  RateLimitConfig
}

type ClientBucket struct {
	tokens     float64
	lastRefill time.Time
	requests   []time.Time // For monitoring/logging
}

type RateLimitConfig struct {
	// General API limits
	RPM        int // Requests per minute
	Burst      int // Burst capacity
	
	// Special limits for different endpoints
	AuthRPM    int // Login/Register requests per minute
	AuthBurst  int // Auth burst capacity
	
	// WebSocket limits
	WSConnections int // Max concurrent WebSocket connections per IP
	
	// Monitoring
	EnableLogging bool
	LogViolations bool
}

type RateLimitViolation struct {
	IP        string    `json:"ip"`
	Endpoint  string    `json:"endpoint"`
	Timestamp time.Time `json:"timestamp"`
	RequestsPerMinute int `json:"requests_per_minute"`
}

// JWT configuration
var (
	jwtSecret     []byte
	jwtExpiration = 24 * time.Hour
)

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"-"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Role      string    `json:"role"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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
	Token     string `json:"token"`
	User      User   `json:"user"`
	ExpiresAt int64  `json:"expires_at"`
}

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

type Service struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Type        string    `json:"type"`
	Enabled     bool      `json:"enabled"`
	Status      string    `json:"status"`
	Latency     int64     `json:"latency"`
	PingLatency int64     `json:"ping_latency"`
	LastChecked time.Time `json:"last_checked"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	UserID      string    `json:"user_id"`
}

type SecurityConfig struct {
	EnableHTTPS      bool
	MaxRequestSize   int64
	RateLimitEnabled bool
	AllowedOrigins   []string
	RequireAuth      bool
	RateLimit        RateLimitConfig
}

type Monitor struct {
	store         *ServiceStore
	userStore     *UserStore
	clients       *ClientManager
	rateLimiter   *RateLimiter
	config        *SecurityConfig
	shutdownChan  chan struct{}
	isRunning     bool
	mu            sync.RWMutex
}

// Rate Limiter Implementation
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		clients: make(map[string]*ClientBucket),
		config:  config,
	}
}

func (rl *RateLimiter) Allow(clientIP string, isAuthEndpoint bool) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	
	// Get or create client bucket
	bucket, exists := rl.clients[clientIP]
	if !exists {
		bucket = &ClientBucket{
			tokens:     float64(rl.config.Burst),
			lastRefill: now,
			requests:   make([]time.Time, 0),
		}
		rl.clients[clientIP] = bucket
	}

	// Choose rate limits based on endpoint type
	rpm := rl.config.RPM
	burst := rl.config.Burst
	if isAuthEndpoint {
		rpm = rl.config.AuthRPM
		burst = rl.config.AuthBurst
	}

	// Refill tokens based on time elapsed
	elapsed := now.Sub(bucket.lastRefill)
	tokensToAdd := elapsed.Seconds() * float64(rpm) / 60.0
	bucket.tokens = min(float64(burst), bucket.tokens + tokensToAdd)
	bucket.lastRefill = now

	// Check if request is allowed
	if bucket.tokens >= 1.0 {
		bucket.tokens -= 1.0
		bucket.requests = append(bucket.requests, now)
		
		// Clean old requests (keep last hour for monitoring)
		oneHourAgo := now.Add(-time.Hour)
		bucket.requests = filterRequests(bucket.requests, oneHourAgo)
		
		return true
	}

	// Log violation if enabled
	if rl.config.LogViolations {
		rl.logViolation(clientIP, bucket, rpm)
	}

	return false
}

func (rl *RateLimiter) GetStats(clientIP string) (requestsPerMinute int, requestsPerHour int) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	bucket, exists := rl.clients[clientIP]
	if !exists {
		return 0, 0
	}

	now := time.Now()
	oneMinuteAgo := now.Add(-time.Minute)
	oneHourAgo := now.Add(-time.Hour)

	requestsPerMinute = countRequests(bucket.requests, oneMinuteAgo)
	requestsPerHour = countRequests(bucket.requests, oneHourAgo)

	return requestsPerMinute, requestsPerHour
}

func (rl *RateLimiter) logViolation(clientIP string, bucket *ClientBucket, rpm int) {
	now := time.Now()
	oneMinuteAgo := now.Add(-time.Minute)
	currentRPM := countRequests(bucket.requests, oneMinuteAgo)
	
	violation := RateLimitViolation{
		IP:                clientIP,
		Timestamp:         now,
		RequestsPerMinute: currentRPM,
	}
	
	log.Printf("🚨 Rate limit violation: IP %s, %d requests/min (limit: %d)", 
		clientIP, currentRPM, rpm)
	
	// In production, you might want to store these in database or send alerts
	_ = violation
}

func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	oneHourAgo := now.Add(-time.Hour)

	// Remove clients with no recent activity
	for ip, bucket := range rl.clients {
		if len(bucket.requests) == 0 || bucket.requests[len(bucket.requests)-1].Before(oneHourAgo) {
			delete(rl.clients, ip)
		}
	}
}

// Start cleanup routine
func (rl *RateLimiter) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.Cleanup()
		}
	}
}

// Helper functions
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func filterRequests(requests []time.Time, cutoff time.Time) []time.Time {
	for i, req := range requests {
		if req.After(cutoff) {
			return requests[i:]
		}
	}
	return []time.Time{}
}

func countRequests(requests []time.Time, since time.Time) int {
	count := 0
	for _, req := range requests {
		if req.After(since) {
			count++
		}
	}
	return count
}

// Get client IP with proxy support
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies/load balancers)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take the first IP in case of multiple
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// Rate limiting middleware
func rateLimitMiddleware(rateLimiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)
			
			// Check if this is an auth endpoint
			isAuthEndpoint := strings.HasPrefix(r.URL.Path, "/auth/")
			
			// Check rate limit
			if !rateLimiter.Allow(clientIP, isAuthEndpoint) {
				// Get current stats for response
				rpm, rph := rateLimiter.GetStats(clientIP)
				
				// Set rate limit headers
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rateLimiter.config.RPM))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
				w.Header().Set("Retry-After", "60")
				
				// Log the violation with more details
				log.Printf("🚨 Rate limit exceeded: IP %s, Path %s, %d req/min, %d req/hour", 
					clientIP, r.URL.Path, rpm, rph)
				
				// Return rate limit error
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":              "Rate limit exceeded",
					"requests_per_minute": rpm,
					"limit_per_minute":   rateLimiter.config.RPM,
					"retry_after_seconds": 60,
					"message":            "Too many requests. Please wait before trying again.",
				})
				return
			}
			
			// Set rate limit headers for successful requests
			rpm, _ := rateLimiter.GetStats(clientIP)
			remaining := max(0, rateLimiter.config.RPM - rpm)
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rateLimiter.config.RPM))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
			
			next.ServeHTTP(w, r)
		})
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// User Store for authentication
type UserStore struct {
	mu    sync.RWMutex
	users map[string]*User
	db    *sql.DB
}

func NewUserStore(db *sql.DB) (*UserStore, error) {
	store := &UserStore{
		users: make(map[string]*User),
		db:    db,
	}

	createUserTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		first_name TEXT,
		last_name TEXT,
		role TEXT DEFAULT 'user',
		active INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	if _, err := db.Exec(createUserTableSQL); err != nil {
		return nil, fmt.Errorf("failed to create users table: %v", err)
	}

	db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")

	if err := store.load(); err != nil {
		return nil, err
	}

	if len(store.users) == 0 {
		if err := store.createDefaultAdmin(); err != nil {
			log.Printf("⚠️ Failed to create default admin: %v", err)
		}
	}

	return store, nil
}

func (s *UserStore) createDefaultAdmin() error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	admin := &User{
		ID:        uuid.New().String(),
		Email:     "admin@vrexisinsights.com",
		Password:  string(hashedPassword),
		FirstName: "Admin",
		LastName:  "User",
		Role:      "admin",
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.Create(admin); err != nil {
		return err
	}

	log.Println("🔑 Default admin user created:")
	log.Println("   Email: admin@vrexisinsights.com")
	log.Println("   Password: admin123")
	log.Println("   ⚠️ CHANGE THIS PASSWORD IMMEDIATELY!")

	return nil
}

func (s *UserStore) load() error {
	query := `SELECT id, email, password, first_name, last_name, role, active, created_at, updated_at FROM users`
	rows, err := s.db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	s.mu.Lock()
	defer s.mu.Unlock()

	for rows.Next() {
		var user User
		var activeInt int
		var createdAtStr, updatedAtStr string

		err := rows.Scan(&user.ID, &user.Email, &user.Password, &user.FirstName,
			&user.LastName, &user.Role, &activeInt, &createdAtStr, &updatedAtStr)
		if err != nil {
			return err
		}

		user.Active = activeInt != 0

		if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			user.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
			user.UpdatedAt = t
		}

		s.users[user.ID] = &user
	}
	return nil
}

func (s *UserStore) Create(user *User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	if user.Email == "" || user.Password == "" {
		return errors.New("email and password are required")
	}

	if s.GetByEmail(user.Email) != nil {
		return errors.New("email already exists")
	}

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	if user.Role == "" {
		user.Role = "user"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	query := `INSERT INTO users (id, email, password, first_name, last_name, role, active, created_at, updated_at)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, user.ID, user.Email, user.Password, user.FirstName,
		user.LastName, user.Role, user.Active, user.CreatedAt.Format(time.RFC3339),
		user.UpdatedAt.Format(time.RFC3339))

	if err == nil {
		s.users[user.ID] = user
	}
	return err
}

func (s *UserStore) GetByEmail(email string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.Email == email {
			return user
		}
	}
	return nil
}

func (s *UserStore) GetByID(id string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.users[id]
}

func (s *UserStore) ValidateCredentials(email, password string) (*User, error) {
	user := s.GetByEmail(email)
	if user == nil {
		return nil, errors.New("invalid credentials")
	}

	if !user.Active {
		return nil, errors.New("account disabled")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	return user, nil
}

// JWT functions
func initJWT() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		randomBytes := make([]byte, 32)
		if _, err := rand.Read(randomBytes); err != nil {
			log.Fatal("Failed to generate JWT secret")
		}
		jwtSecret = randomBytes
		log.Println("🔑 Generated random JWT secret (will change on restart)")
		log.Println("   For production, set JWT_SECRET environment variable")
	} else {
		jwtSecret = []byte(secret)
		log.Println("🔑 Using JWT secret from environment")
	}
}

func generateToken(user *User) (string, int64, error) {
	expirationTime := time.Now().Add(jwtExpiration)
	claims := &Claims{
		UserID: user.ID,
		Email:  user.Email,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   user.ID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", 0, err
	}

	return tokenString, expirationTime.Unix(), nil
}

func validateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// Authentication middleware
func authMiddleware(userStore *UserStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/auth/") || r.URL.Path == "/ws" || r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"Authorization header required"}`, http.StatusUnauthorized)
				return
			}

			tokenParts := strings.Split(authHeader, " ")
			if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
				http.Error(w, `{"error":"Invalid authorization header format"}`, http.StatusUnauthorized)
				return
			}

			claims, err := validateToken(tokenParts[1])
			if err != nil {
				http.Error(w, `{"error":"Invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
			ctx = context.WithValue(ctx, "user_email", claims.Email)
			ctx = context.WithValue(ctx, "user_role", claims.Role)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Enhanced CORS with security headers
func secureMiddleware(config *SecurityConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws: wss:")

			origin := r.Header.Get("Origin")
			if origin == "" {
				origin = "http://localhost:3000"
			}

			allowed := false
			for _, allowedOrigin := range config.AllowedOrigins {
				if origin == allowedOrigin {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else {
				w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
			}

			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Expose-Headers", "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			r.Body = http.MaxBytesReader(w, r.Body, config.MaxRequestSize)

			next.ServeHTTP(w, r)
		})
	}
}

// Enhanced validation with security checks
func (s *Service) Validate() error {
	if s.Name == "" || s.URL == "" {
		return errors.New("missing service name or URL")
	}

	if len(s.Name) > 100 {
		return errors.New("service name too long (max 100 characters)")
	}

	if len(s.URL) > 500 {
		return errors.New("URL too long (max 500 characters)")
	}

	if s.isRawIPOrHostname(s.URL) {
		if !s.isValidIPOrHostname(s.URL) {
			return errors.New("invalid IP address or hostname format")
		}

		if s.isDangerousHost(s.URL) {
			return errors.New("potentially unsafe host detected")
		}
	} else {
		parsedURL, err := url.Parse(s.URL)
		if err != nil {
			return errors.New("invalid URL format")
		}

		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			return errors.New("only HTTP and HTTPS protocols are allowed for URLs")
		}

		if s.isDangerousHost(parsedURL.Host) {
			return errors.New("potentially unsafe host detected")
		}
	}

	validTypes := map[string]bool{"website": true, "server": true, "misc": true}
	if s.Type != "" && !validTypes[s.Type] {
		return errors.New("invalid service type")
	}

	return nil
}

func (s *Service) isRawIPOrHostname(input string) bool {
	if strings.Contains(input, "://") {
		return false
	}

	host := input
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		host = parts[0]
	}

	if net.ParseIP(host) != nil {
		return true
	}

	return len(host) > 0 && !strings.Contains(host, "/")
}

func (s *Service) isValidIPOrHostname(input string) bool {
	host := input
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		if len(parts) != 2 {
			return false
		}
		host = parts[0]
		if port := parts[1]; port != "" {
			if len(port) == 0 || len(port) > 5 {
				return false
			}
			for _, char := range port {
				if char < '0' || char > '9' {
					return false
				}
			}
		}
	}

	if net.ParseIP(host) != nil {
		return true
	}

	if len(host) == 0 || len(host) > 253 {
		return false
	}

	for _, char := range host {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '.' || char == '-') {
			return false
		}
	}

	return true
}

func (s *Service) isDangerousHost(host string) bool {
	if os.Getenv("ENV") == "production" {
		if strings.Contains(host, "localhost") ||
			strings.Contains(host, "127.0.0.1") ||
			strings.Contains(host, "10.") ||
			strings.Contains(host, "172.") ||
			strings.Contains(host, "192.168.") {
			return true
		}
	}

	suspicious := []string{"bit.ly", "tinyurl", "t.co"}
	for _, domain := range suspicious {
		if strings.Contains(host, domain) {
			return true
		}
	}

	return false
}

type ServiceStore struct {
	mu       sync.RWMutex
	services map[string]*Service
	db       *sql.DB
}

func NewServiceStore(db *sql.DB) (*ServiceStore, error) {
	store := &ServiceStore{
		services: make(map[string]*Service),
		db:       db,
	}

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS services (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		url TEXT NOT NULL,
		enabled INTEGER DEFAULT 1
	)`

	if _, err := db.Exec(createTableSQL); err != nil {
		return nil, fmt.Errorf("failed to create services table: %v", err)
	}

	if err := store.migrateSchema(); err != nil {
		return nil, fmt.Errorf("failed to migrate schema: %v", err)
	}

	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *ServiceStore) migrateSchema() error {
	migrations := []struct {
		column     string
		definition string
		defaultVal string
	}{
		{"type", "TEXT DEFAULT 'website'", "website"},
		{"status", "TEXT DEFAULT 'unknown'", "unknown"},
		{"latency", "INTEGER DEFAULT 0", "0"},
		{"ping_latency", "INTEGER DEFAULT 0", "0"},
		{"last_checked", "DATETIME", ""},
		{"created_at", "DATETIME DEFAULT CURRENT_TIMESTAMP", ""},
		{"updated_at", "DATETIME DEFAULT CURRENT_TIMESTAMP", ""},
		{"user_id", "TEXT", ""},
	}

	for _, migration := range migrations {
		alterSQL := fmt.Sprintf("ALTER TABLE services ADD COLUMN %s %s", migration.column, migration.definition)
		if _, err := s.db.Exec(alterSQL); err != nil {
			checkSQL := fmt.Sprintf("SELECT %s FROM services LIMIT 1", migration.column)
			if _, checkErr := s.db.Query(checkSQL); checkErr != nil {
				log.Printf("⚠️ Failed to add column %s: %v", migration.column, err)
				return err
			}
			log.Printf("✅ Column %s already exists", migration.column)
		} else {
			log.Printf("✅ Added column %s to services table", migration.column)

			if migration.defaultVal != "" {
				updateSQL := fmt.Sprintf("UPDATE services SET %s = ? WHERE %s IS NULL OR %s = ''",
					migration.column, migration.column, migration.column)
				s.db.Exec(updateSQL, migration.defaultVal)
			}
		}
	}

	return nil
}

func (s *ServiceStore) load() error {
	columns := s.getAvailableColumns()

	query := "SELECT id, name, url, enabled"
	scanFields := []interface{}{new(string), new(string), new(string), new(int)}

	if contains(columns, "type") {
		query += ", COALESCE(type, 'website')"
		scanFields = append(scanFields, new(string))
	}
	if contains(columns, "status") {
		query += ", COALESCE(status, 'unknown')"
		scanFields = append(scanFields, new(string))
	}
	if contains(columns, "latency") {
		query += ", COALESCE(latency, 0)"
		scanFields = append(scanFields, new(int64))
	}
	if contains(columns, "ping_latency") {
		query += ", COALESCE(ping_latency, 0)"
		scanFields = append(scanFields, new(int64))
	}
	if contains(columns, "last_checked") {
		query += ", COALESCE(last_checked, '')"
		scanFields = append(scanFields, new(string))
	}
	if contains(columns, "created_at") {
		query += ", COALESCE(created_at, '')"
		scanFields = append(scanFields, new(string))
	}
	if contains(columns, "updated_at") {
		query += ", COALESCE(updated_at, '')"
		scanFields = append(scanFields, new(string))
	}
	if contains(columns, "user_id") {
		query += ", COALESCE(user_id, '')"
		scanFields = append(scanFields, new(string))
	}

	query += " FROM services"

	rows, err := s.db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	s.mu.Lock()
	defer s.mu.Unlock()

	for rows.Next() {
		if err := rows.Scan(scanFields...); err != nil {
			return err
		}

		svc := Service{
			ID:      *scanFields[0].(*string),
			Name:    *scanFields[1].(*string),
			URL:     *scanFields[2].(*string),
			Enabled: *scanFields[3].(*int) != 0,
		}

		svc.Type = "website"
		svc.Status = "unknown"
		svc.Latency = 0
		svc.PingLatency = 0
		svc.CreatedAt = time.Now()
		svc.UpdatedAt = time.Now()

		fieldIndex := 4
		if contains(columns, "type") && len(scanFields) > fieldIndex {
			if val := *scanFields[fieldIndex].(*string); val != "" {
				svc.Type = val
			}
			fieldIndex++
		}
		if contains(columns, "status") && len(scanFields) > fieldIndex {
			if val := *scanFields[fieldIndex].(*string); val != "" {
				svc.Status = val
			}
			fieldIndex++
		}
		if contains(columns, "latency") && len(scanFields) > fieldIndex {
			svc.Latency = *scanFields[fieldIndex].(*int64)
			fieldIndex++
		}
		if contains(columns, "ping_latency") && len(scanFields) > fieldIndex {
			svc.PingLatency = *scanFields[fieldIndex].(*int64)
			fieldIndex++
		}
		if contains(columns, "last_checked") && len(scanFields) > fieldIndex {
			if val := *scanFields[fieldIndex].(*string); val != "" {
				if t, err := time.Parse(time.RFC3339, val); err == nil {
					svc.LastChecked = t
				}
			}
			fieldIndex++
		}
		if contains(columns, "created_at") && len(scanFields) > fieldIndex {
			if val := *scanFields[fieldIndex].(*string); val != "" {
				if t, err := time.Parse(time.RFC3339, val); err == nil {
					svc.CreatedAt = t
				}
			}
			fieldIndex++
		}
		if contains(columns, "updated_at") && len(scanFields) > fieldIndex {
			if val := *scanFields[fieldIndex].(*string); val != "" {
				if t, err := time.Parse(time.RFC3339, val); err == nil {
					svc.UpdatedAt = t
				}
			}
			fieldIndex++
		}
		if contains(columns, "user_id") && len(scanFields) > fieldIndex {
			if val := *scanFields[fieldIndex].(*string); val != "" {
				svc.UserID = val
			}
			fieldIndex++
		}

		s.services[svc.ID] = &svc
	}
	return nil
}

func (s *ServiceStore) getAvailableColumns() []string {
	rows, err := s.db.Query("PRAGMA table_info(services)")
	if err != nil {
		return []string{"id", "name", "url", "enabled"}
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, pk int
		var defaultValue sql.NullString

		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
			continue
		}
		columns = append(columns, name)
	}
	return columns
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (s *ServiceStore) AllForUser(userID string) []*Service {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Service, 0)
	for _, svc := range s.services {
		if svc.UserID == userID || svc.UserID == "" {
			out = append(out, svc)
		}
	}
	return out
}

func (s *ServiceStore) All() []*Service {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Service, 0, len(s.services))
	for _, svc := range s.services {
		out = append(out, svc)
	}
	return out
}

func (s *ServiceStore) Add(svc *Service) error {
	if err := svc.Validate(); err != nil {
		return err
	}
	if svc.ID == "" {
		svc.ID = uuid.New().String()
	}

	now := time.Now()
	svc.CreatedAt = now
	svc.UpdatedAt = now
	svc.Status = "unknown"

	if svc.Type == "" {
		svc.Type = "website"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	columns := s.getAvailableColumns()

	query := "INSERT INTO services (id, name, url, enabled"
	values := "?, ?, ?, ?"
	args := []interface{}{svc.ID, svc.Name, svc.URL, svc.Enabled}

	if contains(columns, "type") {
		query += ", type"
		values += ", ?"
		args = append(args, svc.Type)
	}
	if contains(columns, "status") {
		query += ", status"
		values += ", ?"
		args = append(args, svc.Status)
	}
	if contains(columns, "created_at") {
		query += ", created_at"
		values += ", ?"
		args = append(args, svc.CreatedAt.Format(time.RFC3339))
	}
	if contains(columns, "updated_at") {
		query += ", updated_at"
		values += ", ?"
		args = append(args, svc.UpdatedAt.Format(time.RFC3339))
	}
	if contains(columns, "user_id") {
		query += ", user_id"
		values += ", ?"
		args = append(args, svc.UserID)
	}

	query += ") VALUES (" + values + ")"

	_, err := s.db.Exec(query, args...)
	if err == nil {
		s.services[svc.ID] = svc
		log.Printf("🔒 Service added securely: %s (%s) for user %s", svc.Name, svc.URL, svc.UserID)
	}
	return err
}

func (s *ServiceStore) Update(svc *Service) error {
	if err := svc.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	svc.UpdatedAt = time.Now()

	columns := s.getAvailableColumns()

	query := "UPDATE services SET name=?, url=?, enabled=?"
	args := []interface{}{svc.Name, svc.URL, svc.Enabled}

	if contains(columns, "type") {
		query += ", type=?"
		args = append(args, svc.Type)
	}
	if contains(columns, "updated_at") {
		query += ", updated_at=?"
		args = append(args, svc.UpdatedAt.Format(time.RFC3339))
	}

	query += " WHERE id=?"
	args = append(args, svc.ID)

	_, err := s.db.Exec(query, args...)
	if err == nil {
		if existing, ok := s.services[svc.ID]; ok {
			svc.Status = existing.Status
			svc.Latency = existing.Latency
			svc.PingLatency = existing.PingLatency
			svc.LastChecked = existing.LastChecked
			svc.CreatedAt = existing.CreatedAt
			svc.UserID = existing.UserID
		}
		s.services[svc.ID] = svc
		log.Printf("🔒 Service updated securely: %s", svc.Name)
	}
	return err
}

func (s *ServiceStore) UpdateMetrics(id string, status string, latency, pingLatency int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	columns := s.getAvailableColumns()

	setParts := []string{}
	args := []interface{}{}

	if contains(columns, "status") {
		setParts = append(setParts, "status=?")
		args = append(args, status)
	}
	if contains(columns, "latency") {
		setParts = append(setParts, "latency=?")
		args = append(args, latency)
	}
	if contains(columns, "ping_latency") {
		setParts = append(setParts, "ping_latency=?")
		args = append(args, pingLatency)
	}
	if contains(columns, "last_checked") {
		setParts = append(setParts, "last_checked=?")
		args = append(args, now.Format(time.RFC3339))
	}

	if len(setParts) == 0 {
		if s.services[id] != nil {
			s.services[id].Status = status
			s.services[id].Latency = latency
			s.services[id].PingLatency = pingLatency
			s.services[id].LastChecked = now
		}
		return nil
	}

	query := "UPDATE services SET " + strings.Join(setParts, ", ") + " WHERE id=?"
	args = append(args, id)

	_, err := s.db.Exec(query, args...)

	if err == nil && s.services[id] != nil {
		s.services[id].Status = status
		s.services[id].Latency = latency
		s.services[id].PingLatency = pingLatency
		s.services[id].LastChecked = now
	}
	return err
}

func (s *ServiceStore) Delete(id string, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := uuid.Parse(id); err != nil {
		return errors.New("invalid service ID format")
	}

	if service, ok := s.services[id]; ok {
		if service.UserID != "" && service.UserID != userID {
			return errors.New("access denied: service belongs to different user")
		}
	}

	_, err := s.db.Exec("DELETE FROM services WHERE id=?", id)
	if err == nil {
		if svc, ok := s.services[id]; ok {
			log.Printf("🔒 Service deleted securely: %s by user %s", svc.Name, userID)
			delete(s.services, id)
		}
	}
	return err
}

type ClientManager struct {
	mu      sync.Mutex
	clients map[*websocket.Conn]string
}

func NewClientManager() *ClientManager {
	return &ClientManager{clients: make(map[*websocket.Conn]string)}
}

func (c *ClientManager) Add(conn *websocket.Conn, userID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clients[conn] = userID
	log.Printf("🔒 Secure WebSocket client connected for user %s (total: %d)", userID, len(c.clients))
}

func (c *ClientManager) Remove(conn *websocket.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if userID, ok := c.clients[conn]; ok {
		delete(c.clients, conn)
		conn.Close()
		log.Printf("🔒 Secure WebSocket client disconnected for user %s (total: %d)", userID, len(c.clients))
	}
}

func (c *ClientManager) BroadcastToUser(msg interface{}, userID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	deadClients := []*websocket.Conn{}
	for conn, connUserID := range c.clients {
		if connUserID == userID {
			if err := conn.WriteJSON(msg); err != nil {
				deadClients = append(deadClients, conn)
			}
		}
	}

	for _, conn := range deadClients {
		delete(c.clients, conn)
		conn.Close()
	}
}

func (c *ClientManager) Broadcast(msg interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	deadClients := []*websocket.Conn{}
	for conn := range c.clients {
		if err := conn.WriteJSON(msg); err != nil {
			deadClients = append(deadClients, conn)
		}
	}

	for _, conn := range deadClients {
		delete(c.clients, conn)
		conn.Close()
	}
}

func checkHTTP(serviceURL string) (bool, int64) {
	start := time.Now()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}

	req, err := http.NewRequest("GET", serviceURL, nil)
	if err != nil {
		return false, 0
	}

	req.Header.Set("User-Agent", "VrexisMonitor/1.0")
	req.Header.Set("Accept", "text/html,application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()

	latency := time.Since(start).Milliseconds()

	return resp.StatusCode < 400, latency
}

func checkPing(host string) (bool, int64) {
	if strings.Contains(host, "://") {
		parsedURL, err := url.Parse(host)
		if err != nil {
			return false, 0
		}
		host = parsedURL.Host
	}

	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	start := time.Now()
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "5000", host)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "5", host)
	}

	err := cmd.Run()
	if err != nil {
		return false, 0
	}

	return true, time.Since(start).Milliseconds()
}

func (m *Monitor) startMonitoring(ctx context.Context) {
	log.Println("🔒 Starting secure service monitoring...")

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("🔒 Monitoring stopped")
			return
		case <-ticker.C:
			services := m.store.All()

			var wg sync.WaitGroup
			for _, svc := range services {
				if !svc.Enabled {
					continue
				}

				wg.Add(1)
				go func(service *Service) {
					defer wg.Done()

					var upHTTP bool
					var httpLatency int64
					var upPing bool
					var pingLatency int64

					if m.isRawIPOrHostname(service.URL) {
						upPing, pingLatency = checkPing(service.URL)
						upHTTP = false
						httpLatency = 0
						log.Printf("🏓 Ping check %s: %s (%dms)",
							service.Name, m.statusString(upPing), pingLatency)
					} else {
						upHTTP, httpLatency = checkHTTP(service.URL)
						upPing, pingLatency = checkPing(service.URL)
						log.Printf("🌐 HTTP check %s: %s (%dms HTTP, %dms ping)",
							service.Name, m.statusString(upHTTP || upPing), httpLatency, pingLatency)
					}

					status := "down"
					if upHTTP || upPing {
						status = "up"
					}

					if err := m.store.UpdateMetrics(service.ID, status, httpLatency, pingLatency); err != nil {
						log.Printf("⚠️ Failed to update metrics for %s: %v", service.Name, err)
						return
					}

					if service.UserID != "" {
						m.clients.BroadcastToUser(map[string]interface{}{
							"id":           service.ID,
							"name":         service.Name,
							"url":          service.URL,
							"type":         service.Type,
							"status":       status,
							"latency":      httpLatency,
							"ping_latency": pingLatency,
							"last_checked": time.Now().Format(time.RFC3339),
						}, service.UserID)
					}
				}(svc)
			}
			wg.Wait()
		}
	}
}

func (m *Monitor) isRawIPOrHostname(input string) bool {
	return !strings.Contains(input, "://")
}

func (m *Monitor) statusString(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

func setupRoutes(store *ServiceStore, userStore *UserStore, clients *ClientManager, config *SecurityConfig) *mux.Router {
	r := mux.NewRouter()

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			for _, allowed := range config.AllowedOrigins {
				if origin == allowed {
					return true
				}
			}
			return origin == "http://localhost:3000"
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	// Health check endpoint (no rate limiting)
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().Format(time.RFC3339),
			"version":   "1.0.0",
		})
	}).Methods("GET")

	// Authentication routes
	auth := r.PathPrefix("/auth").Subrouter()

	auth.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		if req.Email == "" || req.Password == "" {
			http.Error(w, `{"error":"Email and password are required"}`, http.StatusBadRequest)
			return
		}

		if len(req.Password) < 6 {
			http.Error(w, `{"error":"Password must be at least 6 characters"}`, http.StatusBadRequest)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, `{"error":"Failed to hash password"}`, http.StatusInternalServerError)
			return
		}

		user := &User{
			Email:     req.Email,
			Password:  string(hashedPassword),
			FirstName: req.FirstName,
			LastName:  req.LastName,
			Role:      "user",
			Active:    true,
		}

		if err := userStore.Create(user); err != nil {
			if strings.Contains(err.Error(), "email already exists") {
				http.Error(w, `{"error":"Email already exists"}`, http.StatusConflict)
			} else {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
			}
			return
		}

		token, expiresAt, err := generateToken(user)
		if err != nil {
			http.Error(w, `{"error":"Failed to generate token"}`, http.StatusInternalServerError)
			return
		}

		response := AuthResponse{
			Token:     token,
			User:      *user,
			ExpiresAt: expiresAt,
		}

		json.NewEncoder(w).Encode(response)
		log.Printf("🔑 User registered: %s from IP %s", user.Email, getClientIP(r))
	}).Methods("POST")

	auth.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		user, err := userStore.ValidateCredentials(req.Email, req.Password)
		if err != nil {
			http.Error(w, `{"error":"Invalid credentials"}`, http.StatusUnauthorized)
			return
		}

		token, expiresAt, err := generateToken(user)
		if err != nil {
			http.Error(w, `{"error":"Failed to generate token"}`, http.StatusInternalServerError)
			return
		}

		response := AuthResponse{
			Token:     token,
			User:      *user,
			ExpiresAt: expiresAt,
		}

		json.NewEncoder(w).Encode(response)
		log.Printf("🔑 User logged in: %s from IP %s", user.Email, getClientIP(r))
	}).Methods("POST")

	// WebSocket endpoint
	r.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				tokenParts := strings.Split(authHeader, " ")
				if len(tokenParts) == 2 && tokenParts[0] == "Bearer" {
					token = tokenParts[1]
				}
			}
		}

		if token == "" {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		claims, err := validateToken(token)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("⚠️ WebSocket upgrade failed: %v", err)
			http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
			return
		}

		clients.Add(conn, claims.UserID)

		services := store.AllForUser(claims.UserID)
		for _, svc := range services {
			conn.WriteJSON(map[string]interface{}{
				"id":           svc.ID,
				"name":         svc.Name,
				"url":          svc.URL,
				"type":         svc.Type,
				"status":       svc.Status,
				"latency":      svc.Latency,
				"ping_latency": svc.PingLatency,
				"last_checked": svc.LastChecked.Format(time.RFC3339),
			})
		}

		go func() {
			defer clients.Remove(conn)
			for {
				_, _, err := conn.ReadMessage()
				if err != nil {
					break
				}
			}
		}()
	})

	// API v1 routes
	api := r.PathPrefix("/api/v1").Subrouter()

	api.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		userID := r.Context().Value("user_id").(string)
		services := store.AllForUser(userID)
		if err := json.NewEncoder(w).Encode(services); err != nil {
			http.Error(w, `{"error":"Failed to encode services"}`, http.StatusInternalServerError)
		}
	}).Methods("GET")

	api.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		userID := r.Context().Value("user_id").(string)

		var svc Service
		if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		if svc.ID == "" {
			svc.ID = uuid.New().String()
		}

		svc.UserID = userID

		if err := store.Add(&svc); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
			return
		}

		json.NewEncoder(w).Encode(svc)
	}).Methods("POST")

	api.HandleFunc("/services/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		userID := r.Context().Value("user_id").(string)
		id := mux.Vars(r)["id"]

		var svc Service
		if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		svc.ID = id
		svc.UserID = userID

		if err := store.Update(&svc); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	}).Methods("PUT")

	api.HandleFunc("/services/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		userID := r.Context().Value("user_id").(string)
		id := mux.Vars(r)["id"]

		if err := store.Delete(id, userID); err != nil {
			if strings.Contains(err.Error(), "access denied") {
				http.Error(w, `{"error":"Access denied"}`, http.StatusForbidden)
			} else {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			}
			return
		}

		w.WriteHeader(http.StatusOK)
	}).Methods("DELETE")

	// Legacy routes
	r.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		userID := r.Context().Value("user_id").(string)
		services := store.AllForUser(userID)
		json.NewEncoder(w).Encode(services)
	}).Methods("GET")

	r.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		userID := r.Context().Value("user_id").(string)

		var svc Service
		if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}
		if svc.ID == "" {
			svc.ID = uuid.New().String()
		}
		svc.UserID = userID

		if err := store.Add(&svc); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(svc)
	}).Methods("POST")

	r.HandleFunc("/services/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		userID := r.Context().Value("user_id").(string)
		id := mux.Vars(r)["id"]

		if err := store.Delete(id, userID); err != nil {
			if strings.Contains(err.Error(), "access denied") {
				http.Error(w, `{"error":"Access denied"}`, http.StatusForbidden)
			} else {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}).Methods("DELETE")

	return r
}

func main() {
	initJWT()

	// Enhanced rate limiting configuration
	rateLimitConfig := RateLimitConfig{
		RPM:           100, // 100 requests per minute for general API
		Burst:         20,  // Burst of 20 requests
		AuthRPM:       20,  // 20 auth requests per minute (more restrictive)
		AuthBurst:     5,   // Burst of 5 auth requests
		WSConnections: 10,  // Max 10 WebSocket connections per IP
		EnableLogging: true,
		LogViolations: true,
	}

	config := &SecurityConfig{
		EnableHTTPS:      os.Getenv("ENABLE_HTTPS") == "true",
		MaxRequestSize:   1024 * 1024,
		RateLimitEnabled: true,
		AllowedOrigins: []string{
			"http://localhost:3000",
			"https://localhost:3000",
			"http://127.0.0.1:3000",
		},
		RequireAuth: true,
		RateLimit:   rateLimitConfig,
	}

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "services.db"
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatalf("❌ Failed to open DB: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("❌ Failed to connect to DB: %v", err)
	}

	userStore, err := NewUserStore(db)
	if err != nil {
		log.Fatalf("❌ Failed to initialize user store: %v", err)
	}

	store, err := NewServiceStore(db)
	if err != nil {
		log.Fatalf("❌ Failed to initialize service store: %v", err)
	}

	clients := NewClientManager()
	rateLimiter := NewRateLimiter(rateLimitConfig)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start rate limiter cleanup
	go rateLimiter.StartCleanup(ctx)

	monitor := &Monitor{
		store:       store,
		userStore:   userStore,
		clients:     clients,
		rateLimiter: rateLimiter,
		config:      config,
	}
	go monitor.startMonitoring(ctx)

	router := setupRoutes(store, userStore, clients, config)

	// Apply middleware stack in order
	handler := secureMiddleware(config)(
		rateLimitMiddleware(rateLimiter)(
			authMiddleware(userStore)(router)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		if config.EnableHTTPS {
			log.Printf("🔒 Secure HTTPS server with rate limiting running on https://localhost:%s", port)
		} else {
			log.Printf("🚀 HTTP server with rate limiting running on http://localhost:%s", port)
		}
		log.Printf("🛡️ Rate Limits: %d req/min general, %d req/min auth", rateLimitConfig.RPM, rateLimitConfig.AuthRPM)
		log.Println("🔒 Security features: JWT auth, rate limiting, CORS, headers, validation")
		
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ HTTP server failed: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("🛑 Shutting down server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("⚠️ Server shutdown error: %v", err)
	} else {
		log.Println("✅ Server shutdown complete")
	}
}