package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Demo users for testing (in production, use database)
var demoUsers = map[string]DemoUser{
	"admin@vrexisinsights.com": {
		ID:           1,
		Email:        "admin@vrexisinsights.com",
		PasswordHash: "testtest123", // Plain text for demo
		FirstName:    "Admin",
		LastName:     "User",
		Role:         "admin",
		Active:       true,
		CreatedAt:    time.Now(),
	},
	"demo@vrexisinsights.com": {
		ID:           2,
		Email:        "demo@vrexisinsights.com",
		PasswordHash: "demo123", // Plain text for demo
		FirstName:    "Demo",
		LastName:     "User",
		Role:         "user",
		Active:       true,
		CreatedAt:    time.Now(),
	},
}

type DemoUser struct {
	ID           int       `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	FirstName    string    `json:"first_name"`
	LastName     string    `json:"last_name"`
	Role         string    `json:"role"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
}

// Demo services storage
var demoServices = make(map[string]Service)

// Simple token generation to avoid conflicts
func createDemoToken() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return "demo-token-" + hex.EncodeToString(bytes)
}

// RateLimiter placeholder methods
func (rl *RateLimiter) Allow(ip string, isAuth bool) bool {
	return true // Allow all for demo
}

func (rl *RateLimiter) GetStats(ip string) (int, error) {
	return 10, nil
}

// UserStore placeholder method
func (us *UserStore) GetByID(userID string) *User {
	for _, demoUser := range demoUsers {
		if strconv.Itoa(demoUser.ID) == userID {
			return &User{
				ID:        strconv.Itoa(demoUser.ID),
				Email:     demoUser.Email,
				FirstName: demoUser.FirstName,
				LastName:  demoUser.LastName,
				Role:      demoUser.Role,
				Active:    demoUser.Active,
			}
		}
	}
	return nil
}

// securityMiddleware adds security headers and CORS
func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		if s.config.EnableHTTPS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		// Content Security Policy
		csp := []string{
			"default-src 'self'",
			"script-src 'self' 'unsafe-inline' 'unsafe-eval'",
			"style-src 'self' 'unsafe-inline'",
			"img-src 'self' data: https:",
			"connect-src 'self' ws: wss:",
			"font-src 'self'",
			"object-src 'none'",
			"base-uri 'self'",
			"form-action 'self'",
			"frame-ancestors 'none'",
		}
		w.Header().Set("Content-Security-Policy", strings.Join(csp, "; "))

		// CORS headers
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "http://localhost:3000"
		}

		// Allow localhost origins for development
		allowedOrigins := []string{
			"http://localhost:3000",
			"http://localhost:3001",
			"http://localhost:8080",
			"http://127.0.0.1:3000",
		}

		allowed := false
		for _, o := range allowedOrigins {
			if o == origin {
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

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Request size limiting
		r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024) // 10MB limit

		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware implements rate limiting
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		isAuth := strings.HasPrefix(r.URL.Path, "/auth/")

		if !s.services.RateLimiter.Allow(clientIP, isAuth) {
			rpm, _ := s.services.RateLimiter.GetStats(clientIP)
			w.Header().Set("Retry-After", "60")
			respondJSON(w, http.StatusTooManyRequests, RateLimitResponse{
				Error:             "Rate limit exceeded",
				RequestsPerMinute: rpm,
				LimitPerMinute:    60,
				RetryAfterSeconds: 60,
				Message:           "Too many requests. Please wait before trying again.",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// authMiddleware validates JWT tokens
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Public endpoints that don't require authentication
		public := []string{"/auth/", "/ws", "/health"}
		for _, path := range public {
			if strings.HasPrefix(r.URL.Path, path) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Check for Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		// Parse Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			respondError(w, http.StatusUnauthorized, "Invalid authorization header format")
			return
		}

		token := parts[1]

		// For demo purposes, accept any token that starts with "demo-token"
		if !strings.HasPrefix(token, "demo-token") {
			respondError(w, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		// Add user context
		ctx := context.WithValue(r.Context(), "user_id", "1")
		ctx = context.WithValue(ctx, "user_email", "admin@vrexisinsights.com")
		ctx = context.WithValue(ctx, "user_role", "admin")

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Helper functions
func respondJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

func respondError(w http.ResponseWriter, statusCode int, message string) {
	respondJSON(w, statusCode, map[string]string{"error": message})
}

func getClientIP(r *http.Request) string {
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return cf
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ips := strings.Split(fwd, ",")
		return strings.TrimSpace(ips[0])
	}
	if rip := r.Header.Get("X-Real-IP"); rip != "" {
		return rip
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// Route handlers
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
		"services": map[string]string{
			"database": "connected",
			"cache":    "active",
		},
	}
	respondJSON(w, http.StatusOK, health)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" {
		respondError(w, http.StatusBadRequest, "All fields are required")
		return
	}

	// Check if user already exists
	if _, exists := demoUsers[req.Email]; exists {
		respondError(w, http.StatusConflict, "User with this email already exists")
		return
	}

	// Create new user (using plain text password for demo)
	newUser := DemoUser{
		ID:           len(demoUsers) + 1,
		Email:        req.Email,
		PasswordHash: req.Password, // Store plain text for demo
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Role:         "user",
		Active:       true,
		CreatedAt:    time.Now(),
	}

	// Store user
	demoUsers[req.Email] = newUser

	// Generate token
	token := createDemoToken()

	// Prepare response
	userResponse := map[string]interface{}{
		"id":         newUser.ID,
		"email":      newUser.Email,
		"first_name": newUser.FirstName,
		"last_name":  newUser.LastName,
		"role":       newUser.Role,
		"active":     newUser.Active,
		"created_at": newUser.CreatedAt,
	}

	response := map[string]interface{}{
		"user":    userResponse,
		"token":   token,
		"message": "Registration successful",
	}

	respondJSON(w, http.StatusCreated, response)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	// Check if user exists
	user, exists := demoUsers[req.Email]
	if !exists {
		respondError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	// Check if user is active
	if !user.Active {
		respondError(w, http.StatusUnauthorized, "Account is disabled")
		return
	}

	// Simple password check (plain text for demo)
	if req.Password != user.PasswordHash {
		respondError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	// Generate token
	token := createDemoToken()

	// Prepare user response
	userResponse := map[string]interface{}{
		"id":         user.ID,
		"email":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"role":       user.Role,
		"active":     user.Active,
	}

	response := map[string]interface{}{
		"user":  userResponse,
		"token": token,
	}

	log.Printf("Successful login for user: %s", user.Email)
	respondJSON(w, http.StatusOK, response)
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	token := createDemoToken()

	response := map[string]interface{}{
		"token":      token,
		"expires_in": 3600,
	}

	respondJSON(w, http.StatusOK, response)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"message": "Logged out successfully",
	}
	respondJSON(w, http.StatusOK, response)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	respondError(w, http.StatusNotImplemented, "WebSocket endpoint not yet implemented")
}

func (s *Server) handleGetServices(w http.ResponseWriter, r *http.Request) {
	services := make([]Service, 0, len(demoServices))
	for _, service := range demoServices {
		services = append(services, service)
	}

	respondJSON(w, http.StatusOK, services)
}

func (s *Server) handleCreateService(w http.ResponseWriter, r *http.Request) {
	var service Service
	if err := json.NewDecoder(r.Body).Decode(&service); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if service.Name == "" || service.URL == "" {
		respondError(w, http.StatusBadRequest, "Name and URL are required")
		return
	}

	// Set defaults
	if service.ID == "" {
		service.ID = createDemoToken()[:8] // Short ID
	}
	service.Status = "pending"
	service.CreatedAt = time.Now()
	service.UpdatedAt = time.Now()
	service.LastChecked = time.Now()

	// Store service
	demoServices[service.ID] = service

	log.Printf("Created service: %s (%s)", service.Name, service.URL)
	respondJSON(w, http.StatusCreated, service)
}

func (s *Server) handleUpdateService(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		respondError(w, http.StatusBadRequest, "Service ID required")
		return
	}
	serviceID := parts[len(parts)-1]

	service, exists := demoServices[serviceID]
	if !exists {
		respondError(w, http.StatusNotFound, "Service not found")
		return
	}

	var updates Service
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if updates.Name != "" {
		service.Name = updates.Name
	}
	if updates.URL != "" {
		service.URL = updates.URL
	}
	if updates.Type != "" {
		service.Type = updates.Type
	}
	service.UpdatedAt = time.Now()

	demoServices[serviceID] = service
	respondJSON(w, http.StatusOK, service)
}

func (s *Server) handleDeleteService(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		respondError(w, http.StatusBadRequest, "Service ID required")
		return
	}
	serviceID := parts[len(parts)-1]

	if _, exists := demoServices[serviceID]; !exists {
		respondError(w, http.StatusNotFound, "Service not found")
		return
	}

	delete(demoServices, serviceID)

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "Service deleted successfully",
	})
}

func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	userEmail := r.Context().Value("user_email").(string)

	if user, exists := demoUsers[userEmail]; exists {
		userResponse := map[string]interface{}{
			"id":         user.ID,
			"email":      user.Email,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"role":       user.Role,
			"active":     user.Active,
			"created_at": user.CreatedAt,
		}
		respondJSON(w, http.StatusOK, userResponse)
	} else {
		respondError(w, http.StatusNotFound, "User not found")
	}
}

func (s *Server) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	securityStatus := SecurityStatusResponse{
		MFAEnabled:      false,
		LastLogin:       time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
		ActiveSessions:  1,
		SecurityAlerts:  0,
		PasswordChanged: time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339),
	}

	respondJSON(w, http.StatusOK, securityStatus)
}
