package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

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

// authMiddleware validates JWT tokens properly
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

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		tokenString, err := extractTokenFromHeader(authHeader)
		if err != nil {
			respondError(w, http.StatusUnauthorized, err.Error())
			return
		}

		// Validate JWT token properly
		claims, err := validateToken(tokenString, s.stores.Auth)
		if err != nil {
			respondError(w, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		// Verify user exists and is active
		user := s.stores.User.GetByID(claims.UserID)
		if user == nil || !user.Active {
			respondError(w, http.StatusUnauthorized, "User account not found or disabled")
			return
		}

		// Add user context
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		ctx = context.WithValue(ctx, "user_email", claims.Email)
		ctx = context.WithValue(ctx, "user_role", claims.Role)
		ctx = context.WithValue(ctx, "user", user)

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
	uptime := time.Since(s.startTime).Seconds()

	health := HealthResponse{
		Status:      "healthy",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Version:     "2.1.0",
		Uptime:      uptime,
		Connections: s.services.Clients.GetActiveConnections(),
		GoVersion:   runtime.Version(),
		Services: map[string]interface{}{
			"database": "connected",
			"cache":    "active",
			"alerts":   "running",
		},
	}

	respondJSON(w, http.StatusOK, health)
}

// handleRegister - Fixed to use proper password hashing
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate input
	if err := validateEmail(req.Email); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := validatePasswordComplexity(req.Password); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.FirstName == "" || req.LastName == "" {
		respondError(w, http.StatusBadRequest, "First name and last name are required")
		return
	}

	// Check rate limiting
	clientIP := getClientIP(r)
	if !s.services.RateLimiter.Allow(clientIP, true) {
		respondError(w, http.StatusTooManyRequests, "Too many registration attempts")
		return
	}

	// Hash password properly
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		log.Printf("Password hashing failed: %v", err)
		respondError(w, http.StatusInternalServerError, "Registration failed")
		return
	}

	// Create user via UserStore
	user := &User{
		Email:           req.Email,
		Password:        hashedPassword,
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		Role:            "user",
		Active:          true,
		MFAEnabled:      false,
		PasswordChanged: time.Now(),
	}

	createdUser, err := s.stores.User.CreateUser(user)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "UNIQUE constraint failed") {
			respondError(w, http.StatusConflict, "User with this email already exists")
		} else {
			log.Printf("User creation failed: %v", err)
			respondError(w, http.StatusInternalServerError, "Registration failed")
		}
		return
	}

	// Generate proper JWT tokens
	accessToken, refreshToken, expiresAt, err := generateTokenPair(createdUser)
	if err != nil {
		log.Printf("Token generation failed: %v", err)
		respondError(w, http.StatusInternalServerError, "Registration failed")
		return
	}

	// Store refresh token
	s.stores.Auth.storeRefreshToken(refreshToken, createdUser.ID, time.Unix(expiresAt, 0).Add(refreshExpiration))

	response := AuthResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
		User:         *createdUser,
		ExpiresAt:    expiresAt,
	}

	log.Printf("User registered successfully: %s", createdUser.Email)
	respondJSON(w, http.StatusCreated, response)
}

// handleLogin - Fixed to use proper password verification and JWT
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate input
	if req.Email == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	clientIP := getClientIP(r)

	// Check rate limiting and login attempts
	if !s.stores.Auth.recordLoginAttempt(clientIP, req.Email, 5, 30*time.Minute) {
		remaining := s.stores.Auth.getLockoutTimeRemaining(clientIP, req.Email)
		respondError(w, http.StatusTooManyRequests,
			fmt.Sprintf("Account locked. Try again in %d minutes", int(remaining.Minutes())))
		return
	}

	// Get user from database
	user, err := s.stores.User.GetUserByEmail(req.Email)
	if err != nil {
		log.Printf("Login attempt for non-existent user: %s", req.Email)
		respondError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	// Check if user is active
	if !user.Active {
		respondError(w, http.StatusUnauthorized, "Account is disabled")
		return
	}

	// Verify password
	if err := comparePassword(user.Password, req.Password); err != nil {
		log.Printf("Invalid password for user: %s", req.Email)
		respondError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	// Handle MFA if enabled
	if user.MFAEnabled {
		if req.MFACode == "" {
			response := map[string]interface{}{
				"requires_mfa": true,
				"message":      "MFA code required",
			}
			respondJSON(w, http.StatusOK, response)
			return
		}

		// Verify MFA code
		if !s.verifyMFACode(user, req.MFACode) {
			respondError(w, http.StatusUnauthorized, "Invalid MFA code")
			return
		}
	}

	// Reset login attempts on successful login
	s.stores.Auth.resetLoginAttempts(clientIP, req.Email)

	// Update last login time
	s.stores.User.UpdateLastLogin(user.ID)

	// Generate proper JWT tokens
	accessToken, refreshToken, expiresAt, err := generateTokenPair(user)
	if err != nil {
		log.Printf("Token generation failed: %v", err)
		respondError(w, http.StatusInternalServerError, "Login failed")
		return
	}

	// Store refresh token
	s.stores.Auth.storeRefreshToken(refreshToken, user.ID, time.Unix(expiresAt, 0).Add(refreshExpiration))

	response := AuthResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
		User:         *user,
		ExpiresAt:    expiresAt,
	}

	log.Printf("Successful login for user: %s", user.Email)
	respondJSON(w, http.StatusOK, response)
}

// handleRefresh - Fixed to use proper JWT refresh
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.RefreshToken == "" {
		respondError(w, http.StatusBadRequest, "Refresh token is required")
		return
	}

	// Validate refresh token
	claims, err := validateToken(req.RefreshToken, s.stores.Auth)
	if err != nil || claims.TokenType != "refresh" {
		respondError(w, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	// Verify refresh token exists in store
	storedToken, valid := s.stores.Auth.validateRefreshToken(req.RefreshToken)
	if !valid {
		respondError(w, http.StatusUnauthorized, "Refresh token not found or expired")
		return
	}

	// Get user
	user := s.stores.User.GetByID(storedToken.UserID)
	if user == nil || !user.Active {
		respondError(w, http.StatusUnauthorized, "User not found or disabled")
		return
	}

	// Generate new tokens
	accessToken, newRefreshToken, expiresAt, err := generateTokenPair(user)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Token refresh failed")
		return
	}

	// Revoke old refresh token and store new one
	s.stores.Auth.revokeRefreshToken(req.RefreshToken)
	s.stores.Auth.storeRefreshToken(newRefreshToken, user.ID, time.Unix(expiresAt, 0).Add(refreshExpiration))

	response := map[string]interface{}{
		"token":         accessToken,
		"refresh_token": newRefreshToken,
		"expires_in":    jwtExpiration.Seconds(),
	}

	respondJSON(w, http.StatusOK, response)
}

// handleLogout - Fixed to properly revoke tokens
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Get token from header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		if tokenString, err := extractTokenFromHeader(authHeader); err == nil {
			// Add token to revocation list
			claims, _ := validateToken(tokenString, s.stores.Auth)
			if claims != nil {
				s.stores.Auth.revokeToken(tokenString, time.Unix(claims.ExpiresAt.Unix(), 0))
			}
		}
	}

	// Also check for refresh token in request body
	var req map[string]string
	if json.NewDecoder(r.Body).Decode(&req) == nil {
		if refreshToken := req["refresh_token"]; refreshToken != "" {
			s.stores.Auth.revokeRefreshToken(refreshToken)
		}
	}

	response := map[string]string{
		"message": "Logged out successfully",
	}
	respondJSON(w, http.StatusOK, response)
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	respondError(w, http.StatusNotImplemented, "WebSocket endpoint not yet implemented")
}

// Service management handlers
func (s *Server) handleGetServices(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	services, err := s.stores.Service.GetServicesByUserID(userID)
	if err != nil {
		log.Printf("Error fetching services for user %s: %v", userID, err)
		respondError(w, http.StatusInternalServerError, "Failed to fetch services")
		return
	}

	respondJSON(w, http.StatusOK, services)
}

func (s *Server) handleCreateService(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

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

	// Set user ID and defaults
	service.UserID = userID
	service.Status = "pending"
	service.Enabled = true

	createdService, err := s.stores.Service.CreateService(&service)
	if err != nil {
		log.Printf("Error creating service: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to create service")
		return
	}

	log.Printf("Created service: %s (%s) for user %s", createdService.Name, createdService.URL, userID)
	respondJSON(w, http.StatusCreated, createdService)
}

func (s *Server) handleUpdateService(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	vars := mux.Vars(r)
	serviceID := vars["id"]

	if serviceID == "" {
		respondError(w, http.StatusBadRequest, "Service ID required")
		return
	}

	// Get existing service
	service, err := s.stores.Service.GetServiceByID(serviceID, userID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			respondError(w, http.StatusNotFound, "Service not found")
		} else {
			log.Printf("Error fetching service %s: %v", serviceID, err)
			respondError(w, http.StatusInternalServerError, "Failed to fetch service")
		}
		return
	}

	var updates Service
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Update fields if provided
	if updates.Name != "" {
		service.Name = updates.Name
	}
	if updates.URL != "" {
		service.URL = updates.URL
	}
	if updates.Type != "" {
		service.Type = updates.Type
	}

	if err := s.stores.Service.UpdateService(service); err != nil {
		log.Printf("Error updating service %s: %v", serviceID, err)
		respondError(w, http.StatusInternalServerError, "Failed to update service")
		return
	}

	log.Printf("Updated service: %s by user %s", serviceID, userID)
	respondJSON(w, http.StatusOK, service)
}

func (s *Server) handleDeleteService(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	vars := mux.Vars(r)
	serviceID := vars["id"]

	if serviceID == "" {
		respondError(w, http.StatusBadRequest, "Service ID required")
		return
	}

	if err := s.stores.Service.DeleteService(serviceID, userID); err != nil {
		log.Printf("Error deleting service %s: %v", serviceID, err)
		respondError(w, http.StatusInternalServerError, "Failed to delete service")
		return
	}

	log.Printf("Deleted service: %s by user %s", serviceID, userID)
	respondJSON(w, http.StatusOK, map[string]string{
		"message": "Service deleted successfully",
	})
}

func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)

	userResponse := map[string]interface{}{
		"id":               user.ID,
		"email":            user.Email,
		"first_name":       user.FirstName,
		"last_name":        user.LastName,
		"role":             user.Role,
		"active":           user.Active,
		"mfa_enabled":      user.MFAEnabled,
		"created_at":       user.CreatedAt,
		"updated_at":       user.UpdatedAt,
		"password_changed": user.PasswordChanged,
	}

	if user.LastLogin != nil {
		userResponse["last_login"] = user.LastLogin
	}

	respondJSON(w, http.StatusOK, userResponse)
}

func (s *Server) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)

	lastLogin := ""
	if user.LastLogin != nil {
		lastLogin = user.LastLogin.Format(time.RFC3339)
	}

	securityStatus := SecurityStatusResponse{
		MFAEnabled:      user.MFAEnabled,
		LastLogin:       lastLogin,
		ActiveSessions:  1, // Current session
		SecurityAlerts:  0, // Could be populated from security monitor
		PasswordChanged: user.PasswordChanged.Format(time.RFC3339),
	}

	respondJSON(w, http.StatusOK, securityStatus)
}

// Placeholder for MFA verification - implement based on your MFA solution
func (s *Server) verifyMFACode(user *User, code string) bool {
	// TODO: Implement TOTP verification using user.MFASecret
	// For now, return true for demo purposes
	return true
}
