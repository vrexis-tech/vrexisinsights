package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

// Middleware type definition
type Middleware func(http.Handler) http.Handler

// RateLimiter placeholder methods
func (rl *RateLimiter) Allow(ip string, isAuth bool) bool {
	// TODO: implement rate limiting logic
	return true
}

func (rl *RateLimiter) GetStats(ip string) (int, error) {
	// TODO: return dummy stats or real values
	return 10, nil
}

// UserStore placeholder method
func (us *UserStore) GetByID(userID string) *User {
	// TODO: implement DB fetch logic
	return &User{ID: userID, Email: "test@example.com", Active: true}
}

// securityMiddleware adds security headers and CORS
func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		if s.config.EnableHTTPS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		csp := []string{
			"default-src 'self'",
			"script-src 'self'",
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

		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "http://localhost:3000"
		}
		allowed := false
		for _, o := range s.config.Security.AllowedOrigins {
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

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, s.config.Security.MaxRequestSize)
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
				LimitPerMinute:    s.config.Security.RateLimit.RPM,
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
		public := []string{"/auth/", "/ws", "/health"}
		for _, path := range public {
			if strings.HasPrefix(r.URL.Path, path) {
				next.ServeHTTP(w, r)
				return
			}
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			respondError(w, http.StatusUnauthorized, "Invalid authorization header format")
			return
		}

		claims, err := validateToken(parts[1], s.stores.Auth)
		if err != nil {
			respondError(w, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		user := s.stores.User.GetByID(claims.UserID)
		if user == nil || !user.Active {
			s.stores.Auth.revokeToken(parts[1], time.Now().Add(24*time.Hour))
			respondError(w, http.StatusUnauthorized, "User account disabled or not found")
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		ctx = context.WithValue(ctx, "user_email", claims.Email)
		ctx = context.WithValue(ctx, "user_role", claims.Role)
		ctx = context.WithValue(ctx, "user", user)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Helpers

func respondJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
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

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusCreated, map[string]string{"message": "register successful"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"message": "login successful"})
}

// Stub missing handlers for route registration completeness
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request)        {}
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request)         {}
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request)      {}
func (s *Server) handleGetServices(w http.ResponseWriter, r *http.Request)    {}
func (s *Server) handleCreateService(w http.ResponseWriter, r *http.Request)  {}
func (s *Server) handleUpdateService(w http.ResponseWriter, r *http.Request)  {}
func (s *Server) handleDeleteService(w http.ResponseWriter, r *http.Request)  {}
func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request)     {}
func (s *Server) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {}
