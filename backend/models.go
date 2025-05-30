package main

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// User represents a system user
type User struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	Password        string    `json:"-"`
	FirstName       string    `json:"first_name"`
	LastName        string    `json:"last_name"`
	Role            string    `json:"role"`
	Active          bool      `json:"active"`
	MFAEnabled      bool      `json:"mfa_enabled"`
	MFASecret       string    `json:"-"`
	BackupCodes     []string  `json:"-"`
	LastLogin       time.Time `json:"last_login"`
	PasswordChanged time.Time `json:"password_changed"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Service represents a monitored service
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
	Encrypted   bool      `json:"encrypted"`
}

// Claims represents JWT claims
type Claims struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

// Request/Response DTOs

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	MFACode  string `json:"mfa_code,omitempty"`
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// AuthResponse represents an authentication response
type AuthResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	User         User   `json:"user"`
	ExpiresAt    int64  `json:"expires_at"`
	RequiresMFA  bool   `json:"requires_mfa,omitempty"`
}

// RefreshTokenRequest represents a token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// ServiceStatusMessage represents a WebSocket service status message
type ServiceStatusMessage struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	ServiceType string `json:"service_type"`
	Status      string `json:"status"`
	Latency     int64  `json:"latency"`
	PingLatency int64  `json:"ping_latency"`
	LastChecked string `json:"last_checked"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    string `json:"code,omitempty"`
}

// HealthResponse represents a health check response
type HealthResponse struct {
	Status      string  `json:"status"`
	Timestamp   string  `json:"timestamp"`
	Version     string  `json:"version"`
	Uptime      float64 `json:"uptime"`
	Connections int     `json:"connections"`
	GoVersion   string  `json:"go_version"`
}

// SecurityStatusResponse represents security status information
type SecurityStatusResponse struct {
	MFAEnabled      bool   `json:"mfa_enabled"`
	LastLogin       string `json:"last_login"`
	ActiveSessions  int    `json:"active_sessions"`
	SecurityAlerts  int    `json:"security_alerts"`
	PasswordChanged string `json:"password_changed"`
}

// RateLimitResponse represents rate limit information
type RateLimitResponse struct {
	Error             string `json:"error"`
	RequestsPerMinute int    `json:"requests_per_minute"`
	LimitPerMinute    int    `json:"limit_per_minute"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
	Message           string `json:"message"`
}
