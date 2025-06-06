package main

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// User represents a system user
type User struct {
	ID              string     `json:"id" db:"id"`
	Email           string     `json:"email" db:"email"`
	Password        string     `json:"-" db:"password"`
	FirstName       string     `json:"first_name" db:"first_name"`
	LastName        string     `json:"last_name" db:"last_name"`
	Role            string     `json:"role" db:"role"`
	Active          bool       `json:"active" db:"active"`
	MFAEnabled      bool       `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret       string     `json:"-" db:"mfa_secret"`
	BackupCodes     []string   `json:"-" db:"backup_codes"`
	LastLogin       *time.Time `json:"last_login" db:"last_login"`
	PasswordChanged time.Time  `json:"password_changed" db:"password_changed"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}

// Service represents a monitored service
type Service struct {
	ID          string     `json:"id" db:"id"`
	UserID      string     `json:"user_id" db:"user_id"`
	Name        string     `json:"name" db:"name"`
	URL         string     `json:"url" db:"url"`
	Type        string     `json:"type" db:"type"`
	Enabled     bool       `json:"enabled" db:"enabled"`
	Status      string     `json:"status" db:"status"`
	Latency     *int       `json:"latency" db:"latency"`
	PingLatency *int       `json:"ping_latency" db:"ping_latency"`
	LastChecked *time.Time `json:"last_checked" db:"last_checked"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	Encrypted   bool       `json:"encrypted" db:"encrypted"`
}

// Alert represents an alert configuration
type Alert struct {
	ID            string     `json:"id" db:"id"`
	UserID        string     `json:"user_id" db:"user_id"`
	Name          string     `json:"name" db:"name"`
	Description   string     `json:"description" db:"description"`
	ServiceIDs    []string   `json:"service_ids" db:"service_ids"`
	Condition     string     `json:"condition" db:"condition"`
	Operator      string     `json:"operator" db:"operator"`
	Value         string     `json:"value" db:"value"`
	Enabled       bool       `json:"enabled" db:"enabled"`
	Notifications []string   `json:"notifications" db:"notifications"`
	Cooldown      int        `json:"cooldown" db:"cooldown"`
	Severity      string     `json:"severity" db:"severity"`
	Created       time.Time  `json:"created" db:"created"`
	LastTriggered *time.Time `json:"last_triggered" db:"last_triggered"`
	TriggerCount  int        `json:"trigger_count" db:"trigger_count"`
}

// AlertTrigger represents an alert trigger event
type AlertTrigger struct {
	ID        string     `json:"id" db:"id"`
	AlertID   string     `json:"alert_id" db:"alert_id"`
	ServiceID string     `json:"service_id" db:"service_id"`
	Message   string     `json:"message" db:"message"`
	Severity  string     `json:"severity" db:"severity"`
	Triggered time.Time  `json:"triggered" db:"triggered"`
	Resolved  *time.Time `json:"resolved" db:"resolved"`
}

// NotificationSettings represents user notification preferences
type NotificationSettings struct {
	ID             string    `json:"id" db:"id"`
	UserID         string    `json:"user_id" db:"user_id"`
	EmailEnabled   bool      `json:"email_enabled" db:"email_enabled"`
	EmailAddress   string    `json:"email_address" db:"email_address"`
	EmailVerified  bool      `json:"email_verified" db:"email_verified"`
	SMSEnabled     bool      `json:"sms_enabled" db:"sms_enabled"`
	SMSNumber      string    `json:"sms_number" db:"sms_number"`
	SMSVerified    bool      `json:"sms_verified" db:"sms_verified"`
	SlackEnabled   bool      `json:"slack_enabled" db:"slack_enabled"`
	SlackWebhook   string    `json:"slack_webhook" db:"slack_webhook"`
	SlackChannel   string    `json:"slack_channel" db:"slack_channel"`
	WebhookEnabled bool      `json:"webhook_enabled" db:"webhook_enabled"`
	WebhookURL     string    `json:"webhook_url" db:"webhook_url"`
	WebhookMethod  string    `json:"webhook_method" db:"webhook_method"`
	Updated        time.Time `json:"updated" db:"updated"`
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

// CreateAlertRequest represents an alert creation request
type CreateAlertRequest struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	ServiceIDs    []string `json:"service_ids"`
	Condition     string   `json:"condition"`
	Operator      string   `json:"operator"`
	Value         string   `json:"value"`
	Enabled       bool     `json:"enabled"`
	Notifications []string `json:"notifications"`
	Cooldown      int      `json:"cooldown"`
	Severity      string   `json:"severity"`
}

// UpdateAlertRequest represents an alert update request
type UpdateAlertRequest struct {
	Name          string   `json:"name,omitempty"`
	Description   string   `json:"description,omitempty"`
	ServiceIDs    []string `json:"service_ids,omitempty"`
	Condition     string   `json:"condition,omitempty"`
	Operator      string   `json:"operator,omitempty"`
	Value         string   `json:"value,omitempty"`
	Enabled       *bool    `json:"enabled,omitempty"`
	Notifications []string `json:"notifications,omitempty"`
	Cooldown      *int     `json:"cooldown,omitempty"`
	Severity      string   `json:"severity,omitempty"`
}

// UpdateNotificationSettingsRequest represents notification settings update
type UpdateNotificationSettingsRequest struct {
	EmailEnabled   *bool  `json:"email_enabled,omitempty"`
	EmailAddress   string `json:"email_address,omitempty"`
	SMSEnabled     *bool  `json:"sms_enabled,omitempty"`
	SMSNumber      string `json:"sms_number,omitempty"`
	SlackEnabled   *bool  `json:"slack_enabled,omitempty"`
	SlackWebhook   string `json:"slack_webhook,omitempty"`
	SlackChannel   string `json:"slack_channel,omitempty"`
	WebhookEnabled *bool  `json:"webhook_enabled,omitempty"`
	WebhookURL     string `json:"webhook_url,omitempty"`
	WebhookMethod  string `json:"webhook_method,omitempty"`
}

// ServiceStatusMessage represents a WebSocket service status message
type ServiceStatusMessage struct {
	Type        string     `json:"type"`
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	URL         string     `json:"url"`
	ServiceType string     `json:"service_type"`
	Status      string     `json:"status"`
	Latency     *int       `json:"latency"`
	PingLatency *int       `json:"ping_latency"`
	LastChecked *time.Time `json:"last_checked"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string                 `json:"error"`
	Message string                 `json:"message,omitempty"`
	Code    string                 `json:"code,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// HealthResponse represents a health check response
type HealthResponse struct {
	Status      string                 `json:"status"`
	Timestamp   string                 `json:"timestamp"`
	Version     string                 `json:"version"`
	Uptime      float64                `json:"uptime"`
	Connections int                    `json:"connections"`
	GoVersion   string                 `json:"go_version"`
	Services    map[string]interface{} `json:"services"`
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

// Validation helper methods

// IsValidAlertCondition checks if the alert condition is valid
func IsValidAlertCondition(condition string) bool {
	valid := []string{"status", "latency", "ping_latency", "multiple_down"}
	for _, v := range valid {
		if v == condition {
			return true
		}
	}
	return false
}

// IsValidAlertOperator checks if the alert operator is valid
func IsValidAlertOperator(operator string) bool {
	valid := []string{"equals", "not_equals", "greater_than", "less_than", "greater_equal", "less_equal"}
	for _, v := range valid {
		if v == operator {
			return true
		}
	}
	return false
}

// IsValidSeverity checks if the severity level is valid
func IsValidSeverity(severity string) bool {
	valid := []string{"info", "warning", "critical"}
	for _, v := range valid {
		if v == severity {
			return true
		}
	}
	return false
}

// IsValidNotificationType checks if the notification type is valid
func IsValidNotificationType(notificationType string) bool {
	valid := []string{"email", "sms", "slack", "webhook"}
	for _, v := range valid {
		if v == notificationType {
			return true
		}
	}
	return false
}
