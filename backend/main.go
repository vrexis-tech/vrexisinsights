package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"golang.org/x/crypto/bcrypt"
)

// =============================================================================
// MODELS
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
	// Email configuration
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	EmailFrom    string
}

type User struct {
	ID                 string    `json:"id"`
	Email              string    `json:"email"`
	Password           string    `json:"password,omitempty"`
	FirstName          string    `json:"first_name"`
	LastName           string    `json:"last_name"`
	EmailNotifications bool      `json:"email_notifications"`
	CreatedAt          time.Time `json:"created_at"`
}

type Service struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	PrevStatus  string    `json:"-"` // For tracking status changes
	Latency     int       `json:"latency"`
	LastChecked time.Time `json:"last_checked"`
	CreatedAt   time.Time `json:"created_at"`
}

type ServiceCheck struct {
	ID           string    `json:"id"`
	ServiceID    string    `json:"service_id"`
	Status       string    `json:"status"`
	ResponseTime int       `json:"response_time"`
	CheckedAt    time.Time `json:"checked_at"`
}

type CreateServiceRequest struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Type string `json:"type"`
}

type ServiceStats struct {
	TotalServices int     `json:"total_services"`
	ServicesUp    int     `json:"services_up"`
	ServicesDown  int     `json:"services_down"`
	AvgUptime     float64 `json:"avg_uptime"`
	AvgLatency    int     `json:"avg_latency"`
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

type UpdateEmailNotificationsRequest struct {
	EmailNotifications bool `json:"email_notifications"`
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

type PingResult struct {
	Success      bool
	ResponseTime time.Duration
	Error        string
}

type RateLimiter struct {
	requests map[string][]time.Time
	mutex    sync.RWMutex
	window   time.Duration
	maxReqs  int
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// =============================================================================
// GLOBAL VARIABLES
// =============================================================================

var globalDB *sql.DB
var emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)

// =============================================================================
// CONFIGURATION
// =============================================================================

func loadConfig() *Config {
	config := &Config{
		Port:             getEnv("PORT", "8080"),
		DBPath:           getEnv("DB_PATH", "vrexis_insights.db"),
		JWTSecret:        getEnv("JWT_SECRET", ""),
		JWTRefreshSecret: getEnv("JWT_REFRESH_SECRET", ""),
		Environment:      getEnv("ENVIRONMENT", "development"),
		LogLevel:         getEnv("LOG_LEVEL", "info"),
		RateLimitWindow:  time.Minute * 15,
		RateLimitMax:     5,
		// Email configuration
		SMTPHost:     getEnv("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:     getEnv("SMTP_PORT", "587"),
		SMTPUsername: getEnv("SMTP_USERNAME", ""),
		SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		EmailFrom:    getEnv("EMAIL_FROM", ""),
	}

	originsStr := getEnv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
	config.AllowedOrigins = strings.Split(originsStr, ",")

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

	if config.Environment == "production" {
		if len(config.JWTSecret) < 32 {
			log.Fatal("❌ JWT_SECRET must be at least 32 characters in production")
		}
		if strings.Contains(originsStr, "localhost") {
			log.Println("⚠️  Warning: localhost origins detected in production")
		}
	}

	// Email configuration warnings
	if config.SMTPUsername == "" || config.SMTPPassword == "" {
		log.Println("⚠️  Email notifications disabled - SMTP credentials not configured")
		log.Println("   Set SMTP_USERNAME and SMTP_PASSWORD to enable email notifications")
	}

	if config.EmailFrom == "" {
		config.EmailFrom = config.SMTPUsername
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
// EMAIL FUNCTIONS
// =============================================================================

func isEmailConfigured(config *Config) bool {
	return config.SMTPUsername != "" && config.SMTPPassword != "" && config.SMTPHost != ""
}

func sendEmail(config *Config, to, subject, body string) error {
	if !isEmailConfigured(config) {
		log.Printf("📧 Email notification skipped - SMTP not configured")
		return nil
	}

	from := config.EmailFrom
	if from == "" {
		from = config.SMTPUsername
	}

	msg := []byte("To: " + to + "\r\n" +
		"From: " + from + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"\r\n" +
		body + "\r\n")

	auth := smtp.PlainAuth("", config.SMTPUsername, config.SMTPPassword, config.SMTPHost)
	addr := config.SMTPHost + ":" + config.SMTPPort

	err := smtp.SendMail(addr, auth, from, []string{to}, msg)
	if err != nil {
		log.Printf("📧 Failed to send email to %s: %v", to, err)
		return err
	}

	log.Printf("📧 Email sent successfully to %s: %s", to, subject)
	return nil
}

func sendServiceAlert(config *Config, user *User, service *Service, isDown bool) {
	if !user.EmailNotifications {
		return
	}

	var subject, body string

	if isDown {
		subject = fmt.Sprintf("🚨 Service Alert: %s is DOWN", service.Name)
		body = fmt.Sprintf(`
			<html>
			<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
				<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
					<div style="background: #fee; border-left: 4px solid #f56565; padding: 20px; margin-bottom: 20px;">
						<h2 style="color: #f56565; margin: 0 0 10px 0;">🚨 Service Down Alert</h2>
						<p style="margin: 0; font-size: 16px;">Your service <strong>%s</strong> is currently down.</p>
					</div>
					
					<div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
						<h3 style="margin: 0 0 10px 0;">Service Details:</h3>
						<p style="margin: 5px 0;"><strong>Name:</strong> %s</p>
						<p style="margin: 5px 0;"><strong>URL:</strong> %s</p>
						<p style="margin: 5px 0;"><strong>Type:</strong> %s</p>
						<p style="margin: 5px 0;"><strong>Time:</strong> %s</p>
					</div>
					
					<p style="color: #666;">This alert was sent from your VREXIS Insights monitoring dashboard.</p>
					<p style="color: #666; font-size: 14px;">To manage your notification preferences, please log in to your dashboard.</p>
				</div>
			</body>
			</html>`,
			service.Name, service.Name, service.URL, service.Type,
			time.Now().Format("January 2, 2006 at 3:04 PM MST"))
	} else {
		subject = fmt.Sprintf("✅ Service Restored: %s is UP", service.Name)
		body = fmt.Sprintf(`
			<html>
			<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
				<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
					<div style="background: #eef; border-left: 4px solid #48bb78; padding: 20px; margin-bottom: 20px;">
						<h2 style="color: #48bb78; margin: 0 0 10px 0;">✅ Service Restored</h2>
						<p style="margin: 0; font-size: 16px;">Your service <strong>%s</strong> is back online.</p>
					</div>
					
					<div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
						<h3 style="margin: 0 0 10px 0;">Service Details:</h3>
						<p style="margin: 5px 0;"><strong>Name:</strong> %s</p>
						<p style="margin: 5px 0;"><strong>URL:</strong> %s</p>
						<p style="margin: 5px 0;"><strong>Type:</strong> %s</p>
						<p style="margin: 5px 0;"><strong>Restored:</strong> %s</p>
					</div>
					
					<p style="color: #666;">This alert was sent from your VREXIS Insights monitoring dashboard.</p>
					<p style="color: #666; font-size: 14px;">To manage your notification preferences, please log in to your dashboard.</p>
				</div>
			</body>
			</html>`,
			service.Name, service.Name, service.URL, service.Type,
			time.Now().Format("January 2, 2006 at 3:04 PM MST"))
	}

	go func() {
		if err := sendEmail(config, user.Email, subject, body); err != nil {
			log.Printf("Failed to send email alert for service %s: %v", service.Name, err)
		}
	}()
}

// =============================================================================
// NETWORK TESTING FUNCTIONS
// =============================================================================

func pingHost(host string, timeout time.Duration) *PingResult {
	result := &PingResult{}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		timeoutMs := int(timeout.Milliseconds())
		cmd = exec.Command("ping", "-n", "1", "-w", strconv.Itoa(timeoutMs), host)
	case "darwin":
		timeoutMs := int(timeout.Milliseconds())
		cmd = exec.Command("ping", "-c", "1", "-W", strconv.Itoa(timeoutMs), host)
	default:
		timeoutSec := int(timeout.Seconds())
		if timeoutSec < 1 {
			timeoutSec = 1
		}
		cmd = exec.Command("ping", "-c", "1", "-W", strconv.Itoa(timeoutSec), host)
	}

	start := time.Now()
	output, err := cmd.Output()
	responseTime := time.Since(start)

	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Ping failed: %v", err)
		result.ResponseTime = responseTime
		return result
	}

	outputStr := string(output)
	if strings.Contains(outputStr, "Request timed out") ||
		strings.Contains(outputStr, "Destination host unreachable") ||
		strings.Contains(outputStr, "100% packet loss") {
		result.Success = false
		result.Error = "Host unreachable"
	} else if strings.Contains(outputStr, "TTL=") ||
		strings.Contains(outputStr, "ttl=") ||
		strings.Contains(outputStr, "64 bytes from") ||
		strings.Contains(outputStr, "1 packets transmitted, 1 received") {
		result.Success = true
	} else {
		result.Success = false
		result.Error = "Unknown ping response"
	}

	result.ResponseTime = responseTime
	return result
}

func testTCPConnection(host string, port int, timeout time.Duration) *PingResult {
	result := &PingResult{}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	responseTime := time.Since(start)

	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("TCP connection failed: %v", err)
		result.ResponseTime = responseTime
		return result
	}

	conn.Close()
	result.Success = true
	result.ResponseTime = responseTime
	return result
}

func parseHostPort(url string) (string, int) {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")

	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	if strings.Contains(url, ":") {
		parts := strings.Split(url, ":")
		host := parts[0]
		if len(parts) > 1 {
			if port, err := strconv.Atoi(parts[1]); err == nil {
				return host, port
			}
		}
	}

	return url, 80
}

// =============================================================================
// SERVICE MONITORING
// =============================================================================

func checkServiceHealthEnhanced(service *Service) (*ServiceCheck, error) {
	start := time.Now()

	check := &ServiceCheck{
		ID:        uuid.New().String(),
		ServiceID: service.ID,
		CheckedAt: time.Now(),
	}

	log.Printf("🔍 Checking service: %s (%s) - Type: %s", service.Name, service.URL, service.Type)

	switch service.Type {
	case "website":
		return checkWebsiteHealthEnhanced(service, check, start)
	case "server":
		return checkServerHealthEnhanced(service, check, start)
	case "iot":
		return checkIoTHealthEnhanced(service, check, start)
	default:
		return checkWebsiteHealthEnhanced(service, check, start)
	}
}

func checkWebsiteHealthEnhanced(service *Service, check *ServiceCheck, start time.Time) (*ServiceCheck, error) {
	url := service.URL
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	log.Printf("📡 HTTP check for %s: %s", service.Name, url)

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	resp, err := client.Get(url)
	responseTime := int(time.Since(start).Milliseconds())
	check.ResponseTime = responseTime

	if err != nil {
		log.Printf("❌ HTTP failed for %s: %v", service.Name, err)
		check.Status = "down"
		return check, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		log.Printf("✅ HTTP success for %s: %d (%dms)", service.Name, resp.StatusCode, responseTime)
		check.Status = "up"
	} else {
		log.Printf("⚠️  HTTP error for %s: %d", service.Name, resp.StatusCode)
		check.Status = "down"
	}

	return check, nil
}

func checkServerHealthEnhanced(service *Service, check *ServiceCheck, start time.Time) (*ServiceCheck, error) {
	host, port := parseHostPort(service.URL)

	log.Printf("🖥️  Server check for %s: %s:%d", service.Name, host, port)

	if port == 80 || port == 443 || port == 8080 || port == 3000 {
		url := service.URL
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			if port == 443 {
				url = "https://" + url
			} else {
				url = "http://" + url
			}
		}

		log.Printf("📡 HTTP check for %s: %s", service.Name, url)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(url)
		responseTime := int(time.Since(start).Milliseconds())
		check.ResponseTime = responseTime

		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode < 500 {
				log.Printf("✅ HTTP success for %s: %d (%dms)", service.Name, resp.StatusCode, responseTime)
				check.Status = "up"
				return check, nil
			}
		}
		log.Printf("⚠️  HTTP failed for %s: %v", service.Name, err)
	}

	log.Printf("🏓 Ping check for %s: %s", service.Name, host)
	pingResult := pingHost(host, 3*time.Second)

	if pingResult.Success {
		log.Printf("✅ Ping success for %s (%v)", service.Name, pingResult.ResponseTime)
		check.Status = "up"
		check.ResponseTime = int(pingResult.ResponseTime.Milliseconds())
		return check, nil
	}

	log.Printf("❌ Ping failed for %s: %s", service.Name, pingResult.Error)
	return checkTCPConnectionEnhanced(service, check, start, host, port)
}

func checkIoTHealthEnhanced(service *Service, check *ServiceCheck, start time.Time) (*ServiceCheck, error) {
	host, port := parseHostPort(service.URL)

	log.Printf("📱 IoT check for %s: %s:%d", service.Name, host, port)

	log.Printf("🏓 Ping check for %s: %s", service.Name, host)
	pingResult := pingHost(host, 2*time.Second)

	if pingResult.Success {
		log.Printf("✅ Ping success for %s (%v)", service.Name, pingResult.ResponseTime)
		check.Status = "up"
		check.ResponseTime = int(pingResult.ResponseTime.Milliseconds())
		return check, nil
	}

	log.Printf("❌ Ping failed for %s: %s", service.Name, pingResult.Error)

	if port == 80 || port == 443 || port == 8080 {
		url := service.URL
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}

		log.Printf("📡 HTTP check for %s: %s", service.Name, url)

		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(url)
		responseTime := int(time.Since(start).Milliseconds())
		check.ResponseTime = responseTime

		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode < 500 {
				log.Printf("✅ HTTP success for %s: %d (%dms)", service.Name, resp.StatusCode, responseTime)
				check.Status = "up"
				return check, nil
			}
		}
		log.Printf("⚠️  HTTP failed for %s: %v", service.Name, err)
	}

	return checkTCPConnectionEnhanced(service, check, start, host, port)
}

func checkTCPConnectionEnhanced(service *Service, check *ServiceCheck, start time.Time, host string, port int) (*ServiceCheck, error) {
	log.Printf("🔌 TCP check for %s: %s:%d", service.Name, host, port)

	tcpResult := testTCPConnection(host, port, 3*time.Second)

	if tcpResult.Success {
		log.Printf("✅ TCP success for %s: %s:%d (%v)", service.Name, host, port, tcpResult.ResponseTime)
		check.Status = "up"
		check.ResponseTime = int(tcpResult.ResponseTime.Milliseconds())
		return check, nil
	}

	commonPorts := []int{22, 23, 80, 443, 8080}
	for _, tryPort := range commonPorts {
		if tryPort == port {
			continue
		}

		log.Printf("🔌 TCP check for %s: %s:%d (fallback)", service.Name, host, tryPort)
		tcpResult := testTCPConnection(host, tryPort, 1*time.Second)

		if tcpResult.Success {
			log.Printf("✅ TCP success for %s: %s:%d (%v)", service.Name, host, tryPort, tcpResult.ResponseTime)
			check.Status = "up"
			check.ResponseTime = int(tcpResult.ResponseTime.Milliseconds())
			return check, nil
		}
	}

	log.Printf("❌ All connection attempts failed for %s", service.Name)
	check.Status = "down"
	check.ResponseTime = int(time.Since(start).Milliseconds())
	return check, nil
}

func startServiceMonitor(db *sql.DB, config *Config) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	log.Println("🔍 Service monitor started")

	for {
		select {
		case <-ticker.C:
			services, err := getAllServices(context.Background(), db)
			if err != nil {
				log.Printf("Error fetching services for monitoring: %v", err)
				continue
			}

			log.Printf("🔍 Monitoring %d services", len(services))

			for _, service := range services {
				go func(s Service) {
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()

					done := make(chan bool, 1)
					var check *ServiceCheck
					var err error

					go func() {
						check, err = checkServiceHealthEnhanced(&s)
						done <- true
					}()

					select {
					case <-done:
						if err != nil {
							log.Printf("Error checking service %s: %v", s.Name, err)
							return
						}

						if err := saveServiceCheck(ctx, db, check); err != nil {
							log.Printf("Error saving check for service %s: %v", s.Name, err)
							return
						}

						// Check for status changes and send email alerts
						if s.Status != "" && s.Status != check.Status {
							user, err := getUserByID(ctx, s.UserID)
							if err == nil {
								if check.Status == "down" && s.Status == "up" {
									sendServiceAlert(config, user, &s, true) // Service went down
								} else if check.Status == "up" && s.Status == "down" {
									sendServiceAlert(config, user, &s, false) // Service came back up
								}
							}
						}

						if err := updateServiceStatus(ctx, db, s.ID, check.Status, check.ResponseTime); err != nil {
							log.Printf("Error updating service status for %s: %v", s.Name, err)
						}
					case <-ctx.Done():
						log.Printf("⏰ Timeout checking service %s", s.Name)
					}
				}(service)
			}
		}
	}
}

// =============================================================================
// DATA CLEANUP
// =============================================================================

func cleanupOldData(db *sql.DB) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	log.Println("🧹 Data cleanup service started")

	for {
		select {
		case <-ticker.C:
			// Delete old service checks (keep 24 hours for free tier)
			result, err := db.Exec(`DELETE FROM service_checks 
								  WHERE checked_at < datetime('now', '-1 day')`)
			if err != nil {
				log.Printf("Error cleaning up old service checks: %v", err)
			} else {
				rowsAffected, _ := result.RowsAffected()
				if rowsAffected > 0 {
					log.Printf("🧹 Cleaned up %d old service check records", rowsAffected)
				}
			}
		}
	}
}

// =============================================================================
// RATE LIMITING
// =============================================================================

func NewRateLimiter(window time.Duration, maxReqs int) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		window:   window,
		maxReqs:  maxReqs,
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	requests := rl.requests[key]
	validRequests := make([]time.Time, 0)
	for _, reqTime := range requests {
		if reqTime.After(cutoff) {
			validRequests = append(validRequests, reqTime)
		}
	}

	if len(validRequests) >= rl.maxReqs {
		rl.requests[key] = validRequests
		return false
	}

	validRequests = append(validRequests, now)
	rl.requests[key] = validRequests
	return true
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			func() {
				rl.mutex.Lock()
				defer rl.mutex.Unlock()

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
			}()
		}
	}
}

// =============================================================================
// MIDDLEWARE
// =============================================================================

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:")

		if r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

func httpsRedirectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			key := getClientIP(r)

			if !limiter.Allow(key) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "900")
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
		if r.ContentLength > 1024*1024 {
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
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

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

		logJSON, _ := json.Marshal(logEntry)
		log.Printf("HTTP %s", string(logJSON))
	})
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
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")
	input = strings.ReplaceAll(input, "\"", "&quot;")
	input = strings.ReplaceAll(input, "'", "&#x27;")
	input = strings.ReplaceAll(input, "&", "&amp;")

	input = strings.TrimSpace(input)
	if len(input) > maxLength {
		input = input[:maxLength]
	}

	return input
}

// =============================================================================
// DATABASE
// =============================================================================

func initDatabase(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	_, err = db.Exec("PRAGMA journal_mode=WAL")
	if err != nil {
		log.Printf("Warning: Could not enable WAL mode: %v", err)
	}

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
		email_notifications BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	serviceTable := `
	CREATE TABLE IF NOT EXISTS services (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		url TEXT NOT NULL,
		type TEXT NOT NULL DEFAULT 'website',
		status TEXT DEFAULT 'unknown',
		latency INTEGER DEFAULT 0,
		last_checked DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
	);`

	serviceChecksTable := `
	CREATE TABLE IF NOT EXISTS service_checks (
		id TEXT PRIMARY KEY,
		service_id TEXT NOT NULL,
		status TEXT NOT NULL,
		response_time INTEGER DEFAULT 0,
		checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (service_id) REFERENCES services (id) ON DELETE CASCADE
	);`

	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
		"CREATE INDEX IF NOT EXISTS idx_services_user_id ON services(user_id);",
		"CREATE INDEX IF NOT EXISTS idx_services_status ON services(status);",
		"CREATE INDEX IF NOT EXISTS idx_service_checks_service_id ON service_checks(service_id);",
		"CREATE INDEX IF NOT EXISTS idx_service_checks_checked_at ON service_checks(checked_at);",
	}

	tables := []string{userTable, serviceTable, serviceChecksTable}
	for _, table := range tables {
		if _, err := db.Exec(table); err != nil {
			return err
		}
	}

	for _, indexSQL := range indexes {
		if _, err := db.Exec(indexSQL); err != nil {
			log.Printf("Warning: Could not create index: %v", err)
		}
	}

	// Add email_notifications column if it doesn't exist (for existing databases)
	_, err := db.Exec("ALTER TABLE users ADD COLUMN email_notifications BOOLEAN DEFAULT 1")
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("Warning: Could not add email_notifications column: %v", err)
	}

	return nil
}

func getUserByEmail(ctx context.Context, email string) (*User, error) {
	query := `SELECT id, email, password, first_name, last_name, COALESCE(email_notifications, 1), created_at FROM users WHERE email = ?`
	var user User
	err := globalDB.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName, &user.EmailNotifications, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to query user: %w", err)
	}
	return &user, nil
}

func getUserByID(ctx context.Context, userID string) (*User, error) {
	query := `SELECT id, email, password, first_name, last_name, COALESCE(email_notifications, 1), created_at FROM users WHERE id = ?`
	var user User
	err := globalDB.QueryRowContext(ctx, query, userID).Scan(
		&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName, &user.EmailNotifications, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to query user: %w", err)
	}
	return &user, nil
}

func createUser(ctx context.Context, user *User) error {
	query := `INSERT INTO users (id, email, password, first_name, last_name, email_notifications, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := globalDB.ExecContext(ctx, query, user.ID, user.Email, user.Password, user.FirstName, user.LastName, user.EmailNotifications, user.CreatedAt)
	return err
}

func updateUserEmailNotifications(ctx context.Context, userID string, emailNotifications bool) error {
	query := `UPDATE users SET email_notifications = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := globalDB.ExecContext(ctx, query, emailNotifications, userID)
	return err
}

func createService(ctx context.Context, db *sql.DB, service *Service) error {
	query := `INSERT INTO services (id, user_id, name, url, type, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := db.ExecContext(ctx, query, service.ID, service.UserID, service.Name, service.URL, service.Type, service.Status, service.CreatedAt)
	return err
}

func getServicesByUserID(ctx context.Context, db *sql.DB, userID string) ([]Service, error) {
	query := `SELECT id, user_id, name, url, type, status, latency, last_checked, created_at FROM services WHERE user_id = ? ORDER BY created_at DESC`
	rows, err := db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []Service
	for rows.Next() {
		var service Service
		var lastChecked sql.NullTime
		err := rows.Scan(&service.ID, &service.UserID, &service.Name, &service.URL, &service.Type, &service.Status, &service.Latency, &lastChecked, &service.CreatedAt)
		if err != nil {
			return nil, err
		}
		if lastChecked.Valid {
			service.LastChecked = lastChecked.Time
		}
		services = append(services, service)
	}
	return services, nil
}

func getAllServices(ctx context.Context, db *sql.DB) ([]Service, error) {
	query := `SELECT id, user_id, name, url, type, status, latency, last_checked, created_at FROM services`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []Service
	for rows.Next() {
		var service Service
		var lastChecked sql.NullTime
		err := rows.Scan(&service.ID, &service.UserID, &service.Name, &service.URL, &service.Type, &service.Status, &service.Latency, &lastChecked, &service.CreatedAt)
		if err != nil {
			return nil, err
		}
		if lastChecked.Valid {
			service.LastChecked = lastChecked.Time
		}
		services = append(services, service)
	}
	return services, nil
}

func deleteService(ctx context.Context, db *sql.DB, serviceID, userID string) error {
	query := `DELETE FROM services WHERE id = ? AND user_id = ?`
	result, err := db.ExecContext(ctx, query, serviceID, userID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("service not found or not owned by user")
	}

	return nil
}

func saveServiceCheck(ctx context.Context, db *sql.DB, check *ServiceCheck) error {
	query := `INSERT INTO service_checks (id, service_id, status, response_time, checked_at) VALUES (?, ?, ?, ?, ?)`
	_, err := db.ExecContext(ctx, query, check.ID, check.ServiceID, check.Status, check.ResponseTime, check.CheckedAt)
	return err
}

func updateServiceStatus(ctx context.Context, db *sql.DB, serviceID, status string, latency int) error {
	query := `UPDATE services SET status = ?, latency = ?, last_checked = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := db.ExecContext(ctx, query, status, latency, serviceID)
	return err
}

func getServiceStats(ctx context.Context, db *sql.DB, userID string) (*ServiceStats, error) {
	query := `SELECT COUNT(*) as total, 
				SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) as up_count,
				AVG(latency) as avg_latency
			 FROM services WHERE user_id = ?`

	var stats ServiceStats
	var avgLatency sql.NullFloat64

	err := db.QueryRowContext(ctx, query, userID).Scan(&stats.TotalServices, &stats.ServicesUp, &avgLatency)
	if err != nil {
		return nil, err
	}

	stats.ServicesDown = stats.TotalServices - stats.ServicesUp
	if avgLatency.Valid {
		stats.AvgLatency = int(avgLatency.Float64)
	}

	if stats.TotalServices > 0 {
		stats.AvgUptime = float64(stats.ServicesUp) / float64(stats.TotalServices) * 100
	}

	return &stats, nil
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
// HANDLERS
// =============================================================================

func healthHandler(w http.ResponseWriter, r *http.Request) {
	checks := make(map[string]string)

	if err := globalDB.Ping(); err != nil {
		checks["database"] = "unhealthy: " + err.Error()
	} else {
		checks["database"] = "healthy"
	}

	if stat, err := os.Stat("."); err != nil {
		checks["filesystem"] = "unhealthy: " + err.Error()
	} else {
		checks["filesystem"] = "healthy"
		_ = stat
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
		Version:     "1.0.0",
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

		user, err := getUserByEmail(r.Context(), req.Email)
		if err != nil {
			log.Printf("Failed login attempt for email: %s from IP: %s", req.Email, getClientIP(r))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Invalid email or password",
				Code:  "INVALID_CREDENTIALS",
			})
			return
		}

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

		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    refreshToken,
			Path:     "/",
			MaxAge:   int((time.Hour * 24 * 7).Seconds()),
			HttpOnly: true,
			Secure:   config.Environment == "production",
			SameSite: http.SameSiteStrictMode,
		})

		user.Password = ""
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

		req.Email = sanitizeString(strings.ToLower(req.Email), 255)
		req.FirstName = sanitizeString(req.FirstName, 50)
		req.LastName = sanitizeString(req.LastName, 50)
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

		if err := validatePassword(req.Password); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: err.Error(),
				Code:  "WEAK_PASSWORD",
			})
			return
		}

		if len(req.FirstName) < 1 || len(req.LastName) < 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "First name and last name are required",
				Code:  "MISSING_REQUIRED_FIELDS",
			})
			return
		}

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

		user := &User{
			ID:                 uuid.New().String(),
			Email:              req.Email,
			Password:           string(hashedPassword),
			FirstName:          req.FirstName,
			LastName:           req.LastName,
			EmailNotifications: true, // Default to enabled
			CreatedAt:          time.Now(),
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

		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    refreshToken,
			Path:     "/",
			MaxAge:   int((time.Hour * 24 * 7).Seconds()),
			HttpOnly: true,
			Secure:   config.Environment == "production",
			SameSite: http.SameSiteStrictMode,
		})

		user.Password = ""
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

func updateEmailNotificationsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(string)

	var req UpdateEmailNotificationsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "Invalid request format",
			Code:  "INVALID_JSON",
		})
		return
	}

	if err := updateUserEmailNotifications(r.Context(), userID, req.EmailNotifications); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "Failed to update email notification settings",
			Code:  "UPDATE_FAILED",
		})
		return
	}

	// Get updated user
	user, err := getUserByID(r.Context(), userID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "Failed to fetch updated user",
			Code:  "FETCH_USER_FAILED",
		})
		return
	}

	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func getServicesHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value("userID").(string)

		services, err := getServicesByUserID(r.Context(), db, userID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Failed to fetch services",
				Code:  "FETCH_SERVICES_FAILED",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(services)
	}
}

func createServiceHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value("userID").(string)

		var req CreateServiceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Invalid request format",
				Code:  "INVALID_JSON",
			})
			return
		}

		req.Name = sanitizeString(req.Name, 100)
		req.URL = sanitizeString(req.URL, 255)
		req.Type = sanitizeString(req.Type, 20)

		if req.Name == "" || req.URL == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Name and URL are required",
				Code:  "MISSING_REQUIRED_FIELDS",
			})
			return
		}

		if req.Type == "" {
			req.Type = "website"
		}
		validTypes := map[string]bool{"website": true, "server": true, "iot": true}
		if !validTypes[req.Type] {
			req.Type = "website"
		}

		existingServices, err := getServicesByUserID(r.Context(), db, userID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Failed to check service limit",
				Code:  "SERVICE_LIMIT_CHECK_FAILED",
			})
			return
		}

		if len(existingServices) >= 5 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Service limit reached. Free tier allows up to 5 services.",
				Code:  "SERVICE_LIMIT_REACHED",
			})
			return
		}

		service := &Service{
			ID:        uuid.New().String(),
			UserID:    userID,
			Name:      req.Name,
			URL:       req.URL,
			Type:      req.Type,
			Status:    "checking",
			CreatedAt: time.Now(),
		}

		if err := createService(r.Context(), db, service); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Failed to create service",
				Code:  "SERVICE_CREATION_FAILED",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(service)
	}
}

func deleteServiceHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value("userID").(string)
		serviceID := mux.Vars(r)["id"]

		if err := deleteService(r.Context(), db, serviceID, userID); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Service not found",
				Code:  "SERVICE_NOT_FOUND",
			})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func getServiceStatsHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value("userID").(string)

		stats, err := getServiceStats(r.Context(), db, userID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Failed to fetch service statistics",
				Code:  "STATS_FETCH_FAILED",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	}
}

func setupRoutes(config *Config, db *sql.DB) http.Handler {
	r := mux.NewRouter()

	authLimiter := NewRateLimiter(config.RateLimitWindow, config.RateLimitMax)

	r.Use(securityHeadersMiddleware)
	r.Use(httpsRedirectMiddleware)
	r.Use(loggingMiddleware)
	r.Use(validationMiddleware)

	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/api/health", healthHandler).Methods("GET")

	authRouter := r.PathPrefix("/auth").Subrouter()
	authRouter.Use(rateLimitMiddleware(authLimiter))
	authRouter.HandleFunc("/login", loginHandler(config)).Methods("POST")
	authRouter.HandleFunc("/register", registerHandler(config)).Methods("POST")

	apiRouter := r.PathPrefix("/api/v1").Subrouter()
	apiRouter.Use(jwtMiddleware(config))

	apiRouter.HandleFunc("/services", getServicesHandler(db)).Methods("GET")
	apiRouter.HandleFunc("/services", createServiceHandler(db)).Methods("POST")
	apiRouter.HandleFunc("/services/{id}", deleteServiceHandler(db)).Methods("DELETE")
	apiRouter.HandleFunc("/services/stats", getServiceStatsHandler(db)).Methods("GET")
	apiRouter.HandleFunc("/user/email-notifications", updateEmailNotificationsHandler).Methods("PUT")

	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   config.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           300,
	}).Handler(r)

	return corsHandler
}

func createDemoUser(config *Config) {
	if config.Environment == "production" {
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error creating demo user: %v", err)
		return
	}

	user := &User{
		ID:                 uuid.New().String(),
		Email:              "admin@vrexisinsights.com",
		Password:           string(hashedPassword),
		FirstName:          "Admin",
		LastName:           "User",
		EmailNotifications: true,
		CreatedAt:          time.Now(),
	}

	_, err = getUserByEmail(context.Background(), user.Email)
	if err == nil {
		return
	}

	err = createUser(context.Background(), user)
	if err != nil {
		log.Printf("Error creating demo user: %v", err)
	} else {
		log.Printf("✅ Demo user created: %s / admin123", user.Email)
	}
}

func main() {
	log.Println("🚀 Starting Vrexis Insights server...")

	config := loadConfig()
	log.Println("✅ Configuration loaded")

	log.Println("🔗 Initializing database...")
	db, err := initDatabase(config.DBPath)
	if err != nil {
		log.Fatalf("❌ Database initialization failed: %v", err)
	}
	globalDB = db
	defer db.Close()
	log.Println("✅ Database initialized")

	log.Println("👤 Creating demo user...")
	createDemoUser(config)
	log.Println("✅ Demo user setup complete")

	log.Println("🧹 Starting data cleanup service...")
	go cleanupOldData(db)
	log.Println("✅ Data cleanup service started")

	log.Println("🔍 Starting service monitor...")
	go startServiceMonitor(db, config)
	log.Println("✅ Service monitor started")

	log.Println("🛣️  Setting up routes...")
	handler := setupRoutes(config, db)
	log.Println("✅ Routes configured")

	srv := &http.Server{
		Addr:         ":" + config.Port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("🚀 Vrexis Insights server starting...")
		log.Printf("📍 Environment: %s", config.Environment)
		log.Printf("🌐 Port: %s", config.Port)
		log.Printf("🔒 Security headers enabled")
		log.Printf("⚡ Rate limiting: %d requests per %v", config.RateLimitMax, config.RateLimitWindow)

		if isEmailConfigured(config) {
			log.Printf("📧 Email notifications enabled")
		} else {
			log.Printf("📧 Email notifications disabled - configure SMTP to enable")
		}

		if config.Environment == "development" {
			log.Printf("👤 Demo login: admin@vrexisinsights.com / admin123")
		}

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ Server startup failed: %v", err)
		}
	}()

	app := wails.CreateApp(&options.App{
		Title:  "Vrexis Insights",
		Width:  1024,
		Height: 768,
	})

	if err := app.Run(); err != nil {
		log.Fatalf("❌ Wails app error: %v", err)
	}

	log.Println("🛑 Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("❌ Server shutdown error: %v", err)
	} else {
		log.Println("✅ Server stopped gracefully")
	}
}
