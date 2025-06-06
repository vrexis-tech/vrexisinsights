// monitor.go - Complete monitoring implementation

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Monitor handles service monitoring
type Monitor struct {
	store       *ServiceStore
	userStore   *UserStore
	clients     *ClientManager
	rateLimiter *RateLimiter
	config      *SecurityConfig
	monitor     *SecurityMonitor
	stopChan    chan bool
	wg          sync.WaitGroup
}

// SecurityMonitor handles security monitoring and alerting
type SecurityMonitor struct {
	mu              sync.RWMutex
	suspiciousIPs   map[string]*SuspiciousActivity
	alertThreshold  int
	cleanupInterval time.Duration
}

// SuspiciousActivity tracks suspicious activity from an IP
type SuspiciousActivity struct {
	IP             string
	AttemptCount   int
	LastAttempt    time.Time
	ViolationTypes []string
	Blocked        bool
	BlockedUntil   time.Time
}

// NewSecurityMonitor creates a new security monitor
func NewSecurityMonitor() *SecurityMonitor {
	sm := &SecurityMonitor{
		suspiciousIPs:   make(map[string]*SuspiciousActivity),
		alertThreshold:  5,
		cleanupInterval: 1 * time.Hour,
	}

	// Start cleanup routine
	go sm.startCleanup()

	return sm
}

// alert logs security alerts
func (sm *SecurityMonitor) alert(msg string) {
	log.Printf("🛡️ SECURITY ALERT: %s", msg)

	// Here you could integrate with external security monitoring services
	// like Datadog, New Relic, or send to SIEM systems
}

// recordSuspiciousActivity records suspicious activity from an IP
func (sm *SecurityMonitor) recordSuspiciousActivity(ip, violationType string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	activity, exists := sm.suspiciousIPs[ip]
	if !exists {
		activity = &SuspiciousActivity{
			IP:             ip,
			ViolationTypes: make([]string, 0),
		}
		sm.suspiciousIPs[ip] = activity
	}

	activity.AttemptCount++
	activity.LastAttempt = time.Now()
	activity.ViolationTypes = append(activity.ViolationTypes, violationType)

	// Block IP if threshold exceeded
	if activity.AttemptCount >= sm.alertThreshold && !activity.Blocked {
		activity.Blocked = true
		activity.BlockedUntil = time.Now().Add(24 * time.Hour)
		sm.alert(fmt.Sprintf("IP %s blocked due to %d suspicious activities: %v",
			ip, activity.AttemptCount, activity.ViolationTypes))
	}
}

// isIPBlocked checks if an IP is currently blocked
func (sm *SecurityMonitor) isIPBlocked(ip string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	activity, exists := sm.suspiciousIPs[ip]
	if !exists {
		return false
	}

	if activity.Blocked && time.Now().Before(activity.BlockedUntil) {
		return true
	}

	// Unblock if time has passed
	if activity.Blocked && time.Now().After(activity.BlockedUntil) {
		activity.Blocked = false
	}

	return false
}

// startCleanup periodically cleans up old suspicious activity records
func (sm *SecurityMonitor) startCleanup() {
	ticker := time.NewTicker(sm.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		sm.cleanup()
	}
}

// cleanup removes old suspicious activity records
func (sm *SecurityMonitor) cleanup() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	cutoff := time.Now().Add(-7 * 24 * time.Hour) // Keep records for 7 days

	for ip, activity := range sm.suspiciousIPs {
		if activity.LastAttempt.Before(cutoff) && !activity.Blocked {
			delete(sm.suspiciousIPs, ip)
		}
	}
}

// startMonitoring begins the service monitoring loop
func (m *Monitor) startMonitoring(ctx context.Context) {
	log.Println("🔍 Starting service monitoring...")

	// Initial check
	m.checkAllServices()

	// Set up periodic monitoring
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 Service monitoring stopped")
			return
		case <-m.stopChan:
			log.Println("🛑 Service monitoring stopped")
			return
		case <-ticker.C:
			m.checkAllServices()
		}
	}
}

// checkAllServices checks the status of all enabled services
func (m *Monitor) checkAllServices() {
	services, err := m.store.GetAllEnabledServices()
	if err != nil {
		log.Printf("Error fetching services for monitoring: %v", err)
		return
	}

	if len(services) == 0 {
		return
	}

	log.Printf("🔍 Checking %d services...", len(services))

	// Use worker pool to check services concurrently
	const maxWorkers = 10
	serviceChan := make(chan Service, len(services))

	// Start workers
	m.wg.Add(maxWorkers)
	for i := 0; i < maxWorkers; i++ {
		go m.serviceCheckWorker(serviceChan)
	}

	// Send services to workers
	for _, service := range services {
		serviceChan <- service
	}
	close(serviceChan)

	// Wait for all workers to complete
	m.wg.Wait()
}

// serviceCheckWorker processes service checks
func (m *Monitor) serviceCheckWorker(serviceChan <-chan Service) {
	defer m.wg.Done()

	for service := range serviceChan {
		m.checkService(&service)
	}
}

// checkService checks a single service
func (m *Monitor) checkService(service *Service) {
	var status string
	var latency, pingLatency *int

	switch service.Type {
	case "website":
		status, latency = m.checkHTTP(service.URL)
		_, pingLatency = m.checkPing(service.URL)
	case "server":
		status, pingLatency = m.checkPing(service.URL)
	default:
		// For misc services, try both
		status, latency = m.checkHTTP(service.URL)
		if status == "down" {
			status, pingLatency = m.checkPing(service.URL)
		}
	}

	// Update service status in database
	if err := m.store.UpdateServiceStatus(service.ID, status, latency, pingLatency); err != nil {
		log.Printf("Error updating service status for %s: %v", service.ID, err)
	} else {
		log.Printf("✅ %s (%s): %s", service.Name, service.URL, status)
	}
}

// checkHTTP performs HTTP health check
func (m *Monitor) checkHTTP(url string) (status string, latency *int) {
	start := time.Now()

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	resp, err := client.Get(url)
	duration := int(time.Since(start).Milliseconds())

	if err != nil {
		log.Printf("HTTP check failed for %s: %v", url, err)
		return "down", nil
	}
	defer resp.Body.Close()

	// Consider 2xx and 3xx as up
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return "up", &duration
	}

	log.Printf("HTTP check failed for %s: status %d", url, resp.StatusCode)
	return "down", &duration
}

// checkPing performs ping check
func (m *Monitor) checkPing(url string) (status string, pingLatency *int) {
	// Extract hostname from URL
	hostname := url
	if len(url) > 7 && url[:7] == "http://" {
		hostname = url[7:]
	} else if len(url) > 8 && url[:8] == "https://" {
		hostname = url[8:]
	}

	// Remove path if present
	if idx := len(hostname); idx > 0 {
		for i, char := range hostname {
			if char == '/' || char == ':' {
				hostname = hostname[:i]
				break
			}
		}
	}

	start := time.Now()

	// Use TCP dial as a ping alternative (ICMP requires root privileges)
	conn, err := net.DialTimeout("tcp", hostname+":80", 5*time.Second)
	duration := int(time.Since(start).Milliseconds())

	if err != nil {
		// Try HTTPS port if HTTP fails
		conn, err = net.DialTimeout("tcp", hostname+":443", 5*time.Second)
		duration = int(time.Since(start).Milliseconds())

		if err != nil {
			log.Printf("Ping check failed for %s: %v", hostname, err)
			return "down", nil
		}
	}

	conn.Close()
	return "up", &duration
}

// Rate limiting and client management

// RateLimiter handles rate limiting for API requests
type RateLimiter struct {
	mu       sync.RWMutex
	visitors map[string]*Visitor
	config   RateLimitConfig
	monitor  *SecurityMonitor
}

// Visitor tracks rate limit data for a specific IP
type Visitor struct {
	requests     int
	lastRequest  time.Time
	blocked      bool
	blockedUntil time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config RateLimitConfig, monitor *SecurityMonitor) *RateLimiter {
	return &RateLimiter{
		visitors: make(map[string]*Visitor),
		config:   config,
		monitor:  monitor,
	}
}

// Allow checks if a request should be allowed
func (rl *RateLimiter) Allow(ip string, isAuth bool) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check if IP is blocked by security monitor
	if rl.monitor.isIPBlocked(ip) {
		return false
	}

	visitor, exists := rl.visitors[ip]
	if !exists {
		visitor = &Visitor{
			lastRequest: time.Now(),
			requests:    1,
		}
		rl.visitors[ip] = visitor
		return true
	}

	now := time.Now()

	// Check if visitor is currently blocked
	if visitor.blocked && now.Before(visitor.blockedUntil) {
		return false
	}

	// Reset if it's been more than a minute
	if now.Sub(visitor.lastRequest) > time.Minute {
		visitor.requests = 1
		visitor.lastRequest = now
		visitor.blocked = false
		return true
	}

	// Determine rate limit based on request type
	limit := rl.config.RPM
	if isAuth {
		limit = rl.config.AuthRPM
	}

	visitor.requests++
	visitor.lastRequest = now

	if visitor.requests > limit {
		// Block for 1 minute
		visitor.blocked = true
		visitor.blockedUntil = now.Add(time.Minute)

		// Record suspicious activity
		rl.monitor.recordSuspiciousActivity(ip, "rate_limit_exceeded")

		log.Printf("Rate limit exceeded for IP %s: %d requests", ip, visitor.requests)
		return false
	}

	return true
}

// GetStats returns current rate limit statistics for an IP
func (rl *RateLimiter) GetStats(ip string) (int, error) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	visitor, exists := rl.visitors[ip]
	if !exists {
		return 0, nil
	}

	// Reset count if it's been more than a minute
	if time.Since(visitor.lastRequest) > time.Minute {
		return 0, nil
	}

	return visitor.requests, nil
}

// StartCleanup starts the cleanup routine for old visitor data
func (rl *RateLimiter) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.cleanup()
		}
	}
}

// cleanup removes old visitor data
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)

	for ip, visitor := range rl.visitors {
		if visitor.lastRequest.Before(cutoff) && !visitor.blocked {
			delete(rl.visitors, ip)
		}
	}
}

// ClientManager manages WebSocket connections and client state
type ClientManager struct {
	mu          sync.RWMutex
	clients     map[string]*Client
	monitor     *SecurityMonitor
	connections int
}

// Client represents a connected client
type Client struct {
	ID          string
	UserID      string
	IPAddress   string
	ConnectedAt time.Time
	LastSeen    time.Time
	Active      bool
}

// NewClientManager creates a new client manager
func NewClientManager(monitor *SecurityMonitor) *ClientManager {
	return &ClientManager{
		clients: make(map[string]*Client),
		monitor: monitor,
	}
}

// AddClient adds a new client connection
func (cm *ClientManager) AddClient(clientID, userID, ipAddress string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	client := &Client{
		ID:          clientID,
		UserID:      userID,
		IPAddress:   ipAddress,
		ConnectedAt: time.Now(),
		LastSeen:    time.Now(),
		Active:      true,
	}

	cm.clients[clientID] = client
	cm.connections++

	log.Printf("Client connected: %s (User: %s, IP: %s)", clientID, userID, ipAddress)
}

// RemoveClient removes a client connection
func (cm *ClientManager) RemoveClient(clientID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if client, exists := cm.clients[clientID]; exists {
		delete(cm.clients, clientID)
		if cm.connections > 0 {
			cm.connections--
		}
		log.Printf("Client disconnected: %s (User: %s)", clientID, client.UserID)
	}
}

// UpdateClientActivity updates the last seen time for a client
func (cm *ClientManager) UpdateClientActivity(clientID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if client, exists := cm.clients[clientID]; exists {
		client.LastSeen = time.Now()
	}
}

// GetActiveConnections returns the number of active connections
func (cm *ClientManager) GetActiveConnections() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.connections
}

// GetClientsByUser returns all active clients for a user
func (cm *ClientManager) GetClientsByUser(userID string) []*Client {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var userClients []*Client
	for _, client := range cm.clients {
		if client.UserID == userID && client.Active {
			userClients = append(userClients, client)
		}
	}

	return userClients
}

// DisconnectUser disconnects all clients for a specific user
func (cm *ClientManager) DisconnectUser(userID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for clientID, client := range cm.clients {
		if client.UserID == userID {
			client.Active = false
			delete(cm.clients, clientID)
			if cm.connections > 0 {
				cm.connections--
			}
		}
	}

	log.Printf("All clients disconnected for user: %s", userID)
}

// StartCleanup starts cleanup routine for inactive clients
func (cm *ClientManager) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cm.cleanupInactiveClients()
		}
	}
}

// cleanupInactiveClients removes clients that haven't been seen recently
func (cm *ClientManager) cleanupInactiveClients() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute)

	for clientID, client := range cm.clients {
		if client.LastSeen.Before(cutoff) {
			delete(cm.clients, clientID)
			if cm.connections > 0 {
				cm.connections--
			}
			log.Printf("Cleaned up inactive client: %s", clientID)
		}
	}
}
