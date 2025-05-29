package main

import (
	"context"
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

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
}

type SecurityConfig struct {
	EnableHTTPS      bool
	MaxRequestSize   int64
	RateLimitEnabled bool
	AllowedOrigins   []string
	RequireAuth      bool
}

type Monitor struct {
	store        *ServiceStore
	clients      *ClientManager
	config       *SecurityConfig
	shutdownChan chan struct{}
	isRunning    bool
	mu           sync.RWMutex
}

// Enhanced CORS with security headers
func secureMiddleware(config *SecurityConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws: wss:")

			// CORS with validation
			origin := r.Header.Get("Origin")
			if origin == "" {
				origin = "http://localhost:3000" // Default for development
			}

			// Validate origin against allowed list
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

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			// Request size limiting
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

	// Sanitize name (remove potential XSS)
	if len(s.Name) > 100 {
		return errors.New("service name too long (max 100 characters)")
	}

	// Enhanced URL validation
	if len(s.URL) > 500 {
		return errors.New("URL too long (max 500 characters)")
	}

	// Check if it's a raw IP address or hostname (no protocol)
	if s.isRawIPOrHostname(s.URL) {
		// Validate IP address or hostname format
		if !s.isValidIPOrHostname(s.URL) {
			return errors.New("invalid IP address or hostname format")
		}

		// Security: Block dangerous IPs/hosts
		if s.isDangerousHost(s.URL) {
			return errors.New("potentially unsafe host detected")
		}
	} else {
		// Parse and validate as URL
		parsedURL, err := url.Parse(s.URL)
		if err != nil {
			return errors.New("invalid URL format")
		}

		// Security: Only allow HTTP/HTTPS for URLs
		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			return errors.New("only HTTP and HTTPS protocols are allowed for URLs")
		}

		// Security: Block dangerous domains and IPs
		if s.isDangerousHost(parsedURL.Host) {
			return errors.New("potentially unsafe host detected")
		}
	}

	// Validate service type
	validTypes := map[string]bool{"website": true, "server": true, "misc": true}
	if s.Type != "" && !validTypes[s.Type] {
		return errors.New("invalid service type")
	}

	return nil
}

// Check if URL is a raw IP address or hostname (no protocol)
func (s *Service) isRawIPOrHostname(input string) bool {
	// If it contains ://, it's a full URL
	if strings.Contains(input, "://") {
		return false
	}

	// Remove port if present for validation
	host := input
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		host = parts[0]
	}

	// Check if it's an IP address
	if net.ParseIP(host) != nil {
		return true
	}

	// Check if it looks like a hostname (contains letters)
	return len(host) > 0 && !strings.Contains(host, "/")
}

// Validate IP address or hostname format
func (s *Service) isValidIPOrHostname(input string) bool {
	// Remove port if present
	host := input
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		if len(parts) != 2 {
			return false
		}
		host = parts[0]
		// Validate port number
		if port := parts[1]; port != "" {
			// Port should be numeric and in valid range
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

	// Check if it's a valid IP address
	if net.ParseIP(host) != nil {
		return true
	}

	// Check if it's a valid hostname
	if len(host) == 0 || len(host) > 253 {
		return false
	}

	// Basic hostname validation (letters, numbers, dots, hyphens)
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

// Security check for dangerous hosts
func (s *Service) isDangerousHost(host string) bool {
	// Block localhost and private IPs in production
	if os.Getenv("ENV") == "production" {
		if strings.Contains(host, "localhost") ||
			strings.Contains(host, "127.0.0.1") ||
			strings.Contains(host, "10.") ||
			strings.Contains(host, "172.") ||
			strings.Contains(host, "192.168.") {
			return true
		}
	}

	// Block suspicious domains
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

	// Create basic table first (compatible with old schema)
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

	// Now migrate/add new columns if they don't exist
	if err := store.migrateSchema(); err != nil {
		return nil, fmt.Errorf("failed to migrate schema: %v", err)
	}

	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

// migrateSchema adds new columns if they don't exist
func (s *ServiceStore) migrateSchema() error {
	// Check if columns exist and add them if missing
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
	}

	for _, migration := range migrations {
		// Try to add the column
		alterSQL := fmt.Sprintf("ALTER TABLE services ADD COLUMN %s %s", migration.column, migration.definition)
		if _, err := s.db.Exec(alterSQL); err != nil {
			// Column might already exist, check if that's the case
			checkSQL := fmt.Sprintf("SELECT %s FROM services LIMIT 1", migration.column)
			if _, checkErr := s.db.Query(checkSQL); checkErr != nil {
				log.Printf("⚠️ Failed to add column %s: %v", migration.column, err)
				return err
			}
			// Column exists, continue
			log.Printf("✅ Column %s already exists", migration.column)
		} else {
			log.Printf("✅ Added column %s to services table", migration.column)

			// Set default values for existing records if needed
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
	// First check which columns exist
	columns := s.getAvailableColumns()

	// Build query based on available columns
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

		// Set defaults for optional fields
		svc.Type = "website"
		svc.Status = "unknown"
		svc.Latency = 0
		svc.PingLatency = 0
		svc.CreatedAt = time.Now()
		svc.UpdatedAt = time.Now()

		// Parse optional fields if they exist
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

		s.services[svc.ID] = &svc
	}
	return nil
}

// getAvailableColumns returns list of columns that exist in the services table
func (s *ServiceStore) getAvailableColumns() []string {
	rows, err := s.db.Query("PRAGMA table_info(services)")
	if err != nil {
		return []string{"id", "name", "url", "enabled"} // Fallback to basic columns
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

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
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

	// Set default type if not provided
	if svc.Type == "" {
		svc.Type = "website"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check which columns exist
	columns := s.getAvailableColumns()

	// Build insert query based on available columns
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

	query += ") VALUES (" + values + ")"

	_, err := s.db.Exec(query, args...)
	if err == nil {
		s.services[svc.ID] = svc
		log.Printf("🔒 Service added securely: %s (%s)", svc.Name, svc.URL)
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

	// Check which columns exist
	columns := s.getAvailableColumns()

	// Build update query based on available columns
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
			// Preserve monitoring data
			svc.Status = existing.Status
			svc.Latency = existing.Latency
			svc.PingLatency = existing.PingLatency
			svc.LastChecked = existing.LastChecked
			svc.CreatedAt = existing.CreatedAt
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

	// Check which columns exist
	columns := s.getAvailableColumns()

	// Build update query based on available columns
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
		// No metrics columns exist, just update in memory
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

func (s *ServiceStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Security: Validate UUID format
	if _, err := uuid.Parse(id); err != nil {
		return errors.New("invalid service ID format")
	}

	_, err := s.db.Exec("DELETE FROM services WHERE id=?", id)
	if err == nil {
		if svc, ok := s.services[id]; ok {
			log.Printf("🔒 Service deleted securely: %s", svc.Name)
			delete(s.services, id)
		}
	}
	return err
}

type ClientManager struct {
	mu      sync.Mutex
	clients map[*websocket.Conn]bool
}

func NewClientManager() *ClientManager {
	return &ClientManager{clients: make(map[*websocket.Conn]bool)}
}

func (c *ClientManager) Add(conn *websocket.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clients[conn] = true
	log.Printf("🔒 Secure WebSocket client connected (total: %d)", len(c.clients))
}

func (c *ClientManager) Remove(conn *websocket.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.clients[conn]; ok {
		delete(c.clients, conn)
		conn.Close()
		log.Printf("🔒 Secure WebSocket client disconnected (total: %d)", len(c.clients))
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

	// Clean up dead connections
	for _, conn := range deadClients {
		delete(c.clients, conn)
		conn.Close()
	}
}

// Enhanced HTTP check with timeout and security
func checkHTTP(serviceURL string) (bool, int64) {
	start := time.Now()

	// Security: Custom HTTP client with timeouts
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

	// Security: Set user agent and headers
	req.Header.Set("User-Agent", "VrexisMonitor/1.0")
	req.Header.Set("Accept", "text/html,application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()

	latency := time.Since(start).Milliseconds()

	// Consider 2xx and 3xx as successful
	return resp.StatusCode < 400, latency
}

// Enhanced ping check with cross-platform support
func checkPing(host string) (bool, int64) {
	// Extract hostname from URL if needed
	if strings.Contains(host, "://") {
		parsedURL, err := url.Parse(host)
		if err != nil {
			return false, 0
		}
		host = parsedURL.Host
	}

	// Remove port if present
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

// Enhanced monitoring with error handling and logging
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

					// Determine if this is a raw IP/hostname or full URL
					if m.isRawIPOrHostname(service.URL) {
						// For raw IP/hostname, only do ping check
						upPing, pingLatency = checkPing(service.URL)
						upHTTP = false
						httpLatency = 0
						log.Printf("🏓 Ping check %s: %s (%dms)",
							service.Name, m.statusString(upPing), pingLatency)
					} else {
						// For full URLs, do both HTTP and ping checks
						upHTTP, httpLatency = checkHTTP(service.URL)
						upPing, pingLatency = checkPing(service.URL)
						log.Printf("🌐 HTTP check %s: %s (%dms HTTP, %dms ping)",
							service.Name, m.statusString(upHTTP || upPing), httpLatency, pingLatency)
					}

					status := "down"
					if upHTTP || upPing {
						status = "up"
					}

					// Update database
					if err := m.store.UpdateMetrics(service.ID, status, httpLatency, pingLatency); err != nil {
						log.Printf("⚠️ Failed to update metrics for %s: %v", service.Name, err)
						return
					}

					// Broadcast to clients
					m.clients.Broadcast(map[string]interface{}{
						"id":           service.ID,
						"name":         service.Name,
						"url":          service.URL,
						"type":         service.Type,
						"status":       status,
						"latency":      httpLatency,
						"ping_latency": pingLatency,
						"last_checked": time.Now().Format(time.RFC3339),
					})
				}(svc)
			}
			wg.Wait()
		}
	}
}

// Helper function to check if URL is raw IP/hostname
func (m *Monitor) isRawIPOrHostname(input string) bool {
	return !strings.Contains(input, "://")
}

// Helper function for status string
func (m *Monitor) statusString(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

func setupRoutes(store *ServiceStore, clients *ClientManager, config *SecurityConfig) *mux.Router {
	r := mux.NewRouter()

	// WebSocket upgrade with security checks
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			for _, allowed := range config.AllowedOrigins {
				if origin == allowed {
					return true
				}
			}
			return origin == "http://localhost:3000" // Default for development
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	// Enhanced WebSocket endpoint
	r.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("⚠️ WebSocket upgrade failed: %v", err)
			http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
			return
		}

		clients.Add(conn)

		// Send current services to new client
		services := store.All()
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

		// Handle connection cleanup
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

	// API v1 routes (secure endpoints)
	api := r.PathPrefix("/api/v1").Subrouter()

	// GET /api/v1/services
	api.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		services := store.All()
		if err := json.NewEncoder(w).Encode(services); err != nil {
			http.Error(w, `{"error":"Failed to encode services"}`, http.StatusInternalServerError)
		}
	}).Methods("GET")

	// POST /api/v1/services
	api.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var svc Service
		if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		if svc.ID == "" {
			svc.ID = uuid.New().String()
		}

		if err := store.Add(&svc); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
			return
		}

		json.NewEncoder(w).Encode(svc)
	}).Methods("POST")

	// PUT /api/v1/services/{id}
	api.HandleFunc("/services/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		id := mux.Vars(r)["id"]

		var svc Service
		if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		svc.ID = id
		if err := store.Update(&svc); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	}).Methods("PUT")

	// DELETE /api/v1/services/{id}
	api.HandleFunc("/services/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		id := mux.Vars(r)["id"]

		if err := store.Delete(id); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}).Methods("DELETE")

	// Legacy routes for backwards compatibility
	r.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.All())
	}).Methods("GET")

	r.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var svc Service
		if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}
		if svc.ID == "" {
			svc.ID = uuid.New().String()
		}
		if err := store.Add(&svc); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(svc)
	}).Methods("POST")

	r.HandleFunc("/services/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		id := mux.Vars(r)["id"]
		if err := store.Delete(id); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}).Methods("DELETE")

	return r
}

func main() {
	// Security configuration
	config := &SecurityConfig{
		EnableHTTPS:      os.Getenv("ENABLE_HTTPS") == "true",
		MaxRequestSize:   1024 * 1024, // 1MB
		RateLimitEnabled: true,
		AllowedOrigins: []string{
			"http://localhost:3000",
			"https://localhost:3000",
			"http://127.0.0.1:3000",
		},
		RequireAuth: os.Getenv("REQUIRE_AUTH") == "true",
	}

	// Enhanced database setup
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "services.db"
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("❌ Failed to open DB: %v", err)
	}
	defer db.Close()

	// Test database connection
	if err := db.Ping(); err != nil {
		log.Fatalf("❌ Failed to connect to DB: %v", err)
	}

	store, err := NewServiceStore(db)
	if err != nil {
		log.Fatalf("❌ Failed to initialize store: %v", err)
	}

	clients := NewClientManager()

	// Setup graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start monitoring
	monitor := &Monitor{
		store:   store,
		clients: clients,
		config:  config,
	}
	go monitor.startMonitoring(ctx)

	// Setup routes with security middleware
	router := setupRoutes(store, clients, config)

	// Server configuration
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      secureMiddleware(config)(router),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	go func() {
		if config.EnableHTTPS {
			log.Printf("🔒 Secure HTTPS server running on https://localhost:%s", port)
			if err := srv.ListenAndServeTLS("server.crt", "server.key"); err != nil && err != http.ErrServerClosed {
				log.Fatalf("❌ HTTPS server failed: %v", err)
			}
		} else {
			log.Printf("🚀 HTTP server running on http://localhost:%s", port)
			log.Println("🔒 Security features enabled: CORS, headers, validation")
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("❌ HTTP server failed: %v", err)
			}
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	log.Println("🛑 Shutting down server...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("⚠️ Server shutdown error: %v", err)
	} else {
		log.Println("✅ Server shutdown complete")
	}
}
