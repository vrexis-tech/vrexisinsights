// database_init.go - Complete database initialization and demo data

package main

import (
	"database/sql"
	"log"
	"time"
)

// createOriginalTables creates the core application tables
func createOriginalTables(db *sql.DB) error {
	// This function was empty in the original - now properly implemented
	schema := `
	-- Users table (already created by UserStore, but including for completeness)
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		first_name TEXT NOT NULL,
		last_name TEXT NOT NULL,
		role TEXT DEFAULT 'user',
		active BOOLEAN DEFAULT 1,
		mfa_enabled BOOLEAN DEFAULT 0,
		mfa_secret TEXT,
		backup_codes TEXT, -- JSON array
		last_login DATETIME,
		password_changed DATETIME DEFAULT CURRENT_TIMESTAMP,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Services table (already created by ServiceStore, but including for completeness)
	CREATE TABLE IF NOT EXISTS services (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		url TEXT NOT NULL,
		type TEXT DEFAULT 'website',
		enabled BOOLEAN DEFAULT 1,
		status TEXT DEFAULT 'pending',
		latency INTEGER,
		ping_latency INTEGER,
		last_checked DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		encrypted BOOLEAN DEFAULT 0,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
	);

	-- Session management table for tracking active sessions
	CREATE TABLE IF NOT EXISTS user_sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		token_id TEXT NOT NULL,
		ip_address TEXT,
		user_agent TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
		active BOOLEAN DEFAULT 1,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
	);

	-- API keys table for programmatic access
	CREATE TABLE IF NOT EXISTS api_keys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		key_hash TEXT NOT NULL,
		permissions TEXT, -- JSON array of permissions
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		last_used DATETIME,
		active BOOLEAN DEFAULT 1,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
	);

	-- Security events log
	CREATE TABLE IF NOT EXISTS security_events (
		id TEXT PRIMARY KEY,
		user_id TEXT,
		event_type TEXT NOT NULL,
		ip_address TEXT,
		user_agent TEXT,
		description TEXT,
		severity TEXT DEFAULT 'info',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- System settings table
	CREATE TABLE IF NOT EXISTS system_settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		description TEXT,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_by TEXT
	);

	-- Create indexes for better performance
	CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
	CREATE INDEX IF NOT EXISTS idx_users_active ON users (active);
	CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);
	
	CREATE INDEX IF NOT EXISTS idx_services_user_id ON services (user_id);
	CREATE INDEX IF NOT EXISTS idx_services_status ON services (status);
	CREATE INDEX IF NOT EXISTS idx_services_enabled ON services (enabled);
	CREATE INDEX IF NOT EXISTS idx_services_type ON services (type);
	
	CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions (user_id);
	CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions (active);
	CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions (expires_at);
	
	CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys (user_id);
	CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys (active);
	
	CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events (user_id);
	CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events (event_type);
	CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events (created_at);
	`

	_, err := db.Exec(schema)
	if err != nil {
		return err
	}

	log.Println("✅ Core database tables created successfully")
	return nil
}

// initDemoUsers creates demo users for testing
func initDemoUsers(userStore *UserStore) {
	log.Println("🔧 Initializing demo users...")

	// Check if admin user already exists
	if user, _ := userStore.GetUserByEmail("admin@vrexisinsights.com"); user != nil {
		log.Println("Demo admin user already exists, skipping initialization")
		return
	}

	// Create admin user
	adminPassword, err := hashPassword("admin123!@#")
	if err != nil {
		log.Printf("Error hashing admin password: %v", err)
		return
	}

	adminUser := &User{
		Email:           "admin@vrexisinsights.com",
		Password:        adminPassword,
		FirstName:       "Admin",
		LastName:        "User",
		Role:            "admin",
		Active:          true,
		MFAEnabled:      false,
		PasswordChanged: time.Now(),
	}

	if _, err := userStore.CreateUser(adminUser); err != nil {
		log.Printf("Error creating admin user: %v", err)
	} else {
		log.Println("✅ Created demo admin user: admin@vrexisinsights.com (password: admin123!@#)")
	}

	// Create regular demo user
	demoPassword, err := hashPassword("demo123!@#")
	if err != nil {
		log.Printf("Error hashing demo password: %v", err)
		return
	}

	demoUser := &User{
		Email:           "demo@vrexisinsights.com",
		Password:        demoPassword,
		FirstName:       "Demo",
		LastName:        "User",
		Role:            "user",
		Active:          true,
		MFAEnabled:      false,
		PasswordChanged: time.Now(),
	}

	if _, err := userStore.CreateUser(demoUser); err != nil {
		log.Printf("Error creating demo user: %v", err)
	} else {
		log.Println("✅ Created demo user: demo@vrexisinsights.com (password: demo123!@#)")
	}
}

// initDemoNotificationSettings creates default notification settings for demo users
func initDemoNotificationSettings(notificationStore *NotificationStore) {
	log.Println("🔧 Initializing demo notification settings...")

	// Get demo users (we'll need their IDs)
	demoUserEmails := []string{"admin@vrexisinsights.com", "demo@vrexisinsights.com"}

	for _, email := range demoUserEmails {
		// Create notification settings for each demo user
		// Note: In a real implementation, you'd get the user ID from the UserStore
		// For demo purposes, we'll use the email as a pseudo-ID

		settings := &NotificationSettings{
			UserID:         email, // This should be the actual user ID in production
			EmailEnabled:   true,
			EmailAddress:   email,
			EmailVerified:  true, // Pre-verified for demo
			SMSEnabled:     false,
			SMSNumber:      "",
			SMSVerified:    false,
			SlackEnabled:   true,
			SlackWebhook:   "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
			SlackChannel:   "#alerts",
			WebhookEnabled: false,
			WebhookURL:     "",
			WebhookMethod:  "POST",
			Updated:        time.Now(),
		}

		if err := notificationStore.CreateDemoNotificationSettings(settings); err != nil {
			log.Printf("Error creating notification settings for %s: %v", email, err)
		} else {
			log.Printf("✅ Created notification settings for %s", email)
		}
	}
}

// initDemoAlerts creates demo alerts for testing
func initDemoAlerts(alertStore *AlertStore) {
	log.Println("🔧 Initializing demo alerts...")

	// Demo alerts for the admin user
	demoAlerts := []Alert{
		{
			UserID:        "admin@vrexisinsights.com", // Should be actual user ID in production
			Name:          "Website Down Alert",
			Description:   "Triggers when the main website becomes unreachable",
			ServiceIDs:    []string{"demo-service-1"}, // These should match actual service IDs
			Condition:     "status",
			Operator:      "equals",
			Value:         "down",
			Enabled:       true,
			Notifications: []string{"email", "slack"},
			Cooldown:      5,
			Severity:      "critical",
		},
		{
			UserID:        "admin@vrexisinsights.com",
			Name:          "High Latency Warning",
			Description:   "Alerts when API response time exceeds 2 seconds",
			ServiceIDs:    []string{"demo-service-2"},
			Condition:     "latency",
			Operator:      "greater_than",
			Value:         "2000",
			Enabled:       true,
			Notifications: []string{"email"},
			Cooldown:      10,
			Severity:      "warning",
		},
		{
			UserID:        "demo@vrexisinsights.com",
			Name:          "Multiple Services Down",
			Description:   "Critical alert when multiple services are offline",
			ServiceIDs:    []string{"demo-service-1", "demo-service-2", "demo-service-3"},
			Condition:     "multiple_down",
			Operator:      "greater_than",
			Value:         "1",
			Enabled:       false, // Disabled by default for demo
			Notifications: []string{"email", "slack"},
			Cooldown:      15,
			Severity:      "critical",
		},
		{
			UserID:        "demo@vrexisinsights.com",
			Name:          "Ping Latency Alert",
			Description:   "Warns when server ping latency is too high",
			ServiceIDs:    []string{"demo-service-3"},
			Condition:     "ping_latency",
			Operator:      "greater_than",
			Value:         "100",
			Enabled:       true,
			Notifications: []string{"email"},
			Cooldown:      5,
			Severity:      "warning",
		},
	}

	for _, alert := range demoAlerts {
		if err := alertStore.CreateDemoAlert(&alert); err != nil {
			log.Printf("Error creating demo alert '%s': %v", alert.Name, err)
		} else {
			log.Printf("✅ Created demo alert: %s", alert.Name)
		}
	}
}

// initDemoServices creates demo services for testing
func initDemoServices(serviceStore *ServiceStore) {
	log.Println("🔧 Initializing demo services...")

	// Demo services for testing
	demoServices := []Service{
		{
			ID:      "demo-service-1",
			UserID:  "admin@vrexisinsights.com", // Should be actual user ID in production
			Name:    "Main Website",
			URL:     "https://example.com",
			Type:    "website",
			Enabled: true,
			Status:  "up",
		},
		{
			ID:      "demo-service-2",
			UserID:  "admin@vrexisinsights.com",
			Name:    "API Gateway",
			URL:     "https://api.example.com",
			Type:    "website",
			Enabled: true,
			Status:  "up",
		},
		{
			ID:      "demo-service-3",
			UserID:  "admin@vrexisinsights.com",
			Name:    "Database Server",
			URL:     "192.168.1.100",
			Type:    "server",
			Enabled: true,
			Status:  "down", // Demo: this service is down
		},
		{
			ID:      "demo-service-4",
			UserID:  "demo@vrexisinsights.com",
			Name:    "Load Balancer",
			URL:     "lb.internal.example.com",
			Type:    "misc",
			Enabled: true,
			Status:  "up",
		},
	}

	for _, service := range demoServices {
		// Set default values
		now := time.Now()
		if service.Latency == nil && service.Status == "up" && service.Type == "website" {
			latency := 150
			service.Latency = &latency
		}
		if service.PingLatency == nil && service.Status == "up" {
			pingLatency := 25
			service.PingLatency = &pingLatency
		}
		service.LastChecked = &now

		if _, err := serviceStore.CreateService(&service); err != nil {
			log.Printf("Error creating demo service '%s': %v", service.Name, err)
		} else {
			log.Printf("✅ Created demo service: %s (%s)", service.Name, service.URL)
		}
	}
}

// insertDefaultSystemSettings inserts default system settings
func insertDefaultSystemSettings(db *sql.DB) error {
	log.Println("🔧 Initializing system settings...")

	settings := map[string]string{
		"app_name":                    "VREXIS Insights",
		"app_version":                 "2.1.0",
		"maintenance_mode":            "false",
		"registration_enabled":        "true",
		"max_services_per_user":       "50",
		"max_alerts_per_user":         "25",
		"default_monitoring_interval": "30",
		"session_timeout_hours":       "24",
		"password_min_length":         "8",
		"mfa_required":                "false",
		"rate_limit_per_minute":       "60",
		"auth_rate_limit_per_minute":  "10",
	}

	query := `
		INSERT OR REPLACE INTO system_settings (key, value, description, updated_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
	`

	for key, value := range settings {
		var description string
		switch key {
		case "app_name":
			description = "Application name displayed in UI"
		case "app_version":
			description = "Current application version"
		case "maintenance_mode":
			description = "Whether the application is in maintenance mode"
		case "registration_enabled":
			description = "Whether new user registration is allowed"
		case "max_services_per_user":
			description = "Maximum number of services per user"
		case "max_alerts_per_user":
			description = "Maximum number of alerts per user"
		case "default_monitoring_interval":
			description = "Default monitoring interval in seconds"
		case "session_timeout_hours":
			description = "Session timeout in hours"
		case "password_min_length":
			description = "Minimum password length requirement"
		case "mfa_required":
			description = "Whether MFA is required for all users"
		case "rate_limit_per_minute":
			description = "Rate limit for general API requests per minute"
		case "auth_rate_limit_per_minute":
			description = "Rate limit for authentication requests per minute"
		}

		if _, err := db.Exec(query, key, value, description); err != nil {
			return err
		}
	}

	log.Println("✅ System settings initialized successfully")
	return nil
}

// Enhanced initializeDemoData function to replace the one in main.go
func initializeDemoDataComplete(stores *Stores, db *sql.DB) {
	log.Println("🔧 Initializing complete demo data for testing...")

	// Initialize system settings first
	if err := insertDefaultSystemSettings(db); err != nil {
		log.Printf("Error initializing system settings: %v", err)
	}

	// Initialize demo users
	initDemoUsers(stores.User)

	// Initialize demo services (this creates services that alerts can reference)
	initDemoServices(stores.Service)

	// Initialize demo notification settings
	initDemoNotificationSettings(stores.Notification)

	// Initialize demo alerts (depends on services existing)
	initDemoAlerts(stores.Alert)

	log.Println("✅ Complete demo data initialized successfully")
	log.Println("")
	log.Println("🔑 Demo Login Credentials:")
	log.Println("   Admin: admin@vrexisinsights.com / admin123!@#")
	log.Println("   User:  demo@vrexisinsights.com / demo123!@#")
	log.Println("")
}
