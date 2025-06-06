package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// UserStore handles user data operations
type UserStore struct {
	db        *sql.DB
	monitor   *SecurityMonitor
	authStore *AuthStore
}

// ServiceStore handles service data operations
type ServiceStore struct {
	db      *sql.DB
	monitor *SecurityMonitor
}

// NewUserStore creates a new user store
func NewUserStore(db *sql.DB, monitor *SecurityMonitor) (*UserStore, error) {
	store := &UserStore{
		db:        db,
		monitor:   monitor,
		authStore: NewAuthStore(),
	}

	// Initialize user table if needed
	if err := store.initializeUserTable(); err != nil {
		return nil, fmt.Errorf("failed to initialize user table: %w", err)
	}

	return store, nil
}

// NewServiceStore creates a new service store
func NewServiceStore(db *sql.DB, monitor *SecurityMonitor) (*ServiceStore, error) {
	store := &ServiceStore{
		db:      db,
		monitor: monitor,
	}

	// Initialize service table if needed
	if err := store.initializeServiceTable(); err != nil {
		return nil, fmt.Errorf("failed to initialize service table: %w", err)
	}

	return store, nil
}

// User Store Methods

func (us *UserStore) initializeUserTable() error {
	query := `
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

	CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
	CREATE INDEX IF NOT EXISTS idx_users_active ON users (active);
	CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);
	`

	_, err := us.db.Exec(query)
	return err
}

func (us *UserStore) CreateUser(user *User) (*User, error) {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now
	if user.PasswordChanged.IsZero() {
		user.PasswordChanged = now
	}

	// Marshal backup codes to JSON
	backupCodesJSON, err := json.Marshal(user.BackupCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	query := `
		INSERT INTO users (id, email, password, first_name, last_name, role, active, 
		                  mfa_enabled, mfa_secret, backup_codes, password_changed, 
		                  created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = us.db.Exec(query,
		user.ID, user.Email, user.Password, user.FirstName, user.LastName,
		user.Role, user.Active, user.MFAEnabled, user.MFASecret,
		string(backupCodesJSON), user.PasswordChanged, user.CreatedAt, user.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

func (us *UserStore) GetByID(userID string) *User {
	query := `
		SELECT id, email, password, first_name, last_name, role, active,
		       mfa_enabled, mfa_secret, backup_codes, last_login, password_changed,
		       created_at, updated_at
		FROM users 
		WHERE id = ?
	`

	var user User
	var backupCodesJSON string
	var lastLogin sql.NullTime

	err := us.db.QueryRow(query, userID).Scan(
		&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName,
		&user.Role, &user.Active, &user.MFAEnabled, &user.MFASecret,
		&backupCodesJSON, &lastLogin, &user.PasswordChanged,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		us.monitor.alert(fmt.Sprintf("Database error in GetByID: %v", err))
		return nil
	}

	// Unmarshal backup codes
	if backupCodesJSON != "" {
		json.Unmarshal([]byte(backupCodesJSON), &user.BackupCodes)
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user
}

func (us *UserStore) GetUserByEmail(email string) (*User, error) {
	query := `
		SELECT id, email, password, first_name, last_name, role, active,
		       mfa_enabled, mfa_secret, backup_codes, last_login, password_changed,
		       created_at, updated_at
		FROM users 
		WHERE email = ? AND active = 1
	`

	var user User
	var backupCodesJSON string
	var lastLogin sql.NullTime

	err := us.db.QueryRow(query, email).Scan(
		&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName,
		&user.Role, &user.Active, &user.MFAEnabled, &user.MFASecret,
		&backupCodesJSON, &lastLogin, &user.PasswordChanged,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Unmarshal backup codes
	if backupCodesJSON != "" {
		json.Unmarshal([]byte(backupCodesJSON), &user.BackupCodes)
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user, nil
}

func (us *UserStore) UpdateLastLogin(userID string) error {
	query := `UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := us.db.Exec(query, userID)
	return err
}

func (us *UserStore) UpdateUser(user *User) error {
	user.UpdatedAt = time.Now()

	// Marshal backup codes to JSON
	backupCodesJSON, err := json.Marshal(user.BackupCodes)
	if err != nil {
		return fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	query := `
		UPDATE users 
		SET email = ?, password = ?, first_name = ?, last_name = ?, role = ?,
		    active = ?, mfa_enabled = ?, mfa_secret = ?, backup_codes = ?,
		    password_changed = ?, updated_at = ?
		WHERE id = ?
	`

	_, err = us.db.Exec(query,
		user.Email, user.Password, user.FirstName, user.LastName, user.Role,
		user.Active, user.MFAEnabled, user.MFASecret, string(backupCodesJSON),
		user.PasswordChanged, user.UpdatedAt, user.ID,
	)

	return err
}

func (us *UserStore) DeleteUser(userID string) error {
	query := `DELETE FROM users WHERE id = ?`
	_, err := us.db.Exec(query, userID)
	return err
}

// Service Store Methods

func (ss *ServiceStore) initializeServiceTable() error {
	query := `
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

	CREATE INDEX IF NOT EXISTS idx_services_user_id ON services (user_id);
	CREATE INDEX IF NOT EXISTS idx_services_status ON services (status);
	CREATE INDEX IF NOT EXISTS idx_services_enabled ON services (enabled);
	CREATE INDEX IF NOT EXISTS idx_services_type ON services (type);
	`

	_, err := ss.db.Exec(query)
	return err
}

func (ss *ServiceStore) GetServiceByID(serviceID, userID string) (*Service, error) {
	query := `
		SELECT id, user_id, name, url, type, enabled, status, latency, 
		       ping_latency, last_checked, created_at, updated_at, encrypted
		FROM services 
		WHERE id = ? AND user_id = ?
	`

	var service Service
	var latency, pingLatency sql.NullInt32
	var lastChecked sql.NullTime

	err := ss.db.QueryRow(query, serviceID, userID).Scan(
		&service.ID, &service.UserID, &service.Name, &service.URL, &service.Type,
		&service.Enabled, &service.Status, &latency, &pingLatency, &lastChecked,
		&service.CreatedAt, &service.UpdatedAt, &service.Encrypted,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("service not found")
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Handle nullable fields
	if latency.Valid {
		latencyInt := int(latency.Int32)
		service.Latency = &latencyInt
	}
	if pingLatency.Valid {
		pingLatencyInt := int(pingLatency.Int32)
		service.PingLatency = &pingLatencyInt
	}
	if lastChecked.Valid {
		service.LastChecked = &lastChecked.Time
	}

	return &service, nil
}

func (ss *ServiceStore) GetServicesByUserID(userID string) ([]Service, error) {
	query := `
		SELECT id, user_id, name, url, type, enabled, status, latency, 
		       ping_latency, last_checked, created_at, updated_at, encrypted
		FROM services 
		WHERE user_id = ?
		ORDER BY created_at DESC
	`

	rows, err := ss.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var services []Service
	for rows.Next() {
		var service Service
		var latency, pingLatency sql.NullInt32
		var lastChecked sql.NullTime

		err := rows.Scan(
			&service.ID, &service.UserID, &service.Name, &service.URL, &service.Type,
			&service.Enabled, &service.Status, &latency, &pingLatency, &lastChecked,
			&service.CreatedAt, &service.UpdatedAt, &service.Encrypted,
		)
		if err != nil {
			return nil, fmt.Errorf("scan error: %w", err)
		}

		// Handle nullable fields
		if latency.Valid {
			latencyInt := int(latency.Int32)
			service.Latency = &latencyInt
		}
		if pingLatency.Valid {
			pingLatencyInt := int(pingLatency.Int32)
			service.PingLatency = &pingLatencyInt
		}
		if lastChecked.Valid {
			service.LastChecked = &lastChecked.Time
		}

		services = append(services, service)
	}

	return services, nil
}

func (ss *ServiceStore) CreateService(service *Service) (*Service, error) {
	if service.ID == "" {
		service.ID = uuid.New().String()
	}

	now := time.Now()
	service.CreatedAt = now
	service.UpdatedAt = now

	query := `
		INSERT INTO services (id, user_id, name, url, type, enabled, status, 
		                     latency, ping_latency, last_checked, created_at, 
		                     updated_at, encrypted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	var latency, pingLatency interface{}
	var lastChecked interface{}

	if service.Latency != nil {
		latency = *service.Latency
	}
	if service.PingLatency != nil {
		pingLatency = *service.PingLatency
	}
	if service.LastChecked != nil {
		lastChecked = *service.LastChecked
	}

	_, err := ss.db.Exec(query,
		service.ID, service.UserID, service.Name, service.URL, service.Type,
		service.Enabled, service.Status, latency, pingLatency, lastChecked,
		service.CreatedAt, service.UpdatedAt, service.Encrypted,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create service: %w", err)
	}

	return service, nil
}

func (ss *ServiceStore) UpdateService(service *Service) error {
	service.UpdatedAt = time.Now()

	query := `
		UPDATE services 
		SET name = ?, url = ?, type = ?, enabled = ?, status = ?, 
		    latency = ?, ping_latency = ?, last_checked = ?, updated_at = ?, 
		    encrypted = ?
		WHERE id = ? AND user_id = ?
	`

	var latency, pingLatency interface{}
	var lastChecked interface{}

	if service.Latency != nil {
		latency = *service.Latency
	}
	if service.PingLatency != nil {
		pingLatency = *service.PingLatency
	}
	if service.LastChecked != nil {
		lastChecked = *service.LastChecked
	}

	_, err := ss.db.Exec(query,
		service.Name, service.URL, service.Type, service.Enabled, service.Status,
		latency, pingLatency, lastChecked, service.UpdatedAt, service.Encrypted,
		service.ID, service.UserID,
	)

	return err
}

func (ss *ServiceStore) DeleteService(serviceID, userID string) error {
	query := `DELETE FROM services WHERE id = ? AND user_id = ?`
	_, err := ss.db.Exec(query, serviceID, userID)
	return err
}

func (ss *ServiceStore) UpdateServiceStatus(serviceID string, status string, latency, pingLatency *int) error {
	now := time.Now()

	query := `
		UPDATE services 
		SET status = ?, latency = ?, ping_latency = ?, last_checked = ?, updated_at = ?
		WHERE id = ?
	`

	var latencyVal, pingLatencyVal interface{}
	if latency != nil {
		latencyVal = *latency
	}
	if pingLatency != nil {
		pingLatencyVal = *pingLatency
	}

	_, err := ss.db.Exec(query, status, latencyVal, pingLatencyVal, now, now, serviceID)
	return err
}

// GetAllEnabledServices returns all enabled services across all users (for monitoring)
func (ss *ServiceStore) GetAllEnabledServices() ([]Service, error) {
	query := `
		SELECT id, user_id, name, url, type, enabled, status, latency, 
		       ping_latency, last_checked, created_at, updated_at, encrypted
		FROM services 
		WHERE enabled = 1
		ORDER BY created_at ASC
	`

	rows, err := ss.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var services []Service
	for rows.Next() {
		var service Service
		var latency, pingLatency sql.NullInt32
		var lastChecked sql.NullTime

		err := rows.Scan(
			&service.ID, &service.UserID, &service.Name, &service.URL, &service.Type,
			&service.Enabled, &service.Status, &latency, &pingLatency, &lastChecked,
			&service.CreatedAt, &service.UpdatedAt, &service.Encrypted,
		)
		if err != nil {
			return nil, fmt.Errorf("scan error: %w", err)
		}

		// Handle nullable fields
		if latency.Valid {
			latencyInt := int(latency.Int32)
			service.Latency = &latencyInt
		}
		if pingLatency.Valid {
			pingLatencyInt := int(pingLatency.Int32)
			service.PingLatency = &pingLatencyInt
		}
		if lastChecked.Valid {
			service.LastChecked = &lastChecked.Time
		}

		services = append(services, service)
	}

	return services, nil
}
