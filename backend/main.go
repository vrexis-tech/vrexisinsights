package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// Config struct holds configuration values
type Config struct {
	DBPath string
	Port   string
	JWTKey string
}

// User struct for user authentication
type User struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Password  string `json:"password,omitempty"` // omitempty to not send password in responses
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// Service struct for monitoring services
type Service struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	Latency     int       `json:"latency"`
	PingLatency int       `json:"ping_latency"`
	LastChecked time.Time `json:"last_checked"`
}

// Credentials struct for login
type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Registration struct
type Registration struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// Response structs
type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// Global database variable
var globalDB *sql.DB

// Load configuration from environment variables
func loadConfig() (*Config, error) {
	port := getEnv("PORT", "8080")
	dbPath := getEnv("DB_PATH", "secure_services.db")
	jwtKey := getEnv("JWT_KEY", "your-secret-key-change-this")

	return &Config{
		DBPath: dbPath,
		Port:   port,
		JWTKey: jwtKey,
	}, nil
}

// Get environment variable with fallback to default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Initialize database and create tables
func initDatabase(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection parameters
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	// Create tables if they don't exist
	err = createTables(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return db, nil
}

// Create database tables
func createTables(db *sql.DB) error {
	userTable := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		first_name TEXT NOT NULL,
		last_name TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	serviceTable := `
	CREATE TABLE IF NOT EXISTS services (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		url TEXT NOT NULL,
		type TEXT NOT NULL,
		status TEXT DEFAULT 'unknown',
		latency INTEGER DEFAULT 0,
		ping_latency INTEGER DEFAULT 0,
		last_checked DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users (id)
	);`

	if _, err := db.Exec(userTable); err != nil {
		return err
	}

	if _, err := db.Exec(serviceTable); err != nil {
		return err
	}

	return nil
}

// JWT Middleware for authentication
func jwtMiddleware(next http.Handler, jwtKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		if tokenString == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Missing token"})
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtKey), nil
		})

		if err != nil || !token.Valid {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid token"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Health Check handler
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "Server is running"})
}

// Login Handler - FIXED
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid request"})
		return
	}

	// Validate user credentials
	user, err := getUserByEmail(r.Context(), creds.Email)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid credentials"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)) != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid credentials"})
		return
	}

	// Create JWT token
	token, err := generateJWT(user)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to generate token"})
		return
	}

	// Remove password from user object before sending
	user.Password = ""

	// Send token and user in response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		Token: token,
		User:  *user,
	})
}

// Registration Handler - NEW
func registerHandler(w http.ResponseWriter, r *http.Request) {
	var reg Registration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid request"})
		return
	}

	// Validate input
	if reg.Email == "" || reg.Password == "" || reg.FirstName == "" || reg.LastName == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "All fields are required"})
		return
	}

	if len(reg.Password) < 6 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Password must be at least 6 characters"})
		return
	}

	// Check if user already exists
	_, err := getUserByEmail(r.Context(), reg.Email)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "User already exists"})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(reg.Password), bcrypt.DefaultCost)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to hash password"})
		return
	}

	// Create user
	user := &User{
		ID:        uuid.New().String(),
		Email:     reg.Email,
		Password:  string(hashedPassword),
		FirstName: reg.FirstName,
		LastName:  reg.LastName,
	}

	err = createUser(r.Context(), user)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to create user"})
		return
	}

	// Generate token
	token, err := generateJWT(user)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to generate token"})
		return
	}

	// Remove password from response
	user.Password = ""

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(AuthResponse{
		Token: token,
		User:  *user,
	})
}

// Get user by email from database
func getUserByEmail(ctx context.Context, email string) (*User, error) {
	query := `SELECT id, email, password, first_name, last_name FROM users WHERE email = ?`
	var user User
	err := globalDB.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to query user: %w", err)
	}
	return &user, nil
}

// Create user in database
func createUser(ctx context.Context, user *User) error {
	query := `INSERT INTO users (id, email, password, first_name, last_name) VALUES (?, ?, ?, ?, ?)`
	_, err := globalDB.ExecContext(ctx, query, user.ID, user.Email, user.Password, user.FirstName, user.LastName)
	return err
}

// Generate JWT token - FIXED
func generateJWT(user *User) (string, error) {
	claims := &jwt.RegisteredClaims{
		Subject:   user.ID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // 24 hours
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("your-secret-key-change-this"))
	if err != nil {
		return "", fmt.Errorf("error generating JWT: %w", err)
	}

	return tokenString, nil
}

// Protected handler (example)
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "You have access to this protected route"})
}

// Setup routes with CORS handling - FIXED
func setupRoutes(db *sql.DB, jwtKey string) http.Handler {
	r := mux.NewRouter()

	// API v1 routes
	api := r.PathPrefix("/auth").Subrouter()

	// Public auth routes
	api.HandleFunc("/login", loginHandler).Methods("POST")
	api.HandleFunc("/register", registerHandler).Methods("POST")

	// Public routes
	r.HandleFunc("/health", healthCheckHandler).Methods("GET")

	// Protected routes with JWT middleware
	protected := r.PathPrefix("/api/v1").Subrouter()
	protected.Use(func(next http.Handler) http.Handler {
		return jwtMiddleware(next, jwtKey)
	})
	protected.HandleFunc("/protected", protectedHandler).Methods("GET")

	// Apply CORS middleware
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000", "http://127.0.0.1:3000"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}).Handler(r)

	return corsHandler
}

func main() {
	// Load configuration
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Initialize the database connection
	db, err := initDatabase(config.DBPath)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	globalDB = db // Set global DB reference

	// Create a demo user for testing
	createDemoUser()

	// Initialize routes
	routes := setupRoutes(db, config.JWTKey)

	// Graceful shutdown setup
	srv := &http.Server{
		Addr:         ":" + config.Port,
		Handler:      routes,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Run the server in a goroutine
	go func() {
		log.Printf("Server started on port %s", config.Port)
		log.Printf("Demo login: admin@vrexisinsights.com / admin123")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for an interrupt signal to gracefully shut down
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop

	// Graceful shutdown
	log.Println("Shutting down server...")

	// Create a context with a timeout for graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error shutting down server: %v", err)
	}

	// Close the database connection
	if err := db.Close(); err != nil {
		log.Printf("Error closing database: %v", err)
	}

	log.Println("Server gracefully stopped")
}

// Create demo user for testing
func createDemoUser() {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error creating demo user: %v", err)
		return
	}

	user := &User{
		ID:        uuid.New().String(),
		Email:     "admin@vrexisinsights.com",
		Password:  string(hashedPassword),
		FirstName: "Admin",
		LastName:  "User",
	}

	// Check if user already exists
	_, err = getUserByEmail(context.Background(), user.Email)
	if err == nil {
		// User already exists
		return
	}

	err = createUser(context.Background(), user)
	if err != nil {
		log.Printf("Error creating demo user: %v", err)
	} else {
		log.Printf("Demo user created: %s", user.Email)
	}
}
