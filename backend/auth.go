package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Global variables for JWT configuration
var (
	jwtSecret         []byte
	jwtRefreshSecret  []byte
	jwtExpiration     = time.Duration(1) * time.Hour    // 1 hour for access tokens
	refreshExpiration = time.Duration(7*24) * time.Hour // 7 days for refresh tokens
	bcryptCost        = bcrypt.DefaultCost
)

// AuthStore manages authentication state
type AuthStore struct {
	mu            sync.RWMutex
	attempts      map[string]*LoginAttempt
	revokedTokens map[string]time.Time
	refreshTokens map[string]*RefreshToken
}

// LoginAttempt tracks login attempts
type LoginAttempt struct {
	IP          string
	Email       string
	Attempts    int
	LockedUntil time.Time
	Violations  []time.Time
}

// RefreshToken represents a refresh token
type RefreshToken struct {
	Token     string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// NewAuthStore creates a new auth store
func NewAuthStore() *AuthStore {
	store := &AuthStore{
		attempts:      make(map[string]*LoginAttempt),
		revokedTokens: make(map[string]time.Time),
		refreshTokens: make(map[string]*RefreshToken),
	}

	go store.cleanupRoutine()
	return store
}

// cleanupRoutine periodically cleans up expired data
func (as *AuthStore) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		as.cleanup()
	}
}

// cleanup removes expired entries
func (as *AuthStore) cleanup() {
	as.mu.Lock()
	defer as.mu.Unlock()

	now := time.Now()

	// Clean expired login attempts
	for key, attempt := range as.attempts {
		if now.After(attempt.LockedUntil.Add(24 * time.Hour)) {
			delete(as.attempts, key)
		}
	}

	// Clean expired revoked tokens
	for token, expiry := range as.revokedTokens {
		if now.After(expiry) {
			delete(as.revokedTokens, token)
		}
	}

	// Clean expired refresh tokens
	for token, rt := range as.refreshTokens {
		if now.After(rt.ExpiresAt) {
			delete(as.refreshTokens, token)
		}
	}
}

// Reset login attempts (useful after successful login)
func (as *AuthStore) resetLoginAttempts(ip, email string) {
	as.mu.Lock()
	defer as.mu.Unlock()

	key := ip + ":" + email
	delete(as.attempts, key)
}

// Get remaining lockout time
func (as *AuthStore) getLockoutTimeRemaining(ip, email string) time.Duration {
	as.mu.RLock()
	defer as.mu.RUnlock()

	key := ip + ":" + email
	attempt, exists := as.attempts[key]
	if !exists {
		return 0
	}

	remaining := time.Until(attempt.LockedUntil)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// recordLoginAttempt records a login attempt and returns whether login is allowed
func (as *AuthStore) recordLoginAttempt(ip, email string, maxAttempts int, lockoutDuration time.Duration) bool {
	as.mu.Lock()
	defer as.mu.Unlock()

	key := ip + ":" + email
	attempt, exists := as.attempts[key]

	if !exists {
		attempt = &LoginAttempt{
			IP:         ip,
			Email:      email,
			Violations: make([]time.Time, 0),
		}
		as.attempts[key] = attempt
	}

	now := time.Now()

	// Check if still locked
	if now.Before(attempt.LockedUntil) {
		return false
	}

	// Reset attempts if enough time has passed
	if len(attempt.Violations) > 0 && now.Sub(attempt.Violations[len(attempt.Violations)-1]) > time.Hour {
		attempt.Attempts = 0
		attempt.Violations = attempt.Violations[:0]
	}

	attempt.Attempts++
	attempt.Violations = append(attempt.Violations, now)

	// Lock account after max attempts
	if attempt.Attempts >= maxAttempts {
		attempt.LockedUntil = now.Add(lockoutDuration)
		return false
	}

	return true
}

// isTokenRevoked checks if a token has been revoked
func (as *AuthStore) isTokenRevoked(tokenStr string) bool {
	as.mu.RLock()
	defer as.mu.RUnlock()

	_, revoked := as.revokedTokens[tokenStr]
	return revoked
}

// revokeToken revokes a token
func (as *AuthStore) revokeToken(tokenStr string, expiry time.Time) {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.revokedTokens[tokenStr] = expiry
}

// Store refresh token
func (as *AuthStore) storeRefreshToken(token, userID string, expiresAt time.Time) {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.refreshTokens[token] = &RefreshToken{
		Token:     token,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
}

// Validate and consume refresh token
func (as *AuthStore) validateRefreshToken(token string) (*RefreshToken, bool) {
	as.mu.Lock()
	defer as.mu.Unlock()

	rt, exists := as.refreshTokens[token]
	if !exists {
		return nil, false
	}

	// Check if expired
	if time.Now().After(rt.ExpiresAt) {
		delete(as.refreshTokens, token)
		return nil, false
	}

	return rt, true
}

// Revoke refresh token
func (as *AuthStore) revokeRefreshToken(token string) {
	as.mu.Lock()
	defer as.mu.Unlock()

	delete(as.refreshTokens, token)
}

// JWT Functions

// initJWT initializes JWT secrets
func initJWT() error {
	secret := os.Getenv("JWT_SECRET")
	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")

	if secret == "" {
		randomBytes := make([]byte, 64)
		if _, err := rand.Read(randomBytes); err != nil {
			return fmt.Errorf("failed to generate JWT secret: %w", err)
		}
		jwtSecret = randomBytes
		log.Println("🔑 Generated random JWT secret (set JWT_SECRET env var for production)")
	} else {
		jwtSecret = []byte(secret)
		log.Println("🔑 Using JWT secret from environment")
	}

	if refreshSecret == "" {
		randomBytes := make([]byte, 64)
		if _, err := rand.Read(randomBytes); err != nil {
			return fmt.Errorf("failed to generate JWT refresh secret: %w", err)
		}
		jwtRefreshSecret = randomBytes
		log.Println("🔑 Generated random JWT refresh secret (set JWT_REFRESH_SECRET env var for production)")
	} else {
		jwtRefreshSecret = []byte(refreshSecret)
		log.Println("🔑 Using JWT refresh secret from environment")
	}

	return nil
}

// generateTokenPair generates access and refresh tokens
func generateTokenPair(user *User) (string, string, int64, error) {
	now := time.Now()
	accessExpiration := now.Add(jwtExpiration)
	refreshExpirationTime := now.Add(refreshExpiration)

	// Access token
	accessClaims := &Claims{
		UserID:    user.ID,
		Email:     user.Email,
		Role:      user.Role,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessExpiration),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Subject:   user.ID,
			ID:        uuid.New().String(),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		return "", "", 0, err
	}

	// Refresh token
	refreshClaims := &Claims{
		UserID:    user.ID,
		Email:     user.Email,
		Role:      user.Role,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExpirationTime),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Subject:   user.ID,
			ID:        uuid.New().String(),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(jwtRefreshSecret)
	if err != nil {
		return "", "", 0, err
	}

	return accessTokenString, refreshTokenString, accessExpiration.Unix(), nil
}

// validateToken validates a JWT token
func validateToken(tokenString string, authStore *AuthStore) (*Claims, error) {
	if authStore.isTokenRevoked(tokenString) {
		return nil, errors.New("token has been revoked")
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			return nil, errors.New("invalid token claims")
		}

		// Use appropriate secret based on token type
		if claims.TokenType == "refresh" {
			return jwtRefreshSecret, nil
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// Extract token from Authorization header
func extractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("authorization header required")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid authorization header format")
	}

	return parts[1], nil
}

// Password Functions

// validatePasswordComplexity validates password complexity requirements
func validatePasswordComplexity(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	if len(password) > 128 {
		return errors.New("password too long (max 128 characters)")
	}

	var (
		hasUpper   = regexp.MustCompile(`[A-Z]`).MatchString(password)
		hasLower   = regexp.MustCompile(`[a-z]`).MatchString(password)
		hasNumber  = regexp.MustCompile(`[0-9]`).MatchString(password)
		hasSpecial = regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\?]`).MatchString(password)
	)

	missing := []string{}
	if !hasUpper {
		missing = append(missing, "uppercase letter")
	}
	if !hasLower {
		missing = append(missing, "lowercase letter")
	}
	if !hasNumber {
		missing = append(missing, "number")
	}
	if !hasSpecial {
		missing = append(missing, "special character")
	}

	if len(missing) > 0 {
		return fmt.Errorf("password must contain: %s", strings.Join(missing, ", "))
	}

	// Check for common weak passwords
	commonPasswords := []string{
		"password", "123456", "password123", "admin", "qwerty",
		"letmein", "welcome", "monkey", "dragon", "master",
	}

	lowerPassword := strings.ToLower(password)
	for _, weak := range commonPasswords {
		if strings.Contains(lowerPassword, weak) {
			return errors.New("password contains common weak patterns")
		}
	}

	return nil
}

// hashPassword hashes a password using bcrypt
func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedPassword), nil
}

// comparePassword compares a password with its hash
func comparePassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// generateSecurePassword generates a secure random password
func generateSecurePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	password := make([]byte, length)

	for i := range password {
		randomIndex := make([]byte, 1)
		rand.Read(randomIndex)
		password[i] = charset[randomIndex[0]%byte(len(charset))]
	}

	return string(password)
}

// Helper function to validate email format
func validateEmail(email string) error {
	if email == "" {
		return errors.New("email is required")
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return errors.New("invalid email format")
	}

	if len(email) > 254 {
		return errors.New("email too long")
	}

	return nil
}
