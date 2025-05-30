package main

import (
	"database/sql"
	"log"
)

// UserStore handles user data and authentication
type UserStore struct {
	authStore *AuthStore
}

// ServiceStore handles monitored services
type ServiceStore struct{}

// NewUserStore returns a new UserStore
func NewUserStore(db *sql.DB, monitor *SecurityMonitor) (*UserStore, error) {
	return &UserStore{
		authStore: NewAuthStore(),
	}, nil
}

// NewServiceStore returns a new ServiceStore
func NewServiceStore(db *sql.DB, monitor *SecurityMonitor) (*ServiceStore, error) {
	return &ServiceStore{}, nil
}

// Create inserts a new user into the database (stubbed)
func (us *UserStore) Create(user *User) error {
	log.Printf("🔧 Stub: Creating user %s", user.Email)
	return nil
}

// ValidateCredentials checks if the email and password are valid (stubbed)
func (us *UserStore) ValidateCredentials(email, password string) (*User, error) {
	log.Printf("🔧 Stub: Validating credentials for %s", email)
	return &User{
		ID:    "mock-id",
		Email: email,
		Role:  "user",
	}, nil
}
