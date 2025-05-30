package main

import (
	"context"
	"log"
)

type Monitor struct {
	store       *ServiceStore
	userStore   *UserStore
	clients     *ClientManager
	rateLimiter *RateLimiter
	config      *SecurityConfig
	monitor     *SecurityMonitor
}

type SecurityMonitor struct{}

func NewSecurityMonitor() *SecurityMonitor {
	return &SecurityMonitor{}
}

func (m *Monitor) startMonitoring(ctx context.Context) {
	// No-op for now; add monitoring logic later
}

func (sm *SecurityMonitor) alert(msg string) {
	log.Printf("⚠️ ALERT: %s", msg)
}
