package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os/exec"
	"os/signal"
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
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) Validate() error {
	if s.Name == "" || s.URL == "" {
		return errors.New("missing service name or URL")
	}
	return nil
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
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *ServiceStore) load() error {
	rows, err := s.db.Query("SELECT id, name, url, enabled FROM services")
	if err != nil {
		return err
	}
	defer rows.Close()

	s.mu.Lock()
	defer s.mu.Unlock()
	for rows.Next() {
		var svc Service
		var enabledInt int
		if err := rows.Scan(&svc.ID, &svc.Name, &svc.URL, &enabledInt); err != nil {
			return err
		}
		svc.Enabled = enabledInt != 0
		s.services[svc.ID] = &svc
	}
	return nil
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

	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("INSERT INTO services (id, name, url, enabled) VALUES (?, ?, ?, ?)", svc.ID, svc.Name, svc.URL, svc.Enabled)
	if err == nil {
		s.services[svc.ID] = svc
	}
	return err
}

func (s *ServiceStore) Update(svc *Service) error {
	if err := svc.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE services SET name=?, url=?, enabled=? WHERE id=?", svc.Name, svc.URL, svc.Enabled, svc.ID)
	if err == nil {
		s.services[svc.ID] = svc
	}
	return err
}

func (s *ServiceStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM services WHERE id=?", id)
	if err == nil {
		delete(s.services, id)
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

func (c *ClientManager) Broadcast(msg interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for conn := range c.clients {
		if err := conn.WriteJSON(msg); err != nil {
			conn.Close()
			delete(c.clients, conn)
		}
	}
}

func checkHTTP(url string) (bool, int64) {
	start := time.Now()
	resp, err := http.Get(url)
	if err != nil || resp.StatusCode >= 400 {
		return false, 0
	}
	resp.Body.Close()
	return true, time.Since(start).Milliseconds()
}

func checkPing(host string) (bool, int64) {
	start := time.Now()
	cmd := exec.Command("ping", "-n", "1", host)
	err := cmd.Run()
	if err != nil {
		return false, 0
	}
	return true, time.Since(start).Milliseconds()
}

func startMonitor(ctx context.Context, store *ServiceStore, clients *ClientManager) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, svc := range store.All() {
				if !svc.Enabled {
					continue
				}

				url := svc.URL
				host := strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://")
				parts := strings.Split(host, "/")
				host = parts[0]

				upHTTP, httpLatency := checkHTTP(url)
				upPing, pingLatency := checkPing(host)

				status := "down"
				if upHTTP || upPing {
					status = "up"
				}
				log.Printf("✅ Checked %s: %s (%dms HTTP, %dms ping)", svc.Name, status, httpLatency, pingLatency)
				clients.Broadcast(map[string]interface{}{
					"id":           svc.ID,
					"name":         svc.Name,
					"url":          svc.URL,
					"status":       status,
					"latency":      httpLatency,
					"ping_latency": pingLatency,
					"last_checked": time.Now().Format(time.RFC3339),
				})
			}
		}
	}
}

func main() {
	db, _ := sql.Open("sqlite3", "services.db")
	db.Exec("CREATE TABLE IF NOT EXISTS services (id TEXT PRIMARY KEY, name TEXT, url TEXT, enabled INTEGER)")
	store, _ := NewServiceStore(db)
	clients := NewClientManager()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go startMonitor(ctx, store, clients)

	r := mux.NewRouter()
	r.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Upgrade(w, r, nil, 1024, 1024)
		if err != nil {
			http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
			return
		}
		clients.mu.Lock()
		clients.clients[conn] = true
		clients.mu.Unlock()
	})

	r.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(store.All())
	}).Methods("GET")

	r.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		var svc Service
		if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if svc.ID == "" {
			svc.ID = uuid.New().String()
		}
		if err := store.Add(&svc); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(svc)
	}).Methods("POST")

	r.HandleFunc("/services/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		var svc Service
		json.NewDecoder(r.Body).Decode(&svc)
		svc.ID = id
		if err := store.Update(&svc); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}).Methods("PUT")

	r.HandleFunc("/services/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		if err := store.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}).Methods("DELETE")

	log.Println("🚀 Server running on http://localhost:8080")
	http.ListenAndServe(":8080", enableCORS(r))
}
