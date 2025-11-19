package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

const (
	EnvSSENotifierPort         = "SSE_NOTIFIER_PORT"
	EnvSSENotifierSharedSecret = "SSE_NOTIFIER_SHARED_SECRET"
	EnvAllowedOrigin           = "ALLOWED_ORIGIN"
	EnvConnectionURL           = "CONNECTION_URL"
)

// ============================================================================
// DATA STRUCTURES
// ============================================================================

type Ticket struct {
	UserID    string
	Email     string
	CompanyID string
	CreatedAt time.Time
}

type CompanyChannel struct {
	CompanyID     string
	Channel       chan Notification
	ConnectedUser map[string]*User
	CreatedAt     time.Time
	mu            sync.RWMutex
}

type Notification struct {
	Type      string         `json:"type"`
	Title     string         `json:"title"`
	Message   string         `json:"message"`
	Data      map[string]any `json:"data"`
	CompanyID *string        `json:"company_id,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}

type User struct {
	UserID      string
	Email       string
	ConnectedAt time.Time
}

// ============================================================================
// GLOBAL VARIABLES
// ============================================================================

// Storage
var (
	// Ticket storage (temporary, single-use)
	ticketsByTicketID = make(map[string]*Ticket)
	ticketsMu         sync.RWMutex

	// Company channels (one channel per company)
	companyChannelsByCompanyID = make(map[string]*CompanyChannel)
	companyChannelsMu          sync.RWMutex

	startTime = time.Now()
)

// ============================================================================
// MAIN
// ============================================================================
func main() {
	if os.Getenv(EnvSSENotifierSharedSecret) == "" {
		log.Fatal(EnvSSENotifierSharedSecret + " environment variable is required")
	}

	r := chi.NewRouter()

	// Middlewares
	// r.Use(middleware.Logger)
	r.Use(customLogger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(corsMiddleware())

	// Public endpoints
	r.Get("/health", handleHealth)
	r.Get("/events", handleSSEEvents) // Client subscribes to sse events here

	// Internal endpoints
	r.Group(func(r chi.Router) {
		r.Use(sharedSecretMiddleware)

		r.Post("/api/notifications", handleReceiveNotification)
		r.Get("/internal/stats", handleStats)
		r.Post("/internal/store-ticket", handleStoreTicket)
	})

	// Start background workers
	go cleanupWorker()

	port := os.Getenv(EnvSSENotifierPort)
	if port == "" {
		port = "8080"
	}

	log.Printf("═══════════════════════════════════════════════════════════")
	log.Printf("🚀 SSE Notifier Server")
	log.Printf("═══════════════════════════════════════════════════════════")
	log.Printf("Port:             %s", port)
	log.Printf("Security:         Shared Secret ✓")
	log.Printf("═══════════════════════════════════════════════════════════")

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}

// ============================================================================
// MIDDLEWARES
// ============================================================================

func customLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Log request details
		log.Printf("[REQUEST] %s %s | From: %s | User-Agent: %s | Origin: %s",
			r.Method,
			r.URL.Path,
			getClientIP(r),
			r.UserAgent(),
			r.Header.Get("Origin"),
		)

		// Wrap response writer to capture status
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		// Log response
		log.Printf("[RESPONSE] %s %s | Status: %d | Duration: %v",
			r.Method,
			r.URL.Path,
			ww.Status(),
			time.Since(start),
		)
	})
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}

	// Check X-Real-IP header (nginx)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fallback to RemoteAddr
	return r.RemoteAddr
}

func corsMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := os.Getenv(EnvAllowedOrigin)
			if origin == "" {
				origin = "*"
			}
			allowedOrigins := strings.Split(origin, ",")

			if r.Header.Get("Origin") != "" && slices.Contains(allowedOrigins, r.Header.Get("Origin")) {
				w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			}

			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func sharedSecretMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validateSharedSecret(r) {
			log.Printf("[SECURITY] ⚠️  Unauthorized access attempt to %s from %s",
				r.URL.Path, r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validateSharedSecret(r *http.Request) bool {
	expectedSecret := os.Getenv(EnvSSENotifierSharedSecret)
	if expectedSecret == "" {
		log.Printf("[SECURITY] ⚠️  %s not set!", EnvSSENotifierSharedSecret)
		return false
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return false
	}

	providedSecret := parts[1]

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(
		[]byte(expectedSecret),
		[]byte(providedSecret),
	) == 1
}

// ============================================================================
// TICKET MANAGEMENT
// ============================================================================

type StoreTicketRequest struct {
	UserID    string `json:"userId"`
	Email     string `json:"email"`
	CompanyID string `json:"companyId"`
}

type StoreTicketResponse struct {
	Ticket        string `json:"ticket"`
	ConnectionURL string `json:"connectionUrl"`
}

func handleStoreTicket(w http.ResponseWriter, r *http.Request) {
	var req StoreTicketRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// Validate required fields
	if req.UserID == "" || req.Email == "" || req.CompanyID == "" {
		http.Error(w, "Missing required fields: user_id, email, company_id", http.StatusBadRequest)
		return
	}
	// Generate secure random ticket ID
	ticketID, err := generateTicketID()
	if err != nil {
		log.Printf("[TICKET] ❌ Failed to generate ticket: %v", err)
		http.Error(w, "Failed to generate ticket", http.StatusInternalServerError)
		return
	}

	// Store ticket
	ticket := &Ticket{
		UserID:    req.UserID,
		Email:     req.Email,
		CompanyID: req.CompanyID,
		CreatedAt: time.Now(),
	}

	ticketsMu.Lock()
	ticketsByTicketID[ticketID] = ticket
	ticketsMu.Unlock()

	log.Printf("[TICKET] ✓ Stored: user=%s company=%s ticket=%s", req.Email, req.CompanyID, ticketID)

	// Return ticket
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(StoreTicketResponse{
		Ticket:        ticketID,
		ConnectionURL: fmt.Sprintf("%s/events?ticket=%s", os.Getenv(EnvConnectionURL), ticketID),
	})
}

func generateTicketID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func consumeTicket(ticketID string) *Ticket {
	ticketsMu.Lock()
	defer ticketsMu.Unlock()

	ticket, exists := ticketsByTicketID[ticketID]
	if !exists {
		return nil
	}

	// Single-use: delete after consumption
	delete(ticketsByTicketID, ticketID)
	return ticket
}

// ============================================================================
// NOTIFICATION CHANNEL MANAGEMENT
// ============================================================================

func getOrCreateCompanyChannel(companyID string) *CompanyChannel {
	companyChannelsMu.RLock()
	ch, ok := companyChannelsByCompanyID[companyID]
	companyChannelsMu.RUnlock()
	if ok {
		return ch
	}

	// Create new channel if it doesn't exist
	companyChannelsMu.Lock()
	defer companyChannelsMu.Unlock()
	if ch, ok := companyChannelsByCompanyID[companyID]; ok {
		return ch
	}

	ch = &CompanyChannel{
		CompanyID:     companyID,
		Channel:       make(chan Notification),
		ConnectedUser: make(map[string]*User),
		CreatedAt:     time.Now(),
	}
	companyChannelsByCompanyID[companyID] = ch

	slog.Info("[COMPANY] Created channel for company", slog.String("company_id", companyID))

	return ch
}

func cleanupCompanyChannel(companyID string) {
	companyChannelsMu.Lock()
	defer companyChannelsMu.Unlock()

	if ch, exists := companyChannelsByCompanyID[companyID]; exists {
		close(ch.Channel)
		delete(companyChannelsByCompanyID, companyID)
		log.Printf("[COMPANY] 🧹 Cleaned up channel for company=%s (no users)", companyID)
	}
}

// ============================================================================
// SSE CONNECTION HANDLER
// ============================================================================

func handleSSEEvents(w http.ResponseWriter, r *http.Request) {
	// Extract and validate ticket
	ticketID := r.URL.Query().Get("ticket")
	if ticketID == "" {
		http.Error(w, "Missing ticket parameter", http.StatusUnauthorized)
		return
	}

	ticket := consumeTicket(ticketID)
	if ticket == nil {
		log.Printf("[SSE] ❌ Invalid ticket: %s", ticketID)
		http.Error(w, "Invalid or expired ticket", http.StatusUnauthorized)
		return
	}
	log.Printf("[SSE] ✓ Connection: user=%s company=%s", ticket.Email, ticket.CompanyID)

	// Get or create company channel
	companyChannel := getOrCreateCompanyChannel(ticket.CompanyID)

	// Register user in company channel
	userInfo := &User{
		UserID:      ticket.UserID,
		Email:       ticket.Email,
		ConnectedAt: time.Now(),
	}

	companyChannel.mu.Lock()
	companyChannel.ConnectedUser[ticket.UserID] = userInfo
	userCount := len(companyChannel.ConnectedUser)
	companyChannel.mu.Unlock()

	log.Printf("[SSE] 👥 Company %s: %d users connected", ticket.CompanyID, userCount)

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Cleanup on disconnect
	defer func() {
		companyChannel.mu.Lock()
		delete(companyChannel.ConnectedUser, ticket.UserID)
		remainingUsers := len(companyChannel.ConnectedUser)
		companyChannel.mu.Unlock()

		duration := time.Since(userInfo.ConnectedAt)
		log.Printf("[SSE] ✗ Disconnected: user=%s duration=%v remaining=%d",
			ticket.Email, duration, remainingUsers)

		// Cleanup company channel if no users left
		if remainingUsers == 0 {
			cleanupCompanyChannel(ticket.CompanyID)
		}
	}()

	// Send initial connection message
	sendEvent(w, "connected", map[string]interface{}{
		"message":    "Connected to Notifier",
		"user":       ticket.Email,
		"company_id": ticket.CompanyID,
		"timestamp":  time.Now().Format(time.RFC3339),
	})

	// Stream events from company channel
	for {
		select {
		case <-r.Context().Done():
			return
		case notification, ok := <-companyChannel.Channel:
			if !ok {
				return
			}
			sendEvent(w, notification.Type, notification)
		}
	}
}

func sendEvent(w http.ResponseWriter, eventType string, data any) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("[SSE] ❌ Failed to marshal event: %v", err)
		return
	}

	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, jsonData)

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// ============================================================================
// NOTIFICATION HANDLER
// ============================================================================

type NotificationRequest struct {
	CompanyID string `json:"companyIdd"`
	ByUser    string `json:"byUser"`
	Title     string `json:"title"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

func handleReceiveNotification(w http.ResponseWriter, r *http.Request) {
	var req NotificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.CompanyID == "" {
		http.Error(w, "Missing company_id", http.StatusBadRequest)
		return
	}

	timestamp, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		http.Error(w, "Invalid timestamp", http.StatusBadRequest)
		return
	}
	// Create notification
	notification := Notification{
		Type:      "notification",
		Title:     req.Title,
		Message:   req.Message,
		CompanyID: &req.CompanyID,
		Timestamp: timestamp,
	}

	// Send to company
	usersNotified := sendToCompany(req.CompanyID, notification)
	if usersNotified == 0 {
		log.Printf("[NOTIFICATION] ❌ Failed to send to company=%s", req.CompanyID)
	}

	// do nothing
	w.WriteHeader(http.StatusOK)
}

func sendToCompany(companyID string, notification Notification) int {
	companyChannelsMu.RLock()
	companyChannel, exists := companyChannelsByCompanyID[companyID]
	companyChannelsMu.RUnlock()

	if !exists {
		log.Printf("[RECIEVE NOTIFICATION] ⚠️  No active connections for company=%s", companyID)
		return 0
	}

	companyChannel.mu.RLock()
	userCount := len(companyChannel.ConnectedUser)
	companyChannel.mu.RUnlock()

	// Send to company channel (non-blocking)
	select {
	case companyChannel.Channel <- notification:
		return userCount
	default:
		log.Printf("[RECIEVE NOTIFICATION] ⚠️  Channel full for company=%s, notification dropped", companyID)
		return 0
	}
}

// ============================================================================
// HEALTH & STATS ENDPOINTS
// ============================================================================

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	ticketsMu.RLock()
	ticketCount := len(ticketsByTicketID)
	ticketsMu.RUnlock()

	companyChannelsMu.RLock()
	companyCount := len(companyChannelsByCompanyID)

	totalUsers := 0
	companyStats := make([]map[string]interface{}, 0)

	for companyID, ch := range companyChannelsByCompanyID {
		ch.mu.RLock()
		userCount := len(ch.ConnectedUser)
		ch.mu.RUnlock()

		totalUsers += userCount

		companyStats = append(companyStats, map[string]interface{}{
			"company_id": companyID,
			"users":      userCount,
			"created_at": ch.CreatedAt.Format(time.RFC3339),
		})
	}
	companyChannelsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"uptime":            time.Since(startTime).String(),
		"total_users":       totalUsers,
		"active_companies":  companyCount,
		"pending_tickets":   ticketCount,
		"company_breakdown": companyStats,
	})
}

// ============================================================================
// BACKGROUND WORKERS
// ============================================================================

func cleanupWorker() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cleanupStaleTickets()
	}
}

func cleanupStaleTickets() {
	ticketsMu.Lock()
	defer ticketsMu.Unlock()

	now := time.Now()
	staleThreshold := 5 * time.Minute
	deleted := 0

	for id, ticket := range ticketsByTicketID {
		if now.Sub(ticket.CreatedAt) > staleThreshold {
			delete(ticketsByTicketID, id)
			deleted++
		}
	}

	if deleted > 0 {
		log.Printf("[CLEANUP] 🧹 Deleted %d stale tickets", deleted)
	}
}
