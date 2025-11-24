package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

const (
	EnvDiscordPort         = "DISCORD_PORT"
	EnvDiscordSharedSecret = "DISCORD_SHARED_SECRET"
	EnvDiscordWebhookURL   = "DISCORD_WEBHOOK_URL"
)

// ============================================================================
// DATA STRUCTURES
// ============================================================================

type NotificationRequest struct {
	Title     string `json:"title"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

type DiscordWebhookPayload struct {
	Content string         `json:"content,omitempty"`
	Embeds  []DiscordEmbed `json:"embeds,omitempty"`
}

type DiscordEmbed struct {
	Title       string              `json:"title,omitempty"`
	Description string              `json:"description,omitempty"`
	Color       int                 `json:"color,omitempty"`
	Timestamp   string              `json:"timestamp,omitempty"`
	Footer      *DiscordEmbedFooter `json:"footer,omitempty"`
}

type DiscordEmbedFooter struct {
	Text string `json:"text"`
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	if os.Getenv(EnvDiscordSharedSecret) == "" {
		log.Fatal(EnvDiscordSharedSecret + " environment variable is required")
	}

	if os.Getenv(EnvDiscordWebhookURL) == "" {
		log.Fatal(EnvDiscordWebhookURL + " environment variable is required")
	}

	r := chi.NewRouter()

	// Middlewares
	r.Use(customLogger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	// Public endpoints
	r.Get("/health", handleHealth)

	// Internal endpoints (protected by shared secret)
	r.Group(func(r chi.Router) {
		r.Use(sharedSecretMiddleware)
		r.Post("/api/notifications", handleReceiveNotification)
	})

	port := os.Getenv(EnvDiscordPort)
	if port == "" {
		port = "8081"
	}

	log.Printf("═══════════════════════════════════════════════════════════")
	log.Printf("🤖 Discord Notifier Server")
	log.Printf("═══════════════════════════════════════════════════════════")
	log.Printf("Port:             %s", port)
	log.Printf("Security:         Shared Secret ✓")
	log.Printf("Webhook URL:      %s", maskWebhookURL(os.Getenv(EnvDiscordWebhookURL)))
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

		log.Printf("[REQUEST] %s %s | From: %s | User-Agent: %s",
			r.Method,
			r.URL.Path,
			getClientIP(r),
			r.UserAgent(),
		)

		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		log.Printf("[RESPONSE] %s %s | Status: %d | Duration: %v",
			r.Method,
			r.URL.Path,
			ww.Status(),
			time.Since(start),
		)
	})
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
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
	expectedSecret := os.Getenv(EnvDiscordSharedSecret)
	if expectedSecret == "" {
		log.Printf("[SECURITY] ⚠️  %s not set!", EnvDiscordSharedSecret)
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

	return subtle.ConstantTimeCompare(
		[]byte(expectedSecret),
		[]byte(providedSecret),
	) == 1
}

// ============================================================================
// NOTIFICATION HANDLER
// ============================================================================

func handleReceiveNotification(w http.ResponseWriter, r *http.Request) {
	var req NotificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Message == "" {
		http.Error(w, "Missing required fields: title, message", http.StatusBadRequest)
		return
	}

	timestamp, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		http.Error(w, "Invalid timestamp", http.StatusBadRequest)
		return
	}

	// Send to Discord
	if err := sendToDiscord(req, timestamp); err != nil {
		log.Printf("[DISCORD] ❌ Failed to send notification: %v", err)
		http.Error(w, "Failed to send to Discord", http.StatusInternalServerError)
		return
	}

	log.Printf("[DISCORD] ✓ Sent notification: title=%s", req.Title)
	w.WriteHeader(http.StatusOK)
}

func sendToDiscord(req NotificationRequest, timestamp time.Time) error {
	webhookURL := os.Getenv(EnvDiscordWebhookURL)
	if webhookURL == "" {
		return fmt.Errorf("DISCORD_WEBHOOK_URL not set")
	}

	// Create Discord embed
	embed := DiscordEmbed{
		Title:       req.Title,
		Description: req.Message,
		Color:       0x5865F2, // Discord blurple color
		Timestamp:   timestamp.Format(time.RFC3339),
		Footer: &DiscordEmbedFooter{
			Text: "Stampit Notification",
		},
	}

	payload := DiscordWebhookPayload{
		Embeds: []DiscordEmbed{embed},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discord webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// ============================================================================
// HEALTH ENDPOINT
// ============================================================================

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

func maskWebhookURL(url string) string {
	if url == "" {
		return "not set"
	}
	// Mask most of the URL, only show beginning and end
	if len(url) > 50 {
		return url[:20] + "..." + url[len(url)-10:]
	}
	return url
}
