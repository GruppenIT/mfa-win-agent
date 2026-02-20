package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Counters tracks authentication metrics between heartbeats.
type Counters struct {
	AuthSuccess atomic.Int64
	AuthFailure atomic.Int64
}

// IdPStatus represents the current state of the IdP module.
type IdPStatus struct {
	Active       bool   `json:"active"`
	Port         int    `json:"port"`
	CertValidTo  string `json:"certValidTo,omitempty"`
}

// Sender sends periodic heartbeats to the MFA Gruppen backend.
type Sender struct {
	apiBaseURL    string
	apiKey        string
	agentID       string
	interval      time.Duration
	client        *http.Client
	counters      *Counters
	idpStatusFn   func() IdPStatus
	sessionCountFn func() int
	mu            sync.Mutex
}

// NewSender creates a new heartbeat sender.
func NewSender(
	apiBaseURL, apiKey, agentID string,
	intervalSec int,
	counters *Counters,
	idpStatusFn func() IdPStatus,
	sessionCountFn func() int,
) *Sender {
	if intervalSec <= 0 {
		intervalSec = 300 // default 5 minutes
	}
	return &Sender{
		apiBaseURL:     apiBaseURL,
		apiKey:         apiKey,
		agentID:        agentID,
		interval:       time.Duration(intervalSec) * time.Second,
		client:         &http.Client{Timeout: 10 * time.Second},
		counters:       counters,
		idpStatusFn:    idpStatusFn,
		sessionCountFn: sessionCountFn,
	}
}

// Start begins sending heartbeats. Blocks until context is cancelled.
func (s *Sender) Start(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Send initial heartbeat
	s.send(ctx)

	for {
		select {
		case <-ticker.C:
			s.send(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Sender) send(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Collect and reset counters
	success := s.counters.AuthSuccess.Swap(0)
	failure := s.counters.AuthFailure.Swap(0)

	idpStatus := IdPStatus{Active: false}
	if s.idpStatusFn != nil {
		idpStatus = s.idpStatusFn()
	}

	activeSessions := 0
	if s.sessionCountFn != nil {
		activeSessions = s.sessionCountFn()
	}

	payload := map[string]interface{}{
		"agentId":   s.agentID,
		"agentType": "RADIUS",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"status":    "online",
		"modules": map[string]interface{}{
			"idp": idpStatus,
		},
		"counters": map[string]interface{}{
			"authSuccess":    success,
			"authFailure":    failure,
			"activeSessions": activeSessions,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("heartbeat marshal error", "error", err)
		return
	}

	url := fmt.Sprintf("%s/api/agents/%s/heartbeat", s.apiBaseURL, s.agentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Error("heartbeat request creation error", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.apiKey)

	resp, err := s.client.Do(req)
	if err != nil {
		slog.Warn("heartbeat send failed", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		slog.Warn("heartbeat non-success response", "status", resp.StatusCode)
	} else {
		slog.Debug("heartbeat sent successfully")
	}
}
