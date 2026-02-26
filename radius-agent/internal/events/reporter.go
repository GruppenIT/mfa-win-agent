package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// EventType defines the type of event being reported.
type EventType string

const (
	EventIDPAuthSuccess      EventType = "idp.auth.success"
	EventIDPAuthFailure      EventType = "idp.auth.failure"
	EventIDPAuthTOTPFailure  EventType = "idp.auth.totp_failure"
	EventIDPSessionCreated   EventType = "idp.session.created"
	EventIDPSessionExpired   EventType = "idp.session.expired"
	EventIDPSLORequested     EventType = "idp.slo.requested"
	EventIDPMetadataReq      EventType = "idp.metadata.requested"
	EventRADIUSAuthSuccess   EventType = "radius.auth.success"
	EventRADIUSAuthFailure   EventType = "radius.auth.failure"
)

// Event represents an authentication or session event to report.
type Event struct {
	Type      EventType         `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
	AgentID   string            `json:"agentId"`
	Data      map[string]string `json:"data"`
}

// Reporter sends events to the MFA Gruppen backend API.
type Reporter struct {
	apiBaseURL string
	apiKey     string
	agentID    string
	client     *http.Client
	queue      chan Event
	wg         sync.WaitGroup
}

// NewReporter creates a new event reporter.
func NewReporter(apiBaseURL, apiKey, agentID string) *Reporter {
	r := &Reporter{
		apiBaseURL: apiBaseURL,
		apiKey:     apiKey,
		agentID:    agentID,
		client:     &http.Client{Timeout: 10 * time.Second},
		queue:      make(chan Event, 1000),
	}
	return r
}

// Start begins the background event sender goroutine.
func (r *Reporter) Start(ctx context.Context) {
	r.wg.Add(1)
	go r.processQueue(ctx)
}

// Stop signals the reporter to flush and stop.
func (r *Reporter) Stop() {
	close(r.queue)
	r.wg.Wait()
}

// Report queues an event for sending.
func (r *Reporter) Report(evt Event) {
	evt.AgentID = r.agentID
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	}
	select {
	case r.queue <- evt:
	default:
		slog.Warn("event queue full, dropping event", "type", evt.Type)
	}
}

func (r *Reporter) processQueue(ctx context.Context) {
	defer r.wg.Done()

	batch := make([]Event, 0, 50)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case evt, ok := <-r.queue:
			if !ok {
				// Channel closed, flush remaining
				if len(batch) > 0 {
					r.sendBatch(batch)
				}
				return
			}
			batch = append(batch, evt)
			if len(batch) >= 50 {
				r.sendBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				r.sendBatch(batch)
				batch = batch[:0]
			}
		case <-ctx.Done():
			if len(batch) > 0 {
				r.sendBatch(batch)
			}
			return
		}
	}
}

func (r *Reporter) sendBatch(events []Event) {
	payload := struct {
		Events []Event `json:"events"`
	}{Events: events}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("failed to marshal events", "error", err)
		return
	}

	url := fmt.Sprintf("%s/api/agents/%s/events", r.apiBaseURL, r.agentID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Error("failed to create event request", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.apiKey)

	resp, err := r.client.Do(req)
	if err != nil {
		slog.Warn("failed to send events", "error", err, "count", len(events))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		slog.Warn("event API returned non-success", "status", resp.StatusCode, "count", len(events))
	} else {
		slog.Debug("events sent successfully", "count", len(events))
	}
}
