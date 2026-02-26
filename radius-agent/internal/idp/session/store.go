package session

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Session represents an authenticated IdP session.
type Session struct {
	ID          string
	Username    string
	DisplayName string
	Email       string
	UPN         string
	Groups      []string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	SPEntityID  string
}

// Store manages IdP sessions in memory.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	timeout  time.Duration
}

// NewStore creates a new session store with the given timeout.
func NewStore(timeoutSeconds int) *Store {
	return &Store{
		sessions: make(map[string]*Session),
		timeout:  time.Duration(timeoutSeconds) * time.Second,
	}
}

// Create creates a new session and returns it.
func (s *Store) Create(username, displayName, email, upn string, groups []string, spEntityID string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := generateSessionID()
	now := time.Now()
	sess := &Session{
		ID:          id,
		Username:    username,
		DisplayName: displayName,
		Email:       email,
		UPN:         upn,
		Groups:      groups,
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.timeout),
		SPEntityID:  spEntityID,
	}
	s.sessions[id] = sess
	return sess
}

// Get retrieves a session by ID, returning nil if not found or expired.
func (s *Store) Get(id string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, ok := s.sessions[id]
	if !ok {
		return nil
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil
	}
	return sess
}

// Delete removes a session by ID.
func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// ActiveCount returns the number of non-expired sessions.
func (s *Store) ActiveCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	now := time.Now()
	for _, sess := range s.sessions {
		if now.Before(sess.ExpiresAt) {
			count++
		}
	}
	return count
}

// Cleanup removes all expired sessions and returns the count of removed sessions.
func (s *Store) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	removed := 0
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed
}

// StartCleanup starts a periodic cleanup goroutine.
func (s *Store) StartCleanup(done <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.Cleanup()
			case <-done:
				return
			}
		}
	}()
}

func generateSessionID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
