package session

import (
	"testing"
	"time"
)

func TestStore_CreateAndGet(t *testing.T) {
	store := NewStore(3600)

	sess := store.Create("john", "John Doe", "john@test.com", "john@test.com", []string{"Admin"}, "sp1")

	if sess.ID == "" {
		t.Error("session ID should not be empty")
	}
	if sess.Username != "john" {
		t.Errorf("expected username 'john', got '%s'", sess.Username)
	}

	// Get it back
	got := store.Get(sess.ID)
	if got == nil {
		t.Fatal("expected to find session")
	}
	if got.Username != "john" {
		t.Errorf("expected username 'john', got '%s'", got.Username)
	}
}

func TestStore_GetNonExistent(t *testing.T) {
	store := NewStore(3600)
	got := store.Get("does-not-exist")
	if got != nil {
		t.Error("expected nil for non-existent session")
	}
}

func TestStore_ExpiredSession(t *testing.T) {
	store := NewStore(1) // 1 second timeout

	sess := store.Create("jane", "", "", "", nil, "sp1")

	// Wait for expiration
	time.Sleep(2 * time.Second)

	got := store.Get(sess.ID)
	if got != nil {
		t.Error("expected nil for expired session")
	}
}

func TestStore_Delete(t *testing.T) {
	store := NewStore(3600)
	sess := store.Create("bob", "", "", "", nil, "sp1")

	store.Delete(sess.ID)

	got := store.Get(sess.ID)
	if got != nil {
		t.Error("expected nil after deletion")
	}
}

func TestStore_ActiveCount(t *testing.T) {
	store := NewStore(3600)

	store.Create("user1", "", "", "", nil, "sp1")
	store.Create("user2", "", "", "", nil, "sp1")
	store.Create("user3", "", "", "", nil, "sp1")

	if count := store.ActiveCount(); count != 3 {
		t.Errorf("expected 3 active sessions, got %d", count)
	}
}

func TestStore_Cleanup(t *testing.T) {
	store := NewStore(1) // 1 second timeout

	store.Create("user1", "", "", "", nil, "sp1")
	store.Create("user2", "", "", "", nil, "sp1")

	time.Sleep(2 * time.Second)

	removed := store.Cleanup()
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}

	if count := store.ActiveCount(); count != 0 {
		t.Errorf("expected 0 active after cleanup, got %d", count)
	}
}

func TestStore_UniqueIDs(t *testing.T) {
	store := NewStore(3600)
	ids := make(map[string]bool)

	for i := 0; i < 100; i++ {
		sess := store.Create("user", "", "", "", nil, "sp")
		if ids[sess.ID] {
			t.Fatalf("duplicate session ID generated: %s", sess.ID)
		}
		ids[sess.ID] = true
	}
}
