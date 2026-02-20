package certs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSelfSigned(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")

	if err := GenerateSelfSigned(certPath, keyPath); err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	// Verify files were created
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("certificate file not created")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("key file not created")
	}

	// Verify they can be loaded back
	cert, err := LoadCertificate(certPath)
	if err != nil {
		t.Fatalf("LoadCertificate failed: %v", err)
	}
	if cert.Subject.CommonName != "MFA Gruppen IdP" {
		t.Errorf("expected CN 'MFA Gruppen IdP', got '%s'", cert.Subject.CommonName)
	}
	if cert.Subject.Organization[0] != "MFA Gruppen" {
		t.Errorf("expected Org 'MFA Gruppen', got '%s'", cert.Subject.Organization[0])
	}

	key, err := LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey failed: %v", err)
	}
	if key.N.BitLen() != 2048 {
		t.Errorf("expected 2048-bit key, got %d", key.N.BitLen())
	}

	// Verify key permissions are restrictive
	info, _ := os.Stat(keyPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected key file permissions 0600, got %o", info.Mode().Perm())
	}
}

func TestEnsureCertificates_ExistingFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")

	// Generate first
	GenerateSelfSigned(certPath, keyPath)

	// Should succeed without regenerating
	if err := EnsureCertificates(certPath, keyPath, false); err != nil {
		t.Fatalf("EnsureCertificates failed with existing files: %v", err)
	}
}

func TestEnsureCertificates_AutoGenerate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "new.crt")
	keyPath := filepath.Join(dir, "new.key")

	if err := EnsureCertificates(certPath, keyPath, true); err != nil {
		t.Fatalf("EnsureCertificates auto-generate failed: %v", err)
	}

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("certificate not auto-generated")
	}
}

func TestEnsureCertificates_NoAutoGenerate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "missing.crt")
	keyPath := filepath.Join(dir, "missing.key")

	err := EnsureCertificates(certPath, keyPath, false)
	if err == nil {
		t.Fatal("expected error when files missing and auto_generate is false")
	}
}
