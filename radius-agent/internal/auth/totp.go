package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/GruppenIT/mfa-win-agent/radius-agent/internal/logging"
)

// TOTPValidator validates TOTP codes against the MFA Gruppen API.
type TOTPValidator struct {
	apiBaseURL string
	apiKey     string
	client     *http.Client
}

// TOTPResult holds the result of a TOTP validation.
type TOTPResult struct {
	Success bool
	Message string
}

// NewTOTPValidator creates a new TOTP validation client.
func NewTOTPValidator(apiBaseURL, apiKey string, timeoutSec int) *TOTPValidator {
	return &TOTPValidator{
		apiBaseURL: apiBaseURL,
		apiKey:     apiKey,
		client: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
		},
	}
}

// Validate checks a TOTP code against the MFA Gruppen backend.
func (v *TOTPValidator) Validate(ctx context.Context, username, realm, otpCode string) (*TOTPResult, error) {
	log := logging.Logger(ctx)

	form := url.Values{}
	form.Set("user", username)
	form.Set("pass", otpCode)
	if realm != "" {
		form.Set("realm", realm)
	}

	apiURL := fmt.Sprintf("%s/validate/check", v.apiBaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating validation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+v.apiKey)

	log.Debug("validating TOTP", "username", username)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending validation request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading validation response: %w", err)
	}

	var result struct {
		Result struct {
			Status bool   `json:"status"`
			Value  bool   `json:"value"`
		} `json:"result"`
		Detail struct {
			Message string `json:"message"`
		} `json:"detail"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing validation response: %w", err)
	}

	return &TOTPResult{
		Success: result.Result.Value,
		Message: result.Detail.Message,
	}, nil
}
