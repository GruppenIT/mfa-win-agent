package oidc

import (
	"encoding/json"
	"net/http"
)

// RegisterRoutes registers OIDC stub endpoints on the given mux.
// These are placeholder routes for Phase 2 implementation.
func RegisterRoutes(mux *http.ServeMux, issuer string) {
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		handleDiscovery(w, r, issuer)
	})
	mux.HandleFunc("GET /oauth/authorize", handleNotImplemented)
	mux.HandleFunc("POST /oauth/authorize", handleNotImplemented)
	mux.HandleFunc("POST /oauth/token", handleNotImplemented)
	mux.HandleFunc("GET /oauth/userinfo", handleNotImplemented)
	mux.HandleFunc("GET /oauth/jwks", handleNotImplemented)
}

func handleDiscovery(w http.ResponseWriter, _ *http.Request, issuer string) {
	// Return a minimal OpenID Configuration document
	// This helps SPs discover that OIDC will be available in the future
	config := map[string]interface{}{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/oauth/authorize",
		"token_endpoint":         issuer + "/oauth/token",
		"userinfo_endpoint":      issuer + "/oauth/userinfo",
		"jwks_uri":               issuer + "/oauth/jwks",
		"response_types_supported": []string{"code"},
		"subject_types_supported":  []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"_notice": "OIDC support is planned for Phase 2. Endpoints are not yet functional.",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func handleNotImplemented(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{
		"error":       "not_implemented",
		"description": "OIDC support is planned for Phase 2",
	})
}
