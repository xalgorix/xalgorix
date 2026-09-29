// Package web — api_token.go implements dedicated machine-to-machine
// authentication for API clients (the SaaS backend, CI, integrations) that is
// fully separate from the human dashboard login:
//
//	human:     POST /api/auth/login + username/password -> xalgorix_session cookie
//	machine:   Authorization: Bearer <token> header -> direct API access, no cookie
//
// The two flows are independent security layers, deliberately:
//   - the machine flow never touches the login rate limiter, so automation
//     cannot be locked out by (or cause) dashboard brute-force lockouts, and
//     human lockouts never block API clients;
//   - the machine flow never creates a browser session, so a leaked service
//     token cannot be replayed as a dashboard session;
//   - tokens are stored as SHA-256 digests and compared with constant-time
//     equality, so the raw token is never retained for matching and nothing
//     about the token (length aside, which hashing conceals) leaks.
package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// machineTokenRouteDenylist blocks machine API tokens from operator-only
// routes: a service token identifies an automation client, not the human
// operating the dashboard. Settings routes manage provider API keys and other
// environment secrets; auth profiles hold LLM-provider credentials; chat is an
// interactive operator console. All of these stay session-auth-only.
var machineTokenRouteDenylist = []string{
	"/api/settings/",
	"/api/auth/profiles",
	"/api/chat",
}

// machineTokenPathAllowed reports whether a machine token may authorize the
// path at all.
func machineTokenPathAllowed(path string) bool {
	for _, prefix := range machineTokenRouteDenylist {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}
	return true
}

// isMachineAPIPath reports whether the path belongs to the machine API surface
// (JSON APIs and the scan event WebSocket). Machine tokens authorize these
// only — never dashboard page routes.
func isMachineAPIPath(path string) bool {
	return strings.HasPrefix(path, "/api/") || path == "/ws"
}

// apiTokenHashes returns SHA-256 digests of the configured machine API
// tokens. Tokens are trimmed of surrounding whitespace; entries that are
// empty after trimming are ignored (an unset/blank variable must never
// become a zero-length token that trivially matches). Duplicates collapse.
func apiTokenHashes(tokens []string) [][sha256.Size]byte {
	seen := make(map[[sha256.Size]byte]bool, len(tokens))
	out := make([][sha256.Size]byte, 0, len(tokens))
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		sum := sha256.Sum256([]byte(tok))
		if seen[sum] {
			continue
		}
		seen[sum] = true
		out = append(out, sum)
	}
	return out
}

// bearerScheme is the RFC 7235 token-auth scheme prefix ("Bearer ").
const bearerScheme = "Bearer "

// bearerTokenFromRequest extracts the presented token from the Authorization
// header using the case-insensitive "Bearer" scheme. Malformed presentations
// (no scheme, wrong scheme, empty token) return ("", false).
func bearerTokenFromRequest(r *http.Request) (string, bool) {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if raw == "" {
		return "", false
	}
	if len(raw) <= len(bearerScheme) || !strings.EqualFold(raw[:len(bearerScheme)], bearerScheme) {
		return "", false
	}
	token := strings.TrimSpace(raw[len(bearerScheme):])
	if token == "" {
		return "", false
	}
	return token, true
}

// validMachineToken reports whether the request presents one of the
// configured machine API tokens. Comparison is over SHA-256 digests with
// constant-time equality: neither the token content nor its digest position
// leaks through comparison timing, and the raw token is never stored.
func validMachineToken(r *http.Request, hashes [][sha256.Size]byte) bool {
	token, ok := bearerTokenFromRequest(r)
	if !ok || len(hashes) == 0 {
		return false
	}
	presented := sha256.Sum256([]byte(token))
	for _, want := range hashes {
		if subtle.ConstantTimeCompare(presented[:], want[:]) == 1 {
			return true
		}
	}
	return false
}

// machineAuthResult classifies a request against the machine-token
// configuration.
type machineAuthResult int

const (
	// machineAuthNone: no Authorization header — a browser or legacy client.
	machineAuthNone machineAuthResult = iota
	// machineAuthValid: the request carries a configured machine API token.
	machineAuthValid
	// machineAuthInvalid: an Authorization header was presented but matches
	// no configured token.
	machineAuthInvalid
)

// classifyMachineAuth classifies the request's machine authentication state.
func classifyMachineAuth(r *http.Request, hashes [][sha256.Size]byte) machineAuthResult {
	if strings.TrimSpace(r.Header.Get("Authorization")) == "" {
		return machineAuthNone
	}
	if validMachineToken(r, hashes) {
		return machineAuthValid
	}
	return machineAuthInvalid
}
