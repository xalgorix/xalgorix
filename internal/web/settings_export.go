package web

// settings_export.go: configuration backup & migration.
//
// Export bundles everything an operator would otherwise re-enter by hand
// when moving an install: environment variables (cleartext secrets),
// LLM auth profiles (API keys and OAuth tokens), and multi-provider keys.
// Import merges a previously exported bundle into the local install.
//
// Both routes live under /api/settings/* so they inherit the operator-only
// machine-token policy: an automation credential can never read the export
// (it contains plaintext secrets) and can never bulk-overwrite settings.
// Imports merge rather than replace — values absent from the bundle are
// left untouched, so importing into an existing install never destroys
// anything that is not in the file.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/llm"
)

// settingsExportVersion identifies the backup format. Bump on breaking
// changes; import is deliberately lenient about unknown future fields.
const settingsExportVersion = 1

type settingsExport struct {
	Version    int               `json:"version"`
	ExportedAt string            `json:"exported_at"`
	Env        map[string]string `json:"env"`
	Profiles   []auth.Profile    `json:"profiles,omitempty"`
	LLMKeys    []llm.ProviderKey `json:"llm_keys,omitempty"`
}

// handleSettingsExport serves GET /api/settings/export: the complete
// configuration as a JSON download. Secret values are exported in
// CLEARTEXT on purpose — this is the migration artifact. It is only ever
// served to the operator's dashboard session (machine tokens get the
// standard 403 from the route denylist) and never logged.
func (s *Server) handleSettingsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	out := settingsExport{
		Version:    settingsExportVersion,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		Env:        make(map[string]string),
	}

	// Environment: every definition that currently holds a value. Values
	// come from the runtime config (cleartext), so a masked display value
	// never round-trips into a backup.
	for _, def := range allEnvSettingDefinitions() {
		v := s.envSettingValue(def.Key)
		if v == "" || isMaskedSettingValue(v) {
			continue
		}
		out.Env[def.Key] = v
	}

	// LLM auth profiles (API-key profiles and OAuth profiles with their
	// tokens — the whole point is not having to re-authenticate).
	if s.profiles != nil {
		if profiles, err := s.profiles.List(r.Context()); err == nil && len(profiles) > 0 {
			out.Profiles = profiles
		}
	}

	// Multi-provider key store entries.
	if s.llmKeyStore != nil {
		for _, k := range s.llmKeyStore.ListUnmasked() {
			if k.APIKey != "" {
				out.LLMKeys = append(out.LLMKeys, k)
			}
		}
	}

	w.Header().Set("Content-Disposition", `attachment; filename="xalgorix-settings-backup.json"`)
	writeJSONStatus(w, http.StatusOK, out)
}

type settingsImportRequest struct {
	Env      map[string]string `json:"env"`
	Profiles []auth.Profile    `json:"profiles"`
	LLMKeys  []llm.ProviderKey `json:"llm_keys"`
}

type settingsImportResult struct {
	OK              bool     `json:"ok"`
	EnvApplied      int      `json:"env_applied"`
	EnvSkipped      []string `json:"env_skipped,omitempty"`
	ProfilesApplied int      `json:"profiles_applied"`
	ProfileWarnings []string `json:"profile_warnings,omitempty"`
	LLMKeysApplied  int      `json:"llm_keys_applied"`
	LLMKeyWarnings  []string `json:"llm_key_warnings,omitempty"`
	RestartRequired bool     `json:"restart_required,omitempty"`
	GeneralWarnings []string `json:"general_warnings,omitempty"`
}

// validateImportProfile sanity-checks a profile from a backup before it is
// written: known type, identifying fields present, and a credential to
// import. Store.Put re-validates provider (catalog) and profile-id format,
// so this is the cheap pre-filter that produces useful per-entry warnings.
func validateImportProfile(p auth.Profile) error {
	if strings.TrimSpace(p.Provider) == "" {
		return fmt.Errorf("profile %q: missing provider", p.ProfileID)
	}
	if strings.TrimSpace(p.ProfileID) == "" {
		return fmt.Errorf("profile for %s: missing profile id", p.Provider)
	}
	if p.Type != auth.APIKey && p.Type != auth.OAuth {
		return fmt.Errorf("profile %s/%s: unknown type %q", p.Provider, p.ProfileID, p.Type)
	}
	if p.Type == auth.APIKey && p.APIKey == "" {
		return fmt.Errorf("profile %s/%s: no API key", p.Provider, p.ProfileID)
	}
	if p.Type == auth.OAuth && p.AccessToken == "" && p.RefreshToken == "" {
		return fmt.Errorf("profile %s/%s: no tokens", p.Provider, p.ProfileID)
	}
	return nil
}

// handleSettingsImport serves POST /api/settings/import: merges a backup
// bundle into this install. Unknown environment keys (e.g. from a newer
// export on an older scanner) and masked values are skipped with a report
// instead of failing the whole import; environment application itself is
// atomic — a validation error applies nothing and surfaces as HTTP 400.
func (s *Server) handleSettingsImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req settingsImportRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	if err := dec.Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("invalid JSON body: %v", err),
		})
		return
	}

	res := settingsImportResult{OK: true}

	// 1. Environment: whitelist to known definitions; masked values (which
	// never occur in our own exports but could appear in hand-edited files)
	// are skipped — re-applying a mask would silently clear nothing, but
	// skipping keeps the report honest.
	defs := envDefinitionByKey()
	effective := make(map[string]string, len(req.Env))
	for k, v := range req.Env {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if _, known := defs[k]; !known || v == "" || isMaskedSettingValue(v) {
			res.EnvSkipped = append(res.EnvSkipped, k)
			continue
		}
		effective[k] = v
	}
	if len(effective) > 0 {
		restart, err := s.applyEnvironmentUpdates(effective)
		if err != nil {
			// applyEnvironmentUpdates validates every entry before writing
			// anything, so this failure leaves the config untouched.
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		res.EnvApplied = len(effective)
		res.RestartRequired = restart
	}

	// 2. Auth profiles.
	if len(req.Profiles) > 0 {
		if s.profiles == nil {
			res.GeneralWarnings = append(res.GeneralWarnings,
				"auth profile store unavailable — profiles were not imported")
		} else {
			for _, p := range req.Profiles {
				if err := validateImportProfile(p); err != nil {
					res.ProfileWarnings = append(res.ProfileWarnings, err.Error())
					continue
				}
				if err := s.profiles.Put(r.Context(), p); err != nil {
					res.ProfileWarnings = append(res.ProfileWarnings,
						fmt.Sprintf("profile %s/%s: %v", p.Provider, p.ProfileID, err))
					continue
				}
				res.ProfilesApplied++
			}
		}
	}

	// 3. Multi-provider keys.
	if len(req.LLMKeys) > 0 {
		if s.llmKeyStore == nil {
			res.GeneralWarnings = append(res.GeneralWarnings,
				"LLM key store unavailable — provider keys were not imported")
		} else {
			clean := make([]llm.ProviderKey, 0, len(req.LLMKeys))
			for _, k := range req.LLMKeys {
				if strings.TrimSpace(k.ProviderID) == "" || strings.TrimSpace(k.APIKey) == "" {
					res.LLMKeyWarnings = append(res.LLMKeyWarnings,
						fmt.Sprintf("provider %q: missing provider id or API key", k.ProviderID))
					continue
				}
				clean = append(clean, k)
			}
			if len(clean) > 0 {
				if err := s.llmKeyStore.SetMultiple(r.Context(), clean); err != nil {
					res.LLMKeyWarnings = append(res.LLMKeyWarnings, fmt.Sprintf("key store: %v", err))
				} else {
					res.LLMKeysApplied = len(clean)
				}
			}
		}
	}

	writeJSONStatus(w, http.StatusOK, res)
}
