package web

import (
	"net/http"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// Guard for the 2026-11-12 outage: a test that saves settings must write the
// temp HOME's env file that TestMain set up, never the env file of the account
// running the tests. This replays the request that replaced the production
// API keys.
func TestSettingsWritesStayOutOfRealEnvFile(t *testing.T) {
	// applyEnvironmentUpdates also sets these in the process; restore them.
	t.Setenv("XALGORIX_API_KEY", "")
	t.Setenv("XALGORIX_API_KEYS", "")

	path := xalgorixEnvFilePath()
	if path == realEnvFile {
		t.Fatalf("settings are persisted to the real env file %s; TestMain must point HOME at a temp dir", path)
	}

	s := newTestServer(t, nil)
	rr := doKeyPoolReq(s, http.MethodPost, `{"keys":["dup-key-1111","dup-key-1111"]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /api/pool code = %d body=%s", rr.Code, rr.Body.String())
	}
	if got, err := config.ReadEnvFile(path); err != nil || got["XALGORIX_API_KEY"] != "dup-key-1111" {
		t.Fatalf("POST /api/pool did not write the temp env file %s: %v %v", path, got, err)
	}
	if envFileState(realEnvFile) != realEnvFileBefore {
		t.Fatalf("POST /api/pool changed the real env file %s", realEnvFile)
	}
}
