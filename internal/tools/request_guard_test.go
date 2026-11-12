package tools

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGuardRedirectsRefusesAHopWithoutFollowingIt(t *testing.T) {
	var hits atomic.Int32
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer final.Close()
	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/secret", http.StatusFound)
	}))
	defer start.Close()

	client := &http.Client{}
	refused := GuardRedirects(client, func(raw string) error {
		if strings.HasPrefix(raw, final.URL) {
			return errors.New("not allowed")
		}
		return nil
	})
	resp, err := client.Get(start.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want the 302 itself", resp.StatusCode)
	}
	if hits.Load() != 0 {
		t.Fatal("refused hop was requested")
	}
	if note := refused(); !strings.Contains(note, final.URL+"/secret") || !strings.Contains(note, "not allowed") {
		t.Fatalf("note = %q", note)
	}

	// Allowed hops are followed as before.
	client = &http.Client{}
	refused = GuardRedirects(client, func(string) error { return nil })
	resp, err = client.Get(start.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || hits.Load() != 1 || refused() != "" {
		t.Fatalf("allowed hop: status %d hits %d note %q", resp.StatusCode, hits.Load(), refused())
	}
}

func TestGuardRedirectsKeepsTheRedirectLimit(t *testing.T) {
	var loop *httptest.Server
	loop = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, loop.URL+"/again", http.StatusFound)
	}))
	defer loop.Close()
	client := &http.Client{}
	GuardRedirects(client, func(string) error { return nil })
	if _, err := client.Get(loop.URL); err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("err = %v, want the 10-redirect limit", err)
	}
}

func TestGuardRedirectsNilGuardLeavesClientAlone(t *testing.T) {
	client := &http.Client{}
	if refused := GuardRedirects(client, nil); refused() != "" || client.CheckRedirect != nil {
		t.Fatal("nil guard changed the client")
	}
}

func TestRegistryRequestGuard(t *testing.T) {
	r := NewRegistry()
	if r.RequestGuard() != nil {
		t.Fatal("new registry has a guard")
	}
	r.SetRequestGuard(func(string) error { return errors.New("no") })
	if g := r.RequestGuard(); g == nil || g("http://x") == nil {
		t.Fatal("guard not installed")
	}
}
