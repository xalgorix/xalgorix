package browser

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// maxRefusalNotes caps how many refused requests one tool result reports.
const maxRefusalNotes = 5

// requestGuardState holds the request guard a browser store applies to every
// request its Chromium makes, and the refusals not yet reported. It has its
// own lock because the interception handler runs on its own goroutines while
// tool actions hold the store's locks.
type requestGuardState struct {
	mu       sync.Mutex
	guard    tools.RequestGuard
	refusals []string
	dropped  int
}

// setRequestGuard installs g as the guard for this store's browser. A nil g is
// ignored, so a guard, once installed, stays for the life of the store: a call
// through an unguarded path can never switch the protection off.
func (s *browserStore) setRequestGuard(g tools.RequestGuard) {
	if g == nil {
		return
	}
	s.reqGuard.mu.Lock()
	s.reqGuard.guard = g
	s.reqGuard.mu.Unlock()
}

func (s *browserStore) currentRequestGuard() tools.RequestGuard {
	s.reqGuard.mu.Lock()
	defer s.reqGuard.mu.Unlock()
	return s.reqGuard.guard
}

func (s *browserStore) noteRefusal(rawURL string, err error) {
	s.reqGuard.mu.Lock()
	defer s.reqGuard.mu.Unlock()
	note := fmt.Sprintf("%s: %v", truncate(rawURL, 200), err)
	for _, n := range s.reqGuard.refusals {
		if n == note {
			return
		}
	}
	if len(s.reqGuard.refusals) >= maxRefusalNotes {
		s.reqGuard.dropped++
		return
	}
	s.reqGuard.refusals = append(s.reqGuard.refusals, note)
}

// takeRefusalReport returns, and clears, a note listing the requests the
// guard refused since the last report, or "" when there were none.
func (s *browserStore) takeRefusalReport() string {
	s.reqGuard.mu.Lock()
	notes, dropped := s.reqGuard.refusals, s.reqGuard.dropped
	s.reqGuard.refusals, s.reqGuard.dropped = nil, 0
	s.reqGuard.mu.Unlock()
	if len(notes) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("⛔ BROWSER REQUEST BLOCKED — the browser was stopped from loading these addresses (a redirect, link, script or frame pointed there):\n")
	for _, n := range notes {
		b.WriteString("  - ")
		b.WriteString(n)
		b.WriteString("\n")
	}
	if dropped > 0 {
		fmt.Fprintf(&b, "  (and %d more)\n", dropped)
	}
	return b.String()
}

// guardedScheme reports whether a request to rawURL goes over the network and
// so must pass the guard. data:, blob: and extension URLs never leave
// Chromium.
func guardedScheme(rawURL string) bool {
	lower := strings.ToLower(strings.TrimSpace(rawURL))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// installRequestGuard pauses every request the browser makes, in every tab,
// frame and worker, and lets it continue only when the store's request guard
// allows it. Chromium pauses each redirect hop as a request of its own, so a
// redirect, a meta refresh, a script's fetch() or an iframe cannot reach what
// a direct navigation is refused. When no guard is installed, requests
// continue unchanged.
//
// It runs at the browser level (Fetch.enable on the browser session), so tabs
// opened later are covered too. It returns an error when interception cannot
// be enabled; the caller must not use a browser it could not guard.
func installRequestGuard(br *rod.Browser, s *browserStore) (*rod.HijackRouter, error) {
	router := br.HijackRequests()
	err := router.Add("*", "", func(h *rod.Hijack) {
		h.OnError = func(err error) {
			log.Printf("[browser] request guard: could not resolve paused request: %v", err)
		}
		guard := s.currentRequestGuard()
		if guard == nil {
			h.ContinueRequest(&proto.FetchContinueRequest{})
			return
		}
		u := h.Request.Req().URL
		if u == nil {
			// Unparseable URL: refuse rather than let Chromium decide.
			s.noteRefusal("(unparseable URL)", fmt.Errorf("the address could not be checked"))
			h.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}
		raw := u.String()
		if !guardedScheme(raw) {
			h.ContinueRequest(&proto.FetchContinueRequest{})
			return
		}
		if err := guard(raw); err != nil {
			s.noteRefusal(u.Redacted(), err)
			log.Printf("[browser] request guard refused %s: %v", u.Redacted(), err)
			h.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}
		h.ContinueRequest(&proto.FetchContinueRequest{})
	})
	if err != nil {
		_ = router.Stop()
		return nil, fmt.Errorf("enable request interception: %w", err)
	}
	go router.Run()
	return router, nil
}
