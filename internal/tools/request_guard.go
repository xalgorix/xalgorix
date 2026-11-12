package tools

import (
	"fmt"
	"net/http"
)

// RequestGuard reports why an HTTP tool must not send a request to rawURL,
// or nil when it may. The agent installs one per registry; the HTTP tools
// consult it for every redirect hop, because the agent's own guards only see
// the URL the tool was called with.
type RequestGuard func(rawURL string) error

// maxRedirects matches net/http's default redirect limit.
const maxRedirects = 10

// SetRequestGuard installs the guard the HTTP tools of this registry apply
// to redirect hops. A nil guard leaves redirects unchecked.
func (r *Registry) SetRequestGuard(g RequestGuard) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requestGuard = g
}

// RequestGuard returns the guard installed with SetRequestGuard, or nil.
func (r *Registry) RequestGuard() RequestGuard {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.requestGuard
}

// GuardRedirects makes client check every redirect hop with guard before
// following it. A refused hop is not followed: the client returns the
// redirect response itself, and the returned function reports the refusal so
// the tool can say why. The client must be private to one request, and must
// follow redirects (its CheckRedirect is replaced). A nil guard changes
// nothing.
func GuardRedirects(client *http.Client, guard RequestGuard) (refused func() string) {
	if guard == nil {
		return func() string { return "" }
	}
	var note string
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		if err := guard(next.URL.String()); err != nil {
			note = fmt.Sprintf("⛔ REDIRECT NOT FOLLOWED — %s: %v. The redirect response is shown instead.",
				next.URL.Redacted(), err)
			return http.ErrUseLastResponse
		}
		return nil
	}
	return func() string { return note }
}
