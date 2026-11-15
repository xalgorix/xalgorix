package agent

import (
	"net/url"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
)

const maxAvailabilityProbeTargets = 8

// confirmTargetUnresponsive only authorizes a scan-wide stop when every
// configured, concrete target independently fails two fresh availability
// checks. A failed discovered subdomain must not cancel work on other hosts.
func (a *Agent) confirmTargetUnresponsive() bool {
	contextID := ""
	if a.scanCtx != nil {
		contextID = a.scanCtx.ID
	}
	confirmed := confirmTargetUnresponsive(a.targets, func(target string) (int, error) {
		if err := a.ctx.Err(); err != nil {
			return 0, err
		}
		return httpclient.ProbeTarget(a.ctx, contextID, target, a.checkDialAddr)
	})
	return confirmed && a.ctx.Err() == nil
}

func confirmTargetUnresponsive(targets []string, probe func(string) (int, error)) bool {
	if len(targets) == 0 || len(targets) > maxAvailabilityProbeTargets {
		return false
	}
	seen := make(map[string]bool, len(targets))
	for _, raw := range targets {
		target := strings.TrimSpace(raw)
		if target == "" || strings.ContainsAny(target, "*{}") {
			return false
		}
		candidates := []string{target}
		if !strings.Contains(target, "://") {
			// A bare hostname does not identify the protocol. Both possible
			// origins must fail before an outage can be confirmed.
			candidates = []string{"https://" + target, "http://" + target}
		}
		for _, candidate := range candidates {
			parsed, err := url.Parse(candidate)
			if err != nil || parsed.User != nil || parsed.Hostname() == "" ||
				(parsed.Scheme != "http" && parsed.Scheme != "https") {
				return false
			}
			origin := parsed.Scheme + "://" + parsed.Host
			if seen[origin] {
				continue
			}
			seen[origin] = true
			// Two fresh failures are required. An ordinary 4xx or application
			// 500 is inconclusive, so it cannot justify canceling the scan.
			for attempt := 0; attempt < 2; attempt++ {
				status, err := probe(origin)
				if err != nil {
					if !strings.Contains(err.Error(), "request failed:") {
						return false
					}
					continue
				}
				if status != 502 && status != 503 && status != 504 && (status < 521 || status > 524) {
					return false
				}
			}
		}
	}
	return len(seen) > 0
}
