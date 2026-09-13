package proxy

import "strings"

// Environment gives proxy-aware subprocesses the required loopback egress
// proxy. This is not a security boundary for programs that ignore proxy
// environment variables; those require OS/container network isolation.
func Environment(base []string) ([]string, error) {
	localURL, err := LocalURL()
	if err != nil {
		return nil, err
	}
	env := make([]string, 0, len(base)+8)
	for _, kv := range base {
		key, _, ok := strings.Cut(kv, "=")
		if ok {
			switch strings.ToLower(key) {
			case "http_proxy", "https_proxy", "all_proxy", "no_proxy":
				continue
			}
		}
		env = append(env, kv)
	}
	return append(env,
		"HTTP_PROXY="+localURL,
		"HTTPS_PROXY="+localURL,
		"ALL_PROXY="+localURL,
		"http_proxy="+localURL,
		"https_proxy="+localURL,
		"all_proxy="+localURL,
		"NO_PROXY=localhost,127.0.0.1,::1",
		"no_proxy=localhost,127.0.0.1,::1",
	), nil
}
