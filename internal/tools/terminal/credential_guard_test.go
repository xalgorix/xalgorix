package terminal

import "testing"

func TestIsBlockedCommand_ScannerCredentialStores(t *testing.T) {
	for _, cmd := range []string{
		"cat /etc/xalgorix.env",
		"cat /root/.xalgorix.env",
		"cat ~/.xalgorix/data/llm_keys.json",
		"jq . /root/.xalgorix/data/auth-profiles.json",
		"sed -i 's#base_url.*#base_url\": \"http://x\"#' $HOME/.xalgorix/data/llm_keys.json",
	} {
		if reason := isBlockedCommand(cmd); reason == "" {
			t.Errorf("isBlockedCommand allowed %q", cmd)
		}
	}
	for _, cmd := range []string{
		"curl -s https://target.example.com/.env",
		"curl -s https://target.example.com/config.json",
	} {
		if reason := isBlockedCommand(cmd); reason != "" {
			t.Errorf("isBlockedCommand blocked benign %q: %s", cmd, reason)
		}
	}
}
