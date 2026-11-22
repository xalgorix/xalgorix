package skills

import (
	"io/fs"
	"strings"
	"testing"
)

// TestCatalogStaysWebFocused pins the bundled catalog to web application and
// API testing. Defensive and unrelated categories (SOC, forensics, malware,
// OT/ICS, compliance, containers, mobile, ...) were removed on purpose: the
// engine only tests web targets, and their skills crowded search results and
// the binary.
func TestCatalogStaysWebFocused(t *testing.T) {
	sub, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, c := range listCategories(sub) {
		have[c] = true
	}
	for _, gone := range []string{
		"threat-hunting", "threat-intelligence", "soc-operations", "security-operations",
		"digital-forensics", "malware-analysis", "incident-response", "ransomware-defense",
		"phishing-defense", "social-engineering-defense", "deception-technology",
		"endpoint-security", "linux-hardening", "macos-security", "ot-ics-security",
		"firmware-security", "binary-exploitation", "wireless-security", "network-security",
		"zero-trust-architecture", "compliance-governance", "governance-risk-compliance",
		"privacy-compliance", "data-protection", "purple-team", "threat-detection",
		"blockchain-security", "container-security", "mobile-security",
	} {
		if have[gone] {
			t.Errorf("category %q is back in the web-focused catalog", gone)
		}
	}
	for _, keep := range []string{
		"web-application-security", "api-security", "application-security", "reconnaissance",
		"penetration-testing", "identity-access-management", "cryptography", "ai-security",
		"cloud-security", "network-services-pentesting", "devsecops", "supply-chain-security",
	} {
		if !have[keep] {
			t.Errorf("web-testing category %q is missing", keep)
		}
	}
}

// TestPromptSkillNamesResolve verifies every skill name the root system prompt
// tells the model to load (internal/agent/agent_prompt.go, "Deep Knowledge
// Skills") still loads, so a catalog change cannot silently break them.
func TestPromptSkillNamesResolve(t *testing.T) {
	sub, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		t.Fatal(err)
	}
	read := makeReadSkill(sub)
	for _, name := range []string{
		"nosql_injection", "mass_assignment", "prototype_pollution", "oauth2_attacks",
		"2fa_mfa_bypass", "insecure_file_uploads", "cache_poisoning", "http_request_smuggling",
		"websocket_hijacking", "dom_xss", "saml_attacks", "insecure_deserialization",
		"host_header_attacks", "crlf_injection", "web_cache_deception", "ssrf", "nmap",
	} {
		res, err := read(map[string]string{"name": name})
		if err != nil || !strings.HasPrefix(res.Output, "---\nname: ") {
			t.Errorf("read_skill(%q) did not load a skill: %v %q", name, err, firstLine(res.Output+res.Error))
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
