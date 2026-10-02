package reporting

import "strings"

// FindingIdentity identifies a replaced candidate without duplicating proof data.
type FindingIdentity struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Target   string `json:"target"`
	Endpoint string `json:"endpoint"`
	Method   string `json:"method"`
	CVE      string `json:"cve,omitempty"`
}

func IdentityForFinding(v Vulnerability) *FindingIdentity {
	return &FindingIdentity{ID: v.ID, Title: v.Title, Target: v.Target, Endpoint: v.Endpoint, Method: v.Method, CVE: v.CVE}
}

func (ref *FindingIdentity) matches(v Vulnerability) bool {
	if ref == nil || ref.ID == "" || ref.ID != v.ID {
		return false
	}
	normalize := func(value string) string { return strings.Join(strings.Fields(strings.ToLower(value)), " ") }
	return normalize(ref.Title) == normalize(v.Title) && normalize(ref.Target) == normalize(v.Target) &&
		normalize(ref.Endpoint) == normalize(v.Endpoint) && normalize(ref.Method) == normalize(v.Method) && normalize(ref.CVE) == normalize(v.CVE)
}

func findingIsReplaced(candidate, incoming Vulnerability) bool {
	return incoming.Verified && !candidate.Verified && incoming.Replaces.matches(candidate)
}

func mergeRestoredFinding(store *vulnStore, incoming Vulnerability) {
	for _, row := range store.vulns {
		if findingIsReplaced(incoming, row) {
			return
		}
	}
	kept := store.vulns[:0]
	for _, row := range store.vulns {
		if !findingIsReplaced(row, incoming) {
			kept = append(kept, row)
		}
	}
	store.vulns = kept
	for i := range store.vulns {
		row := &store.vulns[i]
		if IdentityForFinding(*row).matches(incoming) {
			if incoming.Verified && !row.Verified {
				*row = incoming
			} else if row.Verified && incoming.Verified && incoming.Replaces != nil {
				row.Replaces = incoming.Replaces
			}
			return
		}
	}
	if _, _, duplicate := findDuplicateVulnerability(store.vulns, incoming.Title, incoming.Description, incoming.CVE, incoming.CWE, incoming.Target, incoming.Endpoint); !duplicate {
		store.vulns = append(store.vulns, incoming)
	}
}

// IsVerifiedUpgrade uses the same narrow matching rule as the report gate.
func IsVerifiedUpgrade(candidate, incoming Vulnerability) bool {
	return candidate.ID != "" && candidate.ID == incoming.ID && findUpgradeableVulnerabilityIndex([]Vulnerability{candidate}, incoming) == 0
}
