package reporting

// Vuln is the reporting-side projection of a vulnerability finding. Field
// shapes are kept in lock-step with internal/web.VulnSummary so that the
// web layer can convert by direct copy, but this package owns the
// definition for any non-web consumer (cloud Worker_Pool, future CLI).
type Vuln struct {
	ID                 string
	Title              string
	Severity           string
	Target             string
	Endpoint           string
	CVSS               float64
	CVSSVector         string
	Description        string
	Impact             string
	Method             string
	CVE                string
	CWE                string
	OWASP              string
	TechnicalAnalysis  string
	PoCDescription     string
	PoCScript          string
	Remediation        string
	Fix                string
	ExploitationProof  string
	VerificationMethod string
	Verified           bool
}

// Event is the reporting-side projection of a scan WebSocket event. Only
// the fields consulted by the recon-summary extractor and the tested-
// endpoints scraper are retained; the wire-protocol fields (timestamps,
// agent ids, parent target) are intentionally dropped because the report
// pipeline never reads them.
type Event struct {
	Type     string
	Content  string
	ToolName string
	ToolArgs map[string]string
	Output   string
	Error    string
}

// Scan is the reporting-side projection of a persisted scan record. It
// carries only the fields the PDF generator consumes: identity, target
// metadata, status, timing, branding, methodology selection, and the
// finding/event lists.
type Scan struct {
	ID          string
	Name        string
	Target      string
	StartedAt   string
	FinishedAt  string
	Status      string
	CompanyName string
	LogoPath    string
	Phases      []int
	// PhasesWorked lists phases the engine observed concrete work for.
	PhasesWorked []int
	// PhaseStatus is the authoritative derived per-phase disposition
	// ("completed"/"active"/"pending"/"blocked"/"not_applicable"/
	// "not_selected") keyed by decimal phase id.
	PhaseStatus map[string]string
	// PhaseReasons carries the auditable per-phase reason (N-A evidence,
	// blocked cause).
	PhaseReasons map[string]string
	Iterations   int
	ToolCalls    int
	TotalTokens  int
	Vulns        []Vuln
	Events       []Event
}
