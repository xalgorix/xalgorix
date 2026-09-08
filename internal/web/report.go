package web

import (
	"bytes"
	"fmt"
	"image"
	_ "image/jpeg" // register JPEG decoder for image.Decode on uploaded logos
	_ "image/png"  // register PNG decoder for image.Decode on uploaded logos
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
)

type reportPalette struct {
	bg       [3]int
	card     [3]int
	muted    [3]int
	border   [3]int
	fg       [3]int
	subtle   [3]int
	accent   [3]int
	critical [3]int
	high     [3]int
	medium   [3]int
	low      [3]int
	info     [3]int
	code     [3]int
}

func themeReportPalette() reportPalette {
	return reportPalette{
		bg:       [3]int{5, 5, 5},       // #050505
		card:     [3]int{10, 10, 10},    // #0a0a0a
		muted:    [3]int{17, 17, 17},    // #111111
		border:   [3]int{38, 38, 38},    // #262626
		fg:       [3]int{250, 250, 250}, // #fafafa
		subtle:   [3]int{161, 161, 170}, // #a1a1aa
		accent:   [3]int{16, 185, 129},  // #10b981
		critical: [3]int{220, 38, 38},   // #dc2626
		high:     [3]int{234, 88, 12},   // #ea580c
		medium:   [3]int{202, 138, 4},   // #ca8a04
		low:      [3]int{37, 99, 235},   // #2563eb
		info:     [3]int{82, 82, 82},    // #525252
		code:     [3]int{23, 23, 23},    // #171717
	}
}

// owaspCategories defines the OWASP Top 10 (2021) categories in order.
// Package-level to avoid re-allocation per report generation.
var owaspCategories = []struct {
	ID   string
	Name string
}{
	{"A01", "Broken Access Control"},
	{"A02", "Cryptographic Failures"},
	{"A03", "Injection"},
	{"A04", "Insecure Design"},
	{"A05", "Security Misconfiguration"},
	{"A06", "Vulnerable and Outdated Components"},
	{"A07", "Identification and Authentication Failures"},
	{"A08", "Software and Data Integrity Failures"},
	{"A09", "Security Logging and Monitoring Failures"},
	{"A10", "Server-Side Request Forgery (SSRF)"},
}

func parseReportTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, value); err == nil {
			return t
		}
	}
	return time.Time{}
}

func formatReportDate(t time.Time) string {
	if t.IsZero() {
		return "Not recorded"
	}
	return t.Format("January 2, 2006")
}

func formatReportTimestamp(t time.Time) string {
	if t.IsZero() {
		return "Not recorded"
	}
	return t.Format("2006-01-02 15:04:05 MST")
}

func formatReportDuration(startTime, endTime time.Time) string {
	if startTime.IsZero() || endTime.IsZero() || endTime.Before(startTime) {
		return "In progress"
	}
	d := endTime.Sub(startTime).Round(time.Second)
	if d.Hours() >= 1 {
		return fmt.Sprintf("%dh %dm %ds", int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60)
	}
	if d.Minutes() >= 1 {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

func reportDisplayText(value string, fallback string, max int) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if value == "" {
		value = fallback
	}
	if max > 0 && len([]rune(value)) > max {
		runes := []rune(value)
		return string(runes[:max-3]) + "..."
	}
	return value
}

func reportHostLabel(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return "Target"
	}
	parsed, err := url.Parse(target)
	if err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	if !strings.Contains(target, "://") {
		if parsed, err := url.Parse("https://" + target); err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
	}
	return strings.Trim(target, "/")
}

func reportBrandName(scan *ScanRecord) string {
	if scan == nil {
		return "Target"
	}
	for _, candidate := range []string{scan.CompanyName, scan.Name, reportHostLabel(scan.Target), scan.Target} {
		candidate = strings.TrimSpace(candidate)
		if candidate != "" {
			return candidate
		}
	}
	return "Target"
}

func reportInitials(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "XT"
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ' ' || r == '-' || r == '_' || r == '.' || r == '/' || r == ':'
	})
	initials := ""
	for _, part := range parts {
		for _, r := range part {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				if r >= 'a' && r <= 'z' {
					r -= 'a' - 'A'
				}
				initials += string(r)
				break
			}
		}
		if len(initials) >= 2 {
			break
		}
	}
	if initials == "" {
		return "XT"
	}
	return initials
}

func prepareReportCodeBlock(content string, maxLines, maxCols int) string {
	content = strings.TrimRight(content, "\n")
	if content == "" {
		return ""
	}
	var out []string
	truncated := false
	for _, line := range strings.Split(content, "\n") {
		runes := []rune(line)
		if len(runes) == 0 {
			out = append(out, "")
		}
		for len(runes) > 0 {
			if len(out) >= maxLines {
				truncated = true
				break
			}
			take := maxCols
			if len(runes) < take {
				take = len(runes)
			}
			out = append(out, string(runes[:take]))
			runes = runes[take:]
		}
		if truncated {
			break
		}
	}
	if truncated || len(out) > maxLines {
		if len(out) >= maxLines {
			out = out[:maxLines]
		}
		out = append(out, "... (truncated)")
	}
	return strings.Join(out, "\n")
}

func supportedReportLogoExt(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png", ".jpg", ".jpeg":
		return true
	default:
		return false
	}
}

const maxReportLogoBytes = 5 << 20

// loadReportLogo reads an uploaded logo through a directory-bound handle.
// Renderers receive the validated bytes, never a path to reopen after validation.
func (s *Server) loadReportLogo(logoPath string) ([]byte, string) {
	logoPath = strings.TrimSpace(logoPath)
	if logoPath == "" || strings.TrimSpace(s.dataDir) == "" {
		return nil, ""
	}
	logosDir, err := filepath.Abs(filepath.Join(s.dataDir, "logos"))
	if err != nil {
		return nil, ""
	}
	name := logoPath
	if strings.HasPrefix(logoPath, "/uploads/logos/") {
		name = strings.TrimPrefix(logoPath, "/uploads/logos/")
	} else if filepath.IsAbs(logoPath) {
		// Keep legacy saved absolute paths only when they name an upload.
		name, err = filepath.Rel(logosDir, logoPath)
		if err != nil {
			return nil, ""
		}
	}
	if !filepath.IsLocal(name) || strings.ContainsAny(name, "/\\:\x00") || !supportedReportLogoExt(name) {
		return nil, ""
	}
	root, err := os.OpenRoot(logosDir)
	if err != nil {
		return nil, ""
	}
	defer func() { _ = root.Close() }()
	file, err := root.Open(name)
	if err != nil {
		return nil, ""
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxReportLogoBytes {
		return nil, ""
	}
	data, err := io.ReadAll(io.LimitReader(file, maxReportLogoBytes+1))
	if err != nil || len(data) > maxReportLogoBytes {
		return nil, ""
	}
	_, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || (format != "png" && format != "jpeg") {
		return nil, ""
	}
	return data, format
}

// riskScore computes a weighted overall risk score (0-10) from vulnerabilities.
// Formula: weighted average of top-5 CVSS scores + severity count penalty.
func riskScore(vulns []VulnSummary) float64 {
	if len(vulns) == 0 {
		return 0
	}
	// Collect CVSS values, fallback to severity-based defaults
	scores := make([]float64, 0, len(vulns))
	for _, v := range vulns {
		cvss := v.CVSS
		if cvss <= 0 {
			switch strings.ToLower(v.Severity) {
			case "critical":
				cvss = 9.5
			case "high":
				cvss = 7.5
			case "medium":
				cvss = 5.0
			case "low":
				cvss = 2.5
			default:
				cvss = 1.0
			}
		}
		scores = append(scores, cvss)
	}
	sort.Float64s(scores)
	// Take top-5 (or fewer) weighted average
	n := len(scores)
	top := 5
	if n < top {
		top = n
	}
	sum := 0.0
	for i := 0; i < top; i++ {
		sum += scores[n-1-i]
	}
	avg := sum / float64(top)
	// Severity count penalty: more criticals/highs push score up
	crit, high := 0, 0
	for _, v := range vulns {
		switch strings.ToLower(v.Severity) {
		case "critical":
			crit++
		case "high":
			high++
		}
	}
	penalty := math.Min(float64(crit)*0.15+float64(high)*0.05, 1.5)
	return math.Min(avg+penalty, 10.0)
}

// riskLabel returns a human-readable risk rating from a score.
func riskLabel(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score >= 1.0:
		return "LOW"
	default:
		return "INFORMATIONAL"
	}
}

type reconReportSummary struct {
	DNSRecords   []string
	IPAddresses  []string
	Ports        []string
	Technologies []string
	URLs         []string
}

func (s reconReportSummary) hasData() bool {
	return len(s.DNSRecords)+len(s.IPAddresses)+len(s.Ports)+len(s.Technologies)+len(s.URLs) > 0
}

var (
	ipv4Re      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	dnsRecordRe = regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\.?)\s+(?:\d+\s+)?(?:in\s+)?(a|aaaa|cname|mx|ns|txt|soa)\s+(\S[^\r\n]{0,159})`)
	openPortRe  = regexp.MustCompile(`(?im)\b([0-9]{1,5})/(tcp|udp)\s+open\s+([^\s]+)?([^\r\n]{0,100})`)
)

// agentProseTypes are event types that contain natural language from the agent
// rather than structured tool output. These are skipped during recon extraction
// to avoid false positives (e.g., "the site uses WordPress" matching as a tech
// detection, or "check the A record" matching as a DNS record).
var agentProseTypes = map[string]bool{
	"agent":    true,
	"thought":  true,
	"decision": true,
	"message":  true,
	"llm":      true,
	"phase":    true,
}

func collectReconReportSummary(events []WSEvent) reconReportSummary {
	var summary reconReportSummary
	seenDNS := map[string]bool{}
	seenIP := map[string]bool{}
	seenPort := map[string]bool{}
	seenTech := map[string]bool{}
	seenURL := map[string]bool{}

	techSignals := map[string][]string{
		"Cloudflare": {"cloudflare", "cf-ray"},
		"Nginx":      {"nginx"},
		"Apache":     {"apache"},
		"IIS":        {"microsoft-iis", "iis/"},
		"WordPress":  {"wordpress", "wp-content"},
		"Laravel":    {"laravel"},
		"PHP":        {"x-powered-by: php", "phpsessid", ".php"},
		"Node.js":    {"node.js", "express", "x-powered-by: express"},
		"Next.js":    {"next.js", "_next/"},
		"React":      {"react", "react-dom"},
		"jQuery":     {"jquery"},
		"Django":     {"django", "csrftoken"},
		"Flask":      {"flask"},
		"Spring":     {"spring", "jsessionid"},
		"Tomcat":     {"tomcat"},
		"GraphQL":    {"graphql"},
	}

	for _, evt := range events {
		// Skip agent prose — only parse structured tool output to avoid
		// false positives from natural language descriptions.
		if agentProseTypes[evt.Type] {
			continue
		}

		text := evt.Output + "\n" + evt.Error
		for _, value := range evt.ToolArgs {
			text += "\n" + value
		}
		// Include Content only for non-prose events (e.g., tool_call Content
		// may contain a command summary). Agent messages are already filtered.
		if evt.Content != "" {
			text += "\n" + evt.Content
		}
		lower := strings.ToLower(text)

		for _, ip := range ipv4Re.FindAllString(text, -1) {
			if validIPv4(ip) {
				addUnique(&summary.IPAddresses, seenIP, ip, 40)
			}
		}

		for _, match := range dnsRecordRe.FindAllStringSubmatch(text, -1) {
			if len(match) == 4 {
				record := fmt.Sprintf("%s %s %s", strings.TrimSpace(match[1]), strings.ToUpper(match[2]), strings.TrimSpace(match[3]))
				addUnique(&summary.DNSRecords, seenDNS, record, 40)
			}
		}

		for _, match := range openPortRe.FindAllStringSubmatch(text, -1) {
			if len(match) >= 4 {
				port := strings.TrimSpace(match[1])
				service := strings.TrimSpace(match[3] + match[4])
				if service == "" {
					service = "unknown"
				}
				addUnique(&summary.Ports, seenPort, fmt.Sprintf("%s/%s %s", port, strings.ToLower(match[2]), service), 40)
			}
		}

		for tech, signals := range techSignals {
			for _, signal := range signals {
				if strings.Contains(lower, signal) {
					addUnique(&summary.Technologies, seenTech, tech, 30)
					break
				}
			}
		}

		for _, word := range strings.Fields(text) {
			if strings.Contains(word, "http://") || strings.Contains(word, "https://") {
				if u := extractURL(word); u != "" {
					addUnique(&summary.URLs, seenURL, u, 50)
				}
			}
		}
	}

	sort.Strings(summary.DNSRecords)
	sort.Strings(summary.IPAddresses)
	sort.Strings(summary.Ports)
	sort.Strings(summary.Technologies)
	sort.Strings(summary.URLs)
	return summary
}

func addUnique(values *[]string, seen map[string]bool, value string, max int) {
	value = strings.TrimSpace(value)
	if value == "" || seen[value] || len(*values) >= max {
		return
	}
	seen[value] = true
	*values = append(*values, value)
}

func validIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// methodologyPhaseNames maps phase number to name for report display.
var methodologyPhaseNames = map[int]string{
	1:  "Deep Reconnaissance & Attack Surface Mapping",
	2:  "Manual Vulnerability Discovery",
	3:  "Directory & File Discovery",
	4:  "CORS & Cookie Analysis",
	5:  "Authentication & Session Testing",
	6:  "Injection Testing",
	7:  "SSRF Testing",
	8:  "IDOR & Broken Access Control",
	9:  "API & GraphQL Testing",
	10: "File Upload Testing",
	11: "Deserialization & RCE",
	12: "Race Conditions & Business Logic",
	13: "Subdomain Takeover",
	14: "Open Redirect Testing",
	15: "Email Security Testing",
	16: "Cloud & Infrastructure",
	17: "WebSocket Testing",
	18: "CMS-Specific Testing",
	19: "Broken Link Hijacking & Content Spoofing",
	20: "Exploit Verification",
	21: "Novel Vulnerability Discovery",
	22: "Final Report",
}

// generateReport creates a professional PDF pentest report for a scan.
func (s *Server) generateReport(scan *ScanRecord) (string, error) {
	language := ""
	if s.cfg != nil {
		language = s.cfg.Language
	}
	pdf := newReportPDF(language)
	pdf.SetAutoPageBreak(true, 20)

	// tr localizes a static English report label into the configured output
	// language (no-op for English). Used to translate section headings, table
	// headers, and boilerplate; dynamic/technical values are left untouched.
	tr := func(s string) string { return reportTr(language, s) }

	palette := themeReportPalette()
	darkBg := palette.bg
	coral := palette.accent
	teal := palette.accent
	white := palette.fg
	gray := palette.subtle
	red := palette.critical
	orange := palette.high
	amber := palette.medium
	greenLow := palette.low
	cyan := palette.subtle
	sectionBg := palette.card
	codeBg := palette.code
	border := palette.border

	startTime := parseReportTime(scan.StartedAt)
	endTime := parseReportTime(scan.FinishedAt)
	duration := formatReportDuration(startTime, endTime)
	brandName := reportBrandName(scan)
	logoData, logoType := s.loadReportLogo(scan.LogoPath)
	hasLogo := len(logoData) > 0
	const logoPath = "uploaded-report-logo"

	// Helper: set text color
	setColor := func(c [3]int) {
		pdf.SetTextColor(c[0], c[1], c[2])
	}

	// Helper: draw a colored rect
	drawRect := func(x, y, w, h float64, c [3]int) {
		pdf.SetFillColor(c[0], c[1], c[2])
		pdf.Rect(x, y, w, h, "F")
	}

	drawStrokeRect := func(x, y, w, h float64, c [3]int) {
		pdf.SetDrawColor(c[0], c[1], c[2])
		pdf.Rect(x, y, w, h, "D")
	}

	// fpdf can create pages implicitly when MultiCell content crosses a page
	// boundary. Paint every implicit page before content lands on it.
	pdf.SetHeaderFunc(func() {
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, coral)
	})

	drawLogoOrInitials := func(x, y, w, h float64) {
		drawRect(x, y, w, h, palette.muted)
		drawStrokeRect(x, y, w, h, border)
		if hasLogo {
			info := pdf.RegisterImageOptionsReader(logoPath, fpdf.ImageOptions{ImageType: logoType}, bytes.NewReader(logoData))
			if info != nil && info.Height() > 0 && info.Width() > 0 {
				maxW := w - 6
				maxH := h - 6
				imgW := maxW
				imgH := info.Height() * imgW / info.Width()
				if imgH > maxH {
					imgH = maxH
					imgW = info.Width() * imgH / info.Height()
				}
				pdf.ImageOptions(logoPath, x+(w-imgW)/2, y+(h-imgH)/2, imgW, imgH, false, fpdf.ImageOptions{}, 0, "")
				return
			}
		}
		pdf.SetFont("Helvetica", "B", 16)
		setColor(white)
		pdf.SetXY(x, y+h/2-4)
		pdf.CellFormat(w, 8, reportInitials(brandName), "", 0, "C", false, 0, "")
	}

	// Helper: severity color
	sevColor := func(sev string) [3]int {
		switch strings.ToLower(sev) {
		case "critical":
			return red
		case "high":
			return orange
		case "medium":
			return amber
		case "low":
			return greenLow
		default:
			return cyan
		}
	}

	// ─── COVER PAGE ────────────────────────────────────────
	pdf.AddPage()
	drawRect(0, 0, 210, 297, darkBg)

	drawRect(0, 0, 210, 3, coral)
	drawRect(14, 28, 182, 82, sectionBg)
	drawStrokeRect(14, 28, 182, 82, border)
	drawRect(14, 28, 2, 82, coral)
	drawLogoOrInitials(26, 44, 38, 38)

	pdf.SetXY(74, 41)
	pdf.SetFont("Helvetica", "B", 23)
	setColor(white)
	pdf.MultiCell(112, 9, tr("Security Assessment Report"), "", "L", false)

	pdf.SetXY(74, 62)
	pdf.SetFont("Helvetica", "B", 14)
	setColor(coral)
	pdf.MultiCell(112, 7, reportDisplayText(brandName, tr("Target"), 60), "", "L", false)

	pdf.SetXY(74, 78)
	pdf.SetFont("Courier", "", 8)
	setColor(gray)
	pdf.MultiCell(112, 4.5, reportDisplayText(scan.Target, tr("No target recorded"), 95), "", "L", false)

	pdf.SetY(124)
	coverRisk := riskLabel(riskScore(scan.Vulns))
	coverCards := []struct {
		label string
		value string
		color [3]int
	}{
		{tr("Status"), strings.ToUpper(reportDisplayText(scan.Status, "unknown", 18)), coral},
		{tr("Risk"), coverRisk, sevColor(strings.ToLower(coverRisk))},
		{tr("Findings"), fmt.Sprintf("%d", len(scan.Vulns)), red},
		{tr("Started"), formatReportDate(startTime), gray},
	}
	coverCardW := 42.5
	for i, c := range coverCards {
		x := 14 + float64(i)*(coverCardW+4)
		drawRect(x, 124, coverCardW, 27, sectionBg)
		drawStrokeRect(x, 124, coverCardW, 27, border)
		drawRect(x, 124, coverCardW, 1.2, c.color)
		pdf.SetXY(x+4, 131)
		pdf.SetFont("Helvetica", "", 7.5)
		setColor(gray)
		pdf.CellFormat(coverCardW-8, 4, strings.ToUpper(c.label), "", 1, "L", false, 0, "")
		pdf.SetXY(x+4, 138)
		pdf.SetFont("Helvetica", "B", 11)
		setColor(c.color)
		pdf.CellFormat(coverCardW-8, 6, c.value, "", 0, "L", false, 0, "")
	}

	pdf.SetXY(14, 176)
	pdf.SetFont("Helvetica", "B", 10)
	setColor(gray)
	pdf.CellFormat(182, 6, tr("SCAN ID"), "", 1, "L", false, 0, "")
	pdf.SetX(14)
	pdf.SetFont("Courier", "", 10)
	setColor(white)
	pdf.CellFormat(182, 7, reportDisplayText(scan.ID, tr("not recorded"), 90), "", 1, "L", false, 0, "")

	pdf.SetY(248)
	drawRect(14, pdf.GetY(), 182, 0.3, border)
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "B", 10)
	setColor(white)
	pdf.CellFormat(182, 5, "Xalgorix", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 8)
	setColor(gray)
	pdf.CellFormat(182, 5, tr("Autonomous AI-powered security assessment"), "", 1, "L", false, 0, "")
	drawRect(0, 294, 210, 3, coral)

	// ─── EXECUTIVE SUMMARY ─────────────────────────────────
	pdf.AddPage()
	drawRect(0, 0, 210, 297, darkBg)
	drawRect(0, 0, 210, 1.5, coral)

	pdf.SetY(15)
	pdf.SetFont("Helvetica", "B", 22)
	setColor(coral)
	pdf.CellFormat(190, 12, tr("Executive Summary"), "", 1, "L", false, 0, "")
	drawRect(10, pdf.GetY()+2, 50, 0.8, coral)
	pdf.Ln(8)

	// Summary stats cards
	type statCard struct {
		label string
		value string
		color [3]int
	}

	// Count severity
	critCount, highCount, medCount, lowCount, infoCount := 0, 0, 0, 0, 0
	for _, v := range scan.Vulns {
		switch strings.ToLower(v.Severity) {
		case "critical":
			critCount++
		case "high":
			highCount++
		case "medium":
			medCount++
		case "low":
			lowCount++
		default:
			infoCount++
		}
	}

	cards := []statCard{
		{"Total Vulnerabilities", fmt.Sprintf("%d", len(scan.Vulns)), coral},
		{"Critical", fmt.Sprintf("%d", critCount), red},
		{"High", fmt.Sprintf("%d", highCount), orange},
		{"Medium", fmt.Sprintf("%d", medCount), amber},
		{"Low", fmt.Sprintf("%d", lowCount), greenLow},
		{"Info", fmt.Sprintf("%d", infoCount), cyan},
	}

	// Draw stat cards in 2 rows of 3
	cardW := 55.0
	cardH := 28.0
	startX := 12.0
	y := pdf.GetY()
	for i, c := range cards {
		col := i % 3
		row := i / 3
		x := startX + float64(col)*(cardW+7)
		cy := y + float64(row)*(cardH+6)

		drawRect(x, cy, cardW, cardH, sectionBg)
		// Top accent on card
		drawRect(x, cy, cardW, 2, c.color)

		pdf.SetXY(x+4, cy+6)
		pdf.SetFont("Helvetica", "", 9)
		setColor(gray)
		pdf.CellFormat(cardW-8, 5, c.label, "", 1, "L", false, 0, "")

		pdf.SetXY(x+4, cy+14)
		pdf.SetFont("Helvetica", "B", 18)
		setColor(c.color)
		pdf.CellFormat(cardW-8, 10, c.value, "", 0, "L", false, 0, "")
	}

	pdf.SetY(y + 2*(cardH+6) + 10)

	// ── Overall Risk Score ──
	score := riskScore(scan.Vulns)
	label := riskLabel(score)
	var riskColor [3]int
	switch label {
	case "CRITICAL":
		riskColor = red
	case "HIGH":
		riskColor = orange
	case "MEDIUM":
		riskColor = amber
	case "LOW":
		riskColor = greenLow
	default:
		riskColor = cyan
	}

	riskY := pdf.GetY()
	drawRect(10, riskY, 190, 22, sectionBg)
	drawRect(10, riskY, 190, 2.5, riskColor)
	pdf.SetXY(14, riskY+5)
	pdf.SetFont("Helvetica", "B", 11)
	setColor(gray)
	pdf.CellFormat(60, 6, tr("OVERALL RISK SCORE"), "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "B", 22)
	setColor(riskColor)
	pdf.CellFormat(25, 10, fmt.Sprintf("%.1f", score), "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(50, 10, label, "", 0, "L", false, 0, "")
	pdf.SetY(riskY + 26)

	// ── Executive Risk Narrative ──
	pdf.SetFont("Helvetica", "B", 11)
	setColor(white)
	pdf.CellFormat(190, 7, tr("Risk Assessment"), "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	setColor(white)
	narrative := fmt.Sprintf(
		"The automated penetration test of %s identified %d vulnerabilities "+
			"(%d critical, %d high, %d medium, %d low, %d informational). ",
		scan.Target, len(scan.Vulns), critCount, highCount, medCount, lowCount, infoCount,
	)
	if critCount > 0 || highCount > 0 {
		narrative += fmt.Sprintf(
			"The overall risk is assessed as %s (%.1f/10). Immediate remediation is recommended for the %d critical "+
				"and %d high severity findings, as they may allow unauthorized access, data exfiltration, or service disruption. ",
			label, score, critCount, highCount,
		)
	} else if medCount > 0 {
		narrative += fmt.Sprintf(
			"The overall risk is assessed as %s (%.1f/10). While no critical or high-severity issues were found, "+
				"the %d medium findings should be addressed in the next maintenance cycle to reduce attack surface. ",
			label, score, medCount,
		)
	} else {
		narrative += fmt.Sprintf(
			"The overall risk is assessed as %s (%.1f/10). The target demonstrates a strong security posture "+
				"with only low-severity or informational findings. Continuous monitoring is recommended. ",
			label, score,
		)
	}
	pdf.SetX(10)
	pdf.MultiCell(190, 4.5, narrative, "", "L", false)
	pdf.Ln(6)

	// Scan metadata
	pdf.SetFont("Helvetica", "B", 13)
	setColor(white)
	pdf.CellFormat(190, 8, tr("Scan Details"), "", 1, "L", false, 0, "")
	pdf.Ln(2)

	metaItems := [][2]string{
		{"Target", scan.Target},
		{"Status", strings.ToUpper(scan.Status)},
		{"Duration", duration},
		{"Iterations", fmt.Sprintf("%d", scan.Iterations)},
		{"Tool Calls", fmt.Sprintf("%d", scan.ToolCalls)},
		{"Total Tokens", fmt.Sprintf("%d", scan.TotalTokens)},
		{"Started", formatReportTimestamp(startTime)},
		{"Finished", formatReportTimestamp(endTime)},
	}

	for i, m := range metaItems {
		bgColor := darkBg
		if i%2 == 0 {
			bgColor = sectionBg
		}
		drawRect(10, pdf.GetY(), 190, 8, bgColor)
		pdf.SetFont("Helvetica", "B", 9)
		setColor(gray)
		pdf.CellFormat(45, 8, "  "+m[0], "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		setColor(white)
		pdf.CellFormat(145, 8, m[1], "", 1, "L", false, 0, "")
	}

	// ─── METHODOLOGY ──────────────────────────────────────
	pdf.AddPage()
	drawRect(0, 0, 210, 297, darkBg)
	drawRect(0, 0, 210, 1.5, coral)

	pdf.SetY(15)
	pdf.SetFont("Helvetica", "B", 22)
	setColor(coral)
	pdf.CellFormat(190, 12, tr("Testing Methodology"), "", 1, "L", false, 0, "")
	drawRect(10, pdf.GetY()+2, 50, 0.8, coral)
	pdf.Ln(8)

	pdf.SetFont("Helvetica", "", 9)
	setColor(white)
	pdf.SetX(10)
	pdf.MultiCell(190, 4.5, tr("Xalgorix follows a comprehensive 22-phase penetration testing methodology "+
		"aligned with OWASP, PTES, and industry best practices. Each phase is executed by an autonomous AI agent "+
		"with tool access to terminal, browser, and specialized security utilities."), "", "L", false)
	pdf.Ln(4)

	// Determine which phases were executed
	executedPhases := scan.Phases
	allPhases := len(executedPhases) == 0 // empty = all phases
	for phaseNum := 1; phaseNum <= 22; phaseNum++ {
		name, ok := methodologyPhaseNames[phaseNum]
		if !ok {
			continue
		}
		executed := allPhases
		if !allPhases {
			for _, p := range executedPhases {
				if p == phaseNum {
					executed = true
					break
				}
			}
		}
		rowY := pdf.GetY()
		if rowY > 270 {
			pdf.AddPage()
			drawRect(0, 0, 210, 297, darkBg)
			drawRect(0, 0, 210, 1.5, coral)
			pdf.SetY(15)
			rowY = pdf.GetY()
		}
		bgColor := darkBg
		if phaseNum%2 == 0 {
			bgColor = sectionBg
		}
		if executed {
			bgColor = palette.muted
		}
		drawRect(10, rowY, 190, 7, bgColor)
		// Status indicator
		if executed {
			drawRect(10, rowY, 3, 7, teal)
			drawRect(14, rowY+1.5, 4, 4, teal)
		} else {
			drawRect(14, rowY+1.5, 4, 4, gray)
		}
		pdf.SetXY(22, rowY)
		pdf.SetFont("Helvetica", "", 8)
		if executed {
			setColor(white)
		} else {
			setColor(gray)
		}
		status := tr("SKIPPED")
		if executed {
			status = tr("SELECTED")
		}
		pdf.CellFormat(145, 7, fmt.Sprintf(tr("Phase %d: %s"), phaseNum, tr(name)), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "B", 7)
		if executed {
			setColor(teal)
		} else {
			setColor(gray)
		}
		pdf.CellFormat(25, 7, status, "", 1, "R", false, 0, "")
	}

	// Legend
	pdf.Ln(4)
	pdf.SetFont("Helvetica", "", 7)
	setColor(gray)
	pdf.SetX(10)
	drawRect(12, pdf.GetY()+1, 3, 3, teal)
	pdf.SetX(18)
	pdf.CellFormat(30, 5, tr("= Executed"), "", 0, "L", false, 0, "")
	drawRect(50, pdf.GetY()+1, 3, 3, gray)
	pdf.SetX(56)
	pdf.CellFormat(30, 5, tr("= Skipped"), "", 1, "L", false, 0, "")

	// ─── RECONNAISSANCE FINDINGS ─────────────────────────
	recon := collectReconReportSummary(scan.Events)
	if recon.hasData() {
		pdf.AddPage()
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, teal)

		pdf.SetY(15)
		pdf.SetFont("Helvetica", "B", 22)
		setColor(teal)
		pdf.CellFormat(190, 12, tr("Reconnaissance Findings"), "", 1, "L", false, 0, "")
		drawRect(10, pdf.GetY()+2, 62, 0.8, teal)
		pdf.Ln(8)

		pdf.SetFont("Helvetica", "", 9)
		setColor(white)
		pdf.SetX(10)
		pdf.MultiCell(190, 4.5, tr("The following non-exploit reconnaissance observations were extracted from the scan feed and tool outputs. These are included for attack-surface documentation and operational handoff."), "", "L", false)
		pdf.Ln(5)

		drawReconList := func(title string, items []string) {
			if len(items) == 0 {
				return
			}
			if pdf.GetY() > 245 {
				pdf.AddPage()
				drawRect(0, 0, 210, 297, darkBg)
				drawRect(0, 0, 210, 1.5, teal)
				pdf.SetY(15)
			}
			headerY := pdf.GetY()
			drawRect(10, headerY, 190, 8, sectionBg)
			pdf.SetXY(14, headerY+1)
			pdf.SetFont("Helvetica", "B", 9)
			setColor(teal)
			pdf.CellFormat(180, 6, strings.ToUpper(title), "", 1, "L", false, 0, "")
			pdf.Ln(2)
			pdf.SetFont("Courier", "", 7)
			setColor(white)
			for _, item := range items {
				if pdf.GetY() > 270 {
					pdf.AddPage()
					drawRect(0, 0, 210, 297, darkBg)
					drawRect(0, 0, 210, 1.5, teal)
					pdf.SetY(15)
				}
				pdf.SetX(14)
				pdf.MultiCell(182, 4, "- "+item, "", "L", false)
			}
			pdf.Ln(4)
		}

		drawReconList("DNS Records", recon.DNSRecords)
		drawReconList("Resolved IP Addresses", recon.IPAddresses)
		drawReconList("Open Ports & Services", recon.Ports)
		drawReconList("Detected Technologies", recon.Technologies)
		drawReconList("Observed URLs & Endpoints", recon.URLs)
	}

	// ─── BLUE TEAM TIMESTAMPS ─────────────────────────────
	pdf.Ln(10)
	if pdf.GetY() > 230 {
		pdf.AddPage()
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, coral)
		pdf.SetY(15)
	}
	pdf.SetFont("Helvetica", "B", 16)
	setColor(coral)
	pdf.CellFormat(190, 10, tr("Blue Team Reference Timestamps"), "", 1, "L", false, 0, "")
	drawRect(10, pdf.GetY()+1, 50, 0.8, teal)
	pdf.Ln(6)

	pdf.SetFont("Helvetica", "", 8)
	setColor(gray)
	pdf.SetX(10)
	pdf.MultiCell(190, 4, tr("The following RFC3339 timestamps enable Blue Team operators to correlate "+
		"scan activity with SIEM/log sources for use-case development and alert tuning."), "", "L", false)
	pdf.Ln(3)

	tsItems := [][2]string{
		{tr("Scan Start"), scan.StartedAt},
		{tr("Scan End"), scan.FinishedAt},
	}
	// Add per-vulnerability discovery timestamps
	for i, v := range scan.Vulns {
		if i >= 20 {
			break // Limit to 20 to avoid excessive pages
		}
		ts := scan.StartedAt // fallback
		if v.CVSS > 0 {
			ts = scan.StartedAt
		}
		tsItems = append(tsItems, [2]string{
			fmt.Sprintf("Vuln #%d: %s", i+1, v.Title),
			ts,
		})
	}

	for i, ts := range tsItems {
		if pdf.GetY() > 270 {
			pdf.AddPage()
			drawRect(0, 0, 210, 297, darkBg)
			drawRect(0, 0, 210, 1.5, coral)
			pdf.SetY(15)
		}
		bgColor := darkBg
		if i%2 == 0 {
			bgColor = sectionBg
		}
		drawRect(10, pdf.GetY(), 190, 7, bgColor)
		pdf.SetFont("Helvetica", "B", 7)
		setColor(gray)
		titleStr := ts[0]
		if titleRunes := []rune(titleStr); len(titleRunes) > 75 {
			titleStr = string(titleRunes[:72]) + "..."
		}
		pdf.CellFormat(120, 7, "  "+titleStr, "", 0, "L", false, 0, "")
		pdf.SetFont("Courier", "", 7)
		setColor(teal)
		pdf.CellFormat(70, 7, ts[1], "", 1, "L", false, 0, "")
	}

	// Pre-compute all vuln mappings once for the entire report.
	allMappings := make([]VulnMappings, len(scan.Vulns))
	owaspCounts := make(map[string]int)
	ptesCounts := make(map[string]int)
	for i, v := range scan.Vulns {
		allMappings[i] = InferVulnMappings(v)
		if allMappings[i].OWASP != "" {
			owaspCounts[allMappings[i].OWASP]++
		}
		if allMappings[i].PTES != "" {
			ptesCounts[allMappings[i].PTES]++
		}
	}

	// ─── FINDINGS SUMMARY TABLE ──────────────────────────
	if len(scan.Vulns) > 0 {
		pdf.AddPage()
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, coral)

		pdf.SetY(15)
		pdf.SetFont("Helvetica", "B", 22)
		setColor(coral)
		pdf.CellFormat(190, 12, tr("Findings Summary"), "", 1, "L", false, 0, "")
		drawRect(10, pdf.GetY()+2, 50, 0.8, coral)
		pdf.Ln(8)

		pdf.SetFont("Helvetica", "", 8)
		setColor(white)
		pdf.SetX(10)
		pdf.MultiCell(190, 4, tr("The following table summarizes all findings with their security framework mappings (CWE, OWASP Top 10 2021). Detailed write-ups follow in the Vulnerability Details section."), "", "L", false)
		pdf.Ln(4)

		// Table header
		thY := pdf.GetY()
		drawRect(10, thY, 190, 8, sectionBg)
		pdf.SetFont("Helvetica", "B", 7)
		setColor(coral)
		pdf.SetXY(12, thY+1)
		pdf.CellFormat(10, 6, "ID", "", 0, "L", false, 0, "")
		pdf.CellFormat(68, 6, tr("FINDING"), "", 0, "L", false, 0, "")
		pdf.CellFormat(20, 6, tr("SEVERITY"), "", 0, "C", false, 0, "")
		pdf.CellFormat(14, 6, "CVSS", "", 0, "C", false, 0, "")
		pdf.CellFormat(40, 6, "CVE", "", 0, "L", false, 0, "")
		pdf.CellFormat(18, 6, "CWE", "", 0, "L", false, 0, "")
		pdf.CellFormat(20, 6, "OWASP", "", 0, "L", false, 0, "")
		pdf.Ln(8)

		// Table rows
		for i, v := range scan.Vulns {
			if pdf.GetY() > 268 {
				pdf.AddPage()
				drawRect(0, 0, 210, 297, darkBg)
				drawRect(0, 0, 210, 1.5, coral)
				pdf.SetY(15)
			}

			mappings := allMappings[i]
			rowY := pdf.GetY()
			rowBg := darkBg
			if i%2 == 0 {
				rowBg = sectionBg
			}
			drawRect(10, rowY, 190, 7, rowBg)

			// Severity accent
			sc := sevColor(v.Severity)
			drawRect(10, rowY, 2, 7, sc)

			pdf.SetXY(12, rowY)
			pdf.SetFont("Helvetica", "B", 7)
			setColor(gray)
			pdf.CellFormat(10, 7, fmt.Sprintf("F-%02d", i+1), "", 0, "L", false, 0, "")

			pdf.SetFont("Helvetica", "", 7)
			setColor(white)
			titleStr := v.Title
			if titleRunes := []rune(titleStr); len(titleRunes) > 40 {
				titleStr = string(titleRunes[:37]) + "..."
			}
			pdf.CellFormat(68, 7, titleStr, "", 0, "L", false, 0, "")

			pdf.SetFont("Helvetica", "B", 7)
			pdf.SetTextColor(sc[0], sc[1], sc[2])
			pdf.CellFormat(20, 7, strings.ToUpper(v.Severity), "", 0, "C", false, 0, "")

			setColor(white)
			pdf.SetFont("Helvetica", "", 7)
			cvssStr := "—"
			if v.CVSS > 0 {
				cvssStr = fmt.Sprintf("%.1f", v.CVSS)
			}
			pdf.CellFormat(14, 7, cvssStr, "", 0, "C", false, 0, "")

			setColor(gray)
			cveStr := v.CVE
			if len(cveStr) > 22 {
				cveStr = cveStr[:19] + "..."
			}
			if cveStr == "" {
				cveStr = "—"
			}
			pdf.CellFormat(40, 7, cveStr, "", 0, "L", false, 0, "")

			setColor(teal)
			cweStr := mappings.CWEID
			if cweStr == "" {
				cweStr = "—"
			}
			pdf.CellFormat(18, 7, cweStr, "", 0, "L", false, 0, "")

			owaspStr := mappings.OWASP
			if owaspStr == "" {
				owaspStr = "—"
			}
			pdf.CellFormat(20, 7, owaspStr, "", 1, "L", false, 0, "")
		}

		// ─── VULNERABILITY DETAILS ─────────────────────────────
		pdf.AddPage()
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, coral)

		pdf.SetY(15)
		pdf.SetFont("Helvetica", "B", 22)
		setColor(coral)
		pdf.CellFormat(190, 12, tr("Vulnerability Details"), "", 1, "L", false, 0, "")
		drawRect(10, pdf.GetY()+2, 50, 0.8, coral)
		pdf.Ln(8)

		for idx, v := range scan.Vulns {
			sc := sevColor(v.Severity)

			// Check if we need a new page (leave 80mm minimum)
			if pdf.GetY() > 220 {
				pdf.AddPage()
				drawRect(0, 0, 210, 297, darkBg)
				drawRect(0, 0, 210, 1.5, coral)
				pdf.SetY(15)
			}

			// Vuln header bar
			headerY := pdf.GetY()
			drawRect(10, headerY, 190, 10, sectionBg)
			drawRect(10, headerY, 3, 10, sc)

			// Truncate title to avoid overlapping with severity badge
			vulnTitle := fmt.Sprintf("#%d  %s", idx+1, v.Title)
			pdf.SetFont("Helvetica", "B", 10)
			maxTitleW := 150.0 // badge starts at x=170, title starts at x=16, leave 4mm gap
			for len(vulnTitle) > 0 && pdf.GetStringWidth(vulnTitle) > maxTitleW {
				runes := []rune(vulnTitle)
				vulnTitle = string(runes[:len(runes)-1])
			}
			if len(vulnTitle) < len(fmt.Sprintf("#%d  %s", idx+1, v.Title)) {
				vulnTitle = strings.TrimSpace(vulnTitle) + "..."
			}

			pdf.SetXY(16, headerY+1)
			setColor(white)
			pdf.CellFormat(maxTitleW, 8, vulnTitle, "", 0, "L", false, 0, "")

			// Severity badge
			pdf.SetXY(170, headerY+2)
			pdf.SetFont("Helvetica", "B", 8)
			drawRect(170, headerY+2, 28, 6, sc)
			pdf.SetTextColor(255, 255, 255)
			pdf.CellFormat(28, 6, strings.ToUpper(v.Severity), "", 0, "C", false, 0, "")

			pdf.SetY(headerY + 12)

			// Verification badge — only label a finding "Verified" when it was
			// independently confirmed. Otherwise mark it for manual review so an
			// inconclusive finding is never presented as validated.
			if v.VerificationMethod != "" {
				pdf.SetFont("Helvetica", "I", 7)
				pdf.SetX(14)
				if v.Verified {
					setColor(teal)
					pdf.CellFormat(0, 5, fmt.Sprintf(tr("Verified via: %s"), strings.ToUpper(v.VerificationMethod)), "", 1, "L", false, 0, "")
				} else {
					setColor(amber)
					pdf.CellFormat(0, 5, fmt.Sprintf(tr("UNVERIFIED — manual review required (reported via %s)"), strings.ToUpper(v.VerificationMethod)), "", 1, "L", false, 0, "")
				}
			}

			// Vuln meta — row 1: CVSS + CVSS vector
			if v.CVSS > 0 {
				metaY := pdf.GetY()
				pdf.SetFont("Helvetica", "", 8)
				setColor(gray)
				pdf.SetXY(14, metaY)
				pdf.CellFormat(15, 5, tr("CVSS:"), "", 0, "L", false, 0, "")
				setColor(sc)
				pdf.SetFont("Helvetica", "B", 8)
				pdf.CellFormat(15, 5, fmt.Sprintf("%.1f", v.CVSS), "", 0, "L", false, 0, "")
				if v.CVSSVector != "" {
					setColor(gray)
					pdf.SetFont("Helvetica", "", 7)
					pdf.CellFormat(0, 5, v.CVSSVector, "", 0, "L", false, 0, "")
				}
				pdf.Ln(6)
			}

			// Vuln meta — row 2: CVE + Method
			hasCVEOrMethod := v.CVE != "" || v.Method != ""
			if hasCVEOrMethod {
				meta2Y := pdf.GetY()
				pdf.SetXY(14, meta2Y)
				if v.CVE != "" {
					setColor(gray)
					pdf.SetFont("Helvetica", "", 8)
					pdf.CellFormat(12, 5, tr("CVE:"), "", 0, "L", false, 0, "")
					setColor(white)
					cveText := reportDisplayText(v.CVE, "", 80)
					pdf.CellFormat(90, 5, cveText, "", 0, "L", false, 0, "")
				}
				if v.Method != "" {
					setColor(gray)
					pdf.SetFont("Helvetica", "", 8)
					pdf.CellFormat(18, 5, tr("Method:"), "", 0, "L", false, 0, "")
					setColor(white)
					pdf.CellFormat(20, 5, v.Method, "", 0, "L", false, 0, "")
				}
				pdf.Ln(6)
			}

			// Vuln meta — row 3: CWE + OWASP badges
			vulnMappings := allMappings[idx]
			hasMappings := vulnMappings.CWEID != "" || vulnMappings.OWASP != ""
			if hasMappings {
				meta3Y := pdf.GetY()
				pdf.SetXY(14, meta3Y)
				if vulnMappings.CWEID != "" {
					// CWE badge
					badgeW := pdf.GetStringWidth(vulnMappings.CWEID) + 6
					pdf.SetFont("Helvetica", "B", 7)
					drawRect(pdf.GetX(), meta3Y, badgeW, 5.5, palette.muted)
					setColor(teal)
					pdf.CellFormat(badgeW, 5.5, vulnMappings.CWEID, "", 0, "C", false, 0, "")
					pdf.SetX(pdf.GetX() + 2)
					if vulnMappings.CWEName != "" {
						pdf.SetFont("Helvetica", "", 7)
						setColor(gray)
						nameStr := vulnMappings.CWEName
						if nameRunes := []rune(nameStr); len(nameRunes) > 45 {
							nameStr = string(nameRunes[:42]) + "..."
						}
						pdf.CellFormat(0, 5.5, nameStr, "", 0, "L", false, 0, "")
					}
				}
				pdf.Ln(7)
				if vulnMappings.OWASP != "" {
					pdf.SetXY(14, pdf.GetY())
					owaspLabel := vulnMappings.OWASP
					if vulnMappings.OWASPName != "" {
						owaspLabel = vulnMappings.OWASP + " — " + vulnMappings.OWASPName
					}
					badgeW := pdf.GetStringWidth(owaspLabel) + 6
					pdf.SetFont("Helvetica", "B", 7)
					drawRect(pdf.GetX(), pdf.GetY(), badgeW, 5.5, palette.muted)
					setColor(coral)
					pdf.CellFormat(badgeW, 5.5, owaspLabel, "", 0, "C", false, 0, "")
					pdf.Ln(7)
				}
			}
			pdf.Ln(1)

			// Sections - only add if content exists
			type section struct {
				label   string
				content string
			}

			sections := []section{}
			if v.Endpoint != "" {
				sections = append(sections, section{"ENDPOINT", v.Endpoint})
			}
			if v.Description != "" {
				sections = append(sections, section{"DESCRIPTION", v.Description})
			}
			if v.Impact != "" {
				sections = append(sections, section{"IMPACT", v.Impact})
			}
			if v.TechnicalAnalysis != "" {
				sections = append(sections, section{"TECHNICAL ANALYSIS", v.TechnicalAnalysis})
			}
			if v.PoCDescription != "" {
				sections = append(sections, section{"PROOF OF CONCEPT", v.PoCDescription})
			}
			if v.PoCScript != "" {
				sections = append(sections, section{"POC SCRIPT", v.PoCScript})
			}
			if v.ExploitationProof != "" {
				sections = append(sections, section{"EXPLOITATION PROOF", v.ExploitationProof})
			}
			if v.Remediation != "" {
				sections = append(sections, section{"REMEDIATION", v.Remediation})
			}
			if v.Fix != "" {
				sections = append(sections, section{"SUGGESTED FIX", v.Fix})
			}

			for _, sec := range sections {
				if pdf.GetY() > 250 {
					pdf.AddPage()
					drawRect(0, 0, 210, 297, darkBg)
					drawRect(0, 0, 210, 1.5, coral)
					pdf.SetY(15)
				}

				// Section header with dark background for contrast
				secY := pdf.GetY()
				drawRect(10, secY, 190, 8, sectionBg)

				pdf.SetXY(14, secY+1)
				pdf.SetFont("Helvetica", "B", 8)
				setColor(coral)
				pdf.CellFormat(0, 6, sec.label, "", 0, "L", false, 0, "")

				pdf.SetY(secY + 9)

				// Content
				pdf.SetFont("Helvetica", "", 9)
				if sec.label == "POC SCRIPT" || sec.label == "ENDPOINT" || sec.label == "EXPLOITATION PROOF" {
					// Code-style content with dynamic height
					codeY := pdf.GetY()
					content := prepareReportCodeBlock(sec.content, 34, 96)
					// Calculate dynamic height based on content
					lines := strings.Count(content, "\n") + 1
					blockHeight := float64(lines)*4 + 6 // 4mm per line + padding
					if blockHeight < 15 {
						blockHeight = 15
					}
					if blockHeight > 150 {
						blockHeight = 150 // Cap to prevent page overflow
					}
					// Check if we need a new page for this code block
					if codeY+blockHeight > 270 {
						pdf.AddPage()
						drawRect(0, 0, 210, 297, darkBg)
						drawRect(0, 0, 210, 1.5, coral)
						pdf.SetY(15)
						codeY = pdf.GetY()
					}
					drawRect(14, codeY, 182, blockHeight, codeBg)
					pdf.SetXY(17, codeY+3)
					pdf.SetFont("Courier", "", 7)
					if sec.label == "EXPLOITATION PROOF" {
						setColor([3]int{255, 200, 100}) // Gold/amber for exploitation proof
					} else {
						setColor(cyan)
					}
					pdf.MultiCell(175, 4, content, "", "L", false)
				} else {
					setColor(white)
					pdf.SetX(14)
					pdf.MultiCell(182, 5, sec.content, "", "L", false)
				}
				pdf.Ln(4)
			}

			// Separator between vulns
			pdf.Ln(4)
			if idx < len(scan.Vulns)-1 {
				drawRect(30, pdf.GetY(), 150, 0.3, sectionBg)
				pdf.Ln(6)
			}
		}
	}

	// ─── TESTED ENDPOINTS ─────────────────────────────────
	// Only add if there are endpoints
	endpointSet := make(map[string]bool)
	var endpoints []string
	for _, evt := range scan.Events {
		if evt.Type == "tool_call" && evt.ToolName == "terminal_execute" {
			if strings.Contains(evt.ToolArgs["command"], "http") {
				lines := strings.Split(evt.ToolArgs["command"], "\n")
				for _, line := range lines {
					if strings.Contains(line, "http://") || strings.Contains(line, "https://") {
						for _, word := range strings.Fields(line) {
							if strings.Contains(word, "http") {
								u := extractURL(word)
								if u != "" && !endpointSet[u] {
									endpointSet[u] = true
									endpoints = append(endpoints, u)
								}
							}
						}
					}
				}
			}
		}
	}

	if len(endpoints) > 0 {
		pdf.AddPage()
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, coral)

		pdf.SetY(15)
		pdf.SetFont("Helvetica", "B", 22)
		setColor(coral)
		pdf.CellFormat(190, 12, tr("Tested Endpoints & URLs"), "", 1, "L", false, 0, "")
		drawRect(10, pdf.GetY()+2, 50, 0.8, coral)
		pdf.Ln(8)

		pdf.SetFont("Helvetica", "", 9)
		setColor(white)
		// Show first 30 endpoints
		displayEndpoints := endpoints
		if len(displayEndpoints) > 30 {
			displayEndpoints = displayEndpoints[:30]
		}
		for _, ep := range displayEndpoints {
			if pdf.GetY() > 265 {
				pdf.AddPage()
				drawRect(0, 0, 210, 297, darkBg)
				drawRect(0, 0, 210, 1.5, coral)
				pdf.SetY(15)
			}
			pdf.SetFont("Courier", "", 8)
			setColor(cyan)
			pdf.CellFormat(190, 5, "- "+ep, "", 1, "L", false, 0, "")
		}
		if len(endpoints) > 30 {
			pdf.Ln(2)
			pdf.SetFont("Helvetica", "", 9)
			setColor(gray)
			pdf.CellFormat(190, 5, fmt.Sprintf("... and %d more endpoints", len(endpoints)-30), "", 1, "L", false, 0, "")
		}
	}

	// ─── DISCLAIMER ──────────────────────────────────────
	pdf.AddPage()
	drawRect(0, 0, 210, 297, darkBg)
	drawRect(0, 0, 210, 1.5, coral)

	pdf.SetY(15)
	pdf.SetFont("Helvetica", "B", 22)
	setColor(red)
	pdf.CellFormat(190, 12, tr("Disclaimer"), "", 1, "L", false, 0, "")
	drawRect(10, pdf.GetY()+2, 50, 0.8, teal)
	pdf.Ln(10)

	pdf.SetFont("Helvetica", "", 10)
	setColor(white)
	pdf.MultiCell(182, 5, tr(reportDisclaimerEN), "", "L", false)

	// ─── REFERENCE INDEX APPENDIX ──────────────────────────
	if len(scan.Vulns) > 0 {
		pdf.AddPage()
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, teal)

		pdf.SetY(15)
		pdf.SetFont("Helvetica", "B", 22)
		setColor(teal)
		pdf.CellFormat(190, 12, tr("Reference Index"), "", 1, "L", false, 0, "")
		drawRect(10, pdf.GetY()+2, 50, 0.8, teal)
		pdf.Ln(8)

		pdf.SetFont("Helvetica", "", 8)
		setColor(white)
		pdf.SetX(10)
		pdf.MultiCell(190, 4, tr("The mappings below are inferred from each finding's vulnerability class and are provided as a consolidated index for traceability and compliance reporting."), "", "L", false)
		pdf.Ln(5)

		// ── CWE Reference Table ──
		pdf.SetFont("Helvetica", "B", 13)
		setColor(teal)
		pdf.CellFormat(190, 8, tr("CWE Reference Table"), "", 1, "L", false, 0, "")
		pdf.Ln(2)

		// Table header
		cweThY := pdf.GetY()
		drawRect(10, cweThY, 190, 8, sectionBg)
		pdf.SetFont("Helvetica", "B", 7)
		setColor(teal)
		pdf.SetXY(12, cweThY+1)
		pdf.CellFormat(15, 6, tr("FINDING"), "", 0, "L", false, 0, "")
		pdf.CellFormat(22, 6, "CWE", "", 0, "L", false, 0, "")
		pdf.CellFormat(80, 6, tr("CWE NAME"), "", 0, "L", false, 0, "")
		pdf.CellFormat(63, 6, tr("FINDING TITLE"), "", 0, "L", false, 0, "")
		pdf.Ln(8)

		for i, v := range scan.Vulns {
			if pdf.GetY() > 268 {
				pdf.AddPage()
				drawRect(0, 0, 210, 297, darkBg)
				drawRect(0, 0, 210, 1.5, teal)
				pdf.SetY(15)
			}
			mappings := allMappings[i]
			rowY := pdf.GetY()
			rowBg := darkBg
			if i%2 == 0 {
				rowBg = sectionBg
			}
			drawRect(10, rowY, 190, 7, rowBg)

			pdf.SetXY(12, rowY)
			pdf.SetFont("Helvetica", "B", 7)
			setColor(gray)
			pdf.CellFormat(15, 7, fmt.Sprintf("F-%02d", i+1), "", 0, "L", false, 0, "")

			setColor(teal)
			cweStr := mappings.CWEID
			if cweStr == "" {
				cweStr = "—"
			}
			pdf.CellFormat(22, 7, cweStr, "", 0, "L", false, 0, "")

			setColor(white)
			pdf.SetFont("Helvetica", "", 7)
			cweName := mappings.CWEName
			if cweName == "" {
				cweName = "—"
			}
			if cweRunes := []rune(cweName); len(cweRunes) > 48 {
				cweName = string(cweRunes[:45]) + "..."
			}
			pdf.CellFormat(80, 7, cweName, "", 0, "L", false, 0, "")

			setColor(gray)
			titleStr := v.Title
			if titleRunes := []rune(titleStr); len(titleRunes) > 38 {
				titleStr = string(titleRunes[:35]) + "..."
			}
			pdf.CellFormat(63, 7, titleStr, "", 1, "L", false, 0, "")
		}

		pdf.Ln(8)

		// ── OWASP Top 10 Coverage Matrix ──
		if pdf.GetY() > 200 {
			pdf.AddPage()
			drawRect(0, 0, 210, 297, darkBg)
			drawRect(0, 0, 210, 1.5, teal)
			pdf.SetY(15)
		}

		pdf.SetFont("Helvetica", "B", 13)
		setColor(teal)
		pdf.CellFormat(190, 8, tr("OWASP Top 10 (2021) Coverage"), "", 1, "L", false, 0, "")
		pdf.Ln(2)

		// owaspCounts was pre-computed above

		// Table header
		owThY := pdf.GetY()
		drawRect(10, owThY, 190, 8, sectionBg)
		pdf.SetFont("Helvetica", "B", 7)
		setColor(teal)
		pdf.SetXY(12, owThY+1)
		pdf.CellFormat(16, 6, "ID", "", 0, "L", false, 0, "")
		pdf.CellFormat(120, 6, tr("OWASP CATEGORY"), "", 0, "L", false, 0, "")
		pdf.CellFormat(20, 6, tr("FINDINGS"), "", 0, "C", false, 0, "")
		pdf.CellFormat(24, 6, tr("STATUS"), "", 0, "C", false, 0, "")
		pdf.Ln(8)

		for i, cat := range owaspCategories {
			rowY := pdf.GetY()
			rowBg := darkBg
			if i%2 == 0 {
				rowBg = sectionBg
			}
			drawRect(10, rowY, 190, 7, rowBg)

			count := owaspCounts[cat.ID]
			hasFindings := count > 0

			// Status accent
			if hasFindings {
				drawRect(10, rowY, 2, 7, red)
			} else {
				drawRect(10, rowY, 2, 7, teal)
			}

			pdf.SetXY(12, rowY)
			pdf.SetFont("Helvetica", "B", 7)
			if hasFindings {
				setColor(coral)
			} else {
				setColor(gray)
			}
			pdf.CellFormat(16, 7, cat.ID, "", 0, "L", false, 0, "")

			pdf.SetFont("Helvetica", "", 7)
			if hasFindings {
				setColor(white)
			} else {
				setColor(gray)
			}
			pdf.CellFormat(120, 7, cat.Name, "", 0, "L", false, 0, "")

			pdf.SetFont("Helvetica", "B", 7)
			if hasFindings {
				setColor(red)
				pdf.CellFormat(20, 7, fmt.Sprintf("%d", count), "", 0, "C", false, 0, "")
				pdf.SetFont("Helvetica", "B", 6)
				drawRect(166, rowY+1, 22, 5, red)
				pdf.SetTextColor(255, 255, 255)
				pdf.SetXY(166, rowY+1)
				pdf.CellFormat(22, 5, tr("FOUND"), "", 0, "C", false, 0, "")
			} else {
				setColor(gray)
				pdf.CellFormat(20, 7, "0", "", 0, "C", false, 0, "")
				pdf.SetFont("Helvetica", "", 6)
				setColor(teal)
				pdf.SetXY(166, rowY+1)
				pdf.CellFormat(22, 5, "CLEAR", "", 0, "C", false, 0, "")
			}
			pdf.Ln(7)
		}

		// ── PTES Phase Mapping ──
		if len(ptesCounts) > 0 {
			pdf.Ln(8)
			if pdf.GetY() > 230 {
				pdf.AddPage()
				drawRect(0, 0, 210, 297, darkBg)
				drawRect(0, 0, 210, 1.5, teal)
				pdf.SetY(15)
			}

			pdf.SetFont("Helvetica", "B", 13)
			setColor(teal)
			pdf.CellFormat(190, 8, tr("PTES Phase Mapping"), "", 1, "L", false, 0, "")
			pdf.Ln(2)

			ptesPhases := []string{
				"Intelligence Gathering",
				"Vulnerability Analysis",
				"Exploitation",
				"Post-Exploitation",
				"Reporting",
			}

			// Table header
			ptThY := pdf.GetY()
			drawRect(10, ptThY, 190, 8, sectionBg)
			pdf.SetFont("Helvetica", "B", 7)
			setColor(teal)
			pdf.SetXY(12, ptThY+1)
			pdf.CellFormat(100, 6, tr("PTES PHASE"), "", 0, "L", false, 0, "")
			pdf.CellFormat(30, 6, tr("FINDINGS"), "", 0, "C", false, 0, "")
			pdf.CellFormat(50, 6, tr("STATUS"), "", 0, "C", false, 0, "")
			pdf.Ln(8)

			for j, phase := range ptesPhases {
				rowY := pdf.GetY()
				rowBg := darkBg
				if j%2 == 0 {
					rowBg = sectionBg
				}
				drawRect(10, rowY, 190, 7, rowBg)

				count := ptesCounts[phase]
				hasFindings := count > 0

				if hasFindings {
					drawRect(10, rowY, 2, 7, coral)
				} else {
					drawRect(10, rowY, 2, 7, gray)
				}

				pdf.SetXY(12, rowY)
				pdf.SetFont("Helvetica", "", 7)
				if hasFindings {
					setColor(white)
				} else {
					setColor(gray)
				}
				pdf.CellFormat(100, 7, tr(phase), "", 0, "L", false, 0, "")

				pdf.SetFont("Helvetica", "B", 7)
				if hasFindings {
					setColor(coral)
					pdf.CellFormat(30, 7, fmt.Sprintf("%d", count), "", 0, "C", false, 0, "")
					pdf.SetFont("Helvetica", "B", 6)
					setColor(white)
					pdf.CellFormat(50, 7, tr("TESTED"), "", 0, "C", false, 0, "")
				} else {
					setColor(gray)
					pdf.CellFormat(30, 7, "0", "", 0, "C", false, 0, "")
					pdf.SetFont("Helvetica", "", 6)
					pdf.CellFormat(50, 7, "—", "", 0, "C", false, 0, "")
				}
				pdf.Ln(7)
			}
		}
	}

	// Save PDF — use currentScanDir which is the actual scan directory
	reportID := scan.ID
	if strings.TrimSpace(reportID) == "" && s.currentScanDir != "" {
		reportID = filepath.Base(s.currentScanDir)
	}
	if strings.TrimSpace(reportID) == "" {
		reportID = "scan"
	}
	filename := fmt.Sprintf("xalgorix_report_%s.pdf", reportID)
	// Try saving to the scan directory first, fall back to dataDir
	outPath := filepath.Join(s.currentScanDir, filename)
	if s.currentScanDir == "" {
		outPath = filepath.Join(s.dataDir, filename)
	}
	err := pdf.OutputFileAndClose(outPath)
	if err != nil {
		return "", fmt.Errorf("failed to generate PDF: %w", err)
	}

	return outPath, nil
}

// extractURL extracts a clean URL from a string
func extractURL(s string) string {
	start := strings.Index(s, "http")
	if start == -1 {
		return ""
	}
	end := len(s)
	delimiters := []string{" ", "\"", "'", ">", "<", "|", "\n", "\r"}
	for _, d := range delimiters {
		if idx := strings.Index(s[start:], d); idx != -1 && start+idx < end {
			end = start + idx
		}
	}
	url := s[start:end]
	url = strings.TrimSpace(url)
	url = strings.TrimRight(url, ".,;:!)]}>")
	return url
}
