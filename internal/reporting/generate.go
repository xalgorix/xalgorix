package reporting

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/go-pdf/fpdf"
)

// naText is the ASCII placeholder used where a value is absent (CVSS/CVE/CWE
// columns, etc.). It replaces the em dash previously used as a literal — the
// core-font (cp1252) PDF renderer would otherwise emit mojibake for it.
const naText = "-"

// asciiPunct maps the non-ASCII punctuation/symbols the LLM commonly emits to
// safe ASCII equivalents. The PDF is rendered with fpdf's standard Helvetica/
// Courier fonts, which are single-byte (cp1252): writing raw UTF-8 bytes makes
// an em dash "—" (0xE2 0x80 0x94) render as "â€". Transliterating to ASCII up
// front keeps the exported PDF readable and mojibake-free while leaving the
// HTML report (real UTF-8) untouched.
var asciiPunct = map[rune]string{
	'‐': "-", '‑': "-", '‒': "-", '–': "-", '—': "-",
	'―': "-", '−': "-",
	'‘': "'", '’': "'", '‚': "'", '‛': "'",
	'′': "'", '‵': "'",
	'“': "\"", '”': "\"", '„': "\"", '‟': "\"",
	'″': "\"", '‶': "\"", '«': "\"", '»': "\"",
	'‹': "'", '›': "'",
	'…': "...", '•': "*", '·': "*", '‣': "*", '◦': "*",
	'→': "->", '⇒': "=>", '←': "<-", '⇐': "<=",
	'↔': "<->", '⇔': "<=>",
	'\u00A0': " ", '\u2009': " ", '\u200A': " ", '\u202F': " ", '\u2007': " ",
	'×': "x", '⁄': "/",
	'✓': "[x]", '✔': "[x]", '✅': "[x]",
	'✗': "[!]", '✘': "[!]", '❌': "[!]", '⚠': "[!]",
}

// sanitizeForPDF transliterates non-ASCII text to an ASCII-safe form so the
// core-font PDF renderer never produces mojibake. ASCII (including newlines
// and tabs) passes through untouched; known punctuation/symbols are mapped to
// ASCII equivalents; any remaining printable non-ASCII rune becomes '?' and
// non-printable runes are dropped.
func sanitizeForPDF(s string) string {
	if s == "" {
		return s
	}
	isASCII := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			isASCII = false
			break
		}
	}
	if isASCII {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r < 0x80:
			b.WriteRune(r)
		case asciiPunct[r] != "":
			b.WriteString(asciiPunct[r])
		case r == '\uFEFF' || unicode.Is(unicode.Mn, r):
			// BOM / combining marks: drop.
		case unicode.IsPrint(r):
			b.WriteByte('?')
		}
	}
	return b.String()
}

// sanitizeScanForPDF returns a copy of scan with every text field
// transliterated to ASCII-safe form for the PDF renderer. It never mutates the
// caller's struct (the same *Scan feeds the UTF-8 HTML report).
func sanitizeScanForPDF(s *Scan) *Scan {
	c := *s
	c.ID = sanitizeForPDF(s.ID)
	c.Name = sanitizeForPDF(s.Name)
	c.Target = sanitizeForPDF(s.Target)
	c.CompanyName = sanitizeForPDF(s.CompanyName)
	c.Status = sanitizeForPDF(s.Status)

	c.Vulns = make([]Vuln, len(s.Vulns))
	for i, v := range s.Vulns {
		v.Title = sanitizeForPDF(v.Title)
		v.Target = sanitizeForPDF(v.Target)
		v.Endpoint = sanitizeForPDF(v.Endpoint)
		v.CVSSVector = sanitizeForPDF(v.CVSSVector)
		v.Description = sanitizeForPDF(v.Description)
		v.Impact = sanitizeForPDF(v.Impact)
		v.Method = sanitizeForPDF(v.Method)
		v.CVE = sanitizeForPDF(v.CVE)
		v.CWE = sanitizeForPDF(v.CWE)
		v.OWASP = sanitizeForPDF(v.OWASP)
		v.TechnicalAnalysis = sanitizeForPDF(v.TechnicalAnalysis)
		v.PoCDescription = sanitizeForPDF(v.PoCDescription)
		v.PoCScript = sanitizeForPDF(v.PoCScript)
		v.Remediation = sanitizeForPDF(v.Remediation)
		v.Fix = sanitizeForPDF(v.Fix)
		v.ExploitationProof = sanitizeForPDF(v.ExploitationProof)
		v.VerificationMethod = sanitizeForPDF(v.VerificationMethod)
		c.Vulns[i] = v
	}

	c.Events = make([]Event, len(s.Events))
	for i, e := range s.Events {
		e.Content = sanitizeForPDF(e.Content)
		e.Output = sanitizeForPDF(e.Output)
		e.Error = sanitizeForPDF(e.Error)
		e.ToolName = sanitizeForPDF(e.ToolName)
		if e.ToolArgs != nil {
			na := make(map[string]string, len(e.ToolArgs))
			for k, val := range e.ToolArgs {
				na[k] = sanitizeForPDF(val)
			}
			e.ToolArgs = na
		}
		c.Events[i] = e
	}
	return &c
}

// Options configures a single Generate invocation.
//
// LogoPath is an OPTIONAL pre-resolved, pre-validated absolute path to a
// PNG/JPEG logo for trusted local callers. The web layer supplies LogoData
// and LogoType (png/jpeg) instead, so the renderer cannot reopen a user path.
// LogoData takes precedence over LogoPath. With neither, branding uses initials.
//
// ScanDir is the per-scan working directory. When non-empty the report
// is written to <ScanDir>/<filename>; otherwise it is written to
// <FallbackDir>/<filename>. The naming and fallback rules match the
// previous (*Server).generateReport behavior exactly.
//
// FallbackDir is consulted only when ScanDir is empty.
type Options struct {
	LogoPath    string
	LogoData    []byte
	LogoType    string
	ScanDir     string
	FallbackDir string
}

// tableCol describes one column of a paginatedTable.
type tableCol struct {
	header string
	w      float64
	align  string
}

// Generate renders the branded PDF report for scan and writes it to disk.
// It returns the absolute output path on success.
//
// Visual design: rounded, hairline-bordered cards on a dark canvas, a
// small outline-icon language, and a page chrome (breadcrumb + footer)
// repeated on every page. This mirrors the Xalgorix product's own report
// mockups rather than being an original layout — see the design review
// thread that produced it for the reference pages. The palette (colors,
// severity coding) is unchanged from ThemePalette; only how it is applied
// changed.
func Generate(scan *Scan, opts Options) (string, error) {
	// The PDF is rendered with fpdf's core cp1252 fonts, which mojibake raw
	// UTF-8. Work from an ASCII-transliterated copy so every downstream write
	// is safe; the caller's original struct (used by the UTF-8 HTML report) is
	// left untouched.
	scan = sanitizeScanForPDF(scan)

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 22)

	palette := ThemePalette()
	darkBg := palette.BG
	accent := palette.Accent
	white := palette.FG
	gray := palette.Subtle
	red := palette.Critical
	orange := palette.High
	amber := palette.Medium
	greenLow := palette.Low
	sectionBg := palette.Card
	codeBg := palette.Code
	border := palette.Border

	startTime := ParseTime(scan.StartedAt)
	endTime := ParseTime(scan.FinishedAt)
	duration := FormatDuration(startTime, endTime)
	brandName := BrandName(scan)
	logoPath := opts.LogoPath
	if len(opts.LogoData) > 0 {
		logoPath = "uploaded-report-logo"
	}
	hasLogo := logoPath != ""

	const (
		pageW   = 210.0
		marginX = 10.0
		cardW   = 190.0 // marginX .. 200
		textX   = 16.0  // inside-card text inset
		textW   = 178.0
		footY   = 273.0 // last usable Y before the footer band
	)

	// ── Low-level drawing primitives ──────────────────────────────
	setColor := func(c [3]int) {
		pdf.SetTextColor(c[0], c[1], c[2])
	}
	drawRect := func(x, y, w, h float64, c [3]int) {
		pdf.SetFillColor(c[0], c[1], c[2])
		pdf.Rect(x, y, w, h, "F")
	}
	hairline := func(x1, y, x2 float64, c [3]int) {
		pdf.SetDrawColor(c[0], c[1], c[2])
		pdf.SetLineWidth(0.15)
		pdf.Line(x1, y, x2, y)
	}
	vline := func(x, y1, y2 float64, c [3]int) {
		pdf.SetDrawColor(c[0], c[1], c[2])
		pdf.SetLineWidth(0.15)
		pdf.Line(x, y1, x, y2)
	}
	// card draws a filled, hairline-bordered, rounded-corner container —
	// the single recurring container shape the whole report is built
	// from (stat tiles, tables, per-finding panels, recon groups).
	card := func(x, y, w, h float64, strokeColor [3]int) {
		pdf.SetFillColor(sectionBg[0], sectionBg[1], sectionBg[2])
		pdf.SetDrawColor(strokeColor[0], strokeColor[1], strokeColor[2])
		pdf.SetLineWidth(0.25)
		pdf.RoundedRect(x, y, w, h, 2.6, "1234", "FD")
	}

	// ── Icon language ──────────────────────────────────────────────
	// icon draws a single glyph, stroke-only, inside a size x size box
	// anchored at (x, y). It intentionally covers a small fixed set of
	// shapes (line-icon style) rather than embedding an icon font —
	// fpdf's core fonts can't do that, and simple vector glyphs read
	// fine at report scale.
	icon := func(kind string, x, y, size float64, color [3]int) {
		cx, cy, r := x+size/2, y+size/2, size/2
		pdf.SetDrawColor(color[0], color[1], color[2])
		pdf.SetFillColor(color[0], color[1], color[2])
		pdf.SetLineWidth(size * 0.09)
		pdf.SetLineCapStyle("round")
		switch kind {
		case "check":
			pdf.Line(cx-r*0.5, cy, cx-r*0.1, cy+r*0.4)
			pdf.Line(cx-r*0.1, cy+r*0.4, cx+r*0.5, cy-r*0.4)
		case "shield":
			pdf.Polygon([]fpdf.PointType{
				{X: cx, Y: cy - r}, {X: cx + r*0.8, Y: cy - r*0.55}, {X: cx + r*0.8, Y: cy + r*0.1},
				{X: cx, Y: cy + r}, {X: cx - r*0.8, Y: cy + r*0.1}, {X: cx - r*0.8, Y: cy - r*0.55},
			}, "D")
		case "exclaim":
			pdf.Line(cx, cy-r*0.6, cx, cy+r*0.1)
			pdf.Circle(cx, cy+r*0.55, size*0.045, "F")
		case "chevronUp":
			pdf.Line(cx-r*0.5, cy+r*0.25, cx, cy-r*0.35)
			pdf.Line(cx, cy-r*0.35, cx+r*0.5, cy+r*0.25)
		case "chevronDown":
			pdf.Line(cx-r*0.5, cy-r*0.25, cx, cy+r*0.35)
			pdf.Line(cx, cy+r*0.35, cx+r*0.5, cy-r*0.25)
		case "dots3":
			for _, p := range [][2]float64{{0, -0.55}, {-0.5, 0.35}, {0.5, 0.35}} {
				pdf.Circle(cx+p[0]*r, cy+p[1]*r, size*0.07, "F")
			}
		case "info":
			pdf.Line(cx, cy-r*0.05, cx, cy+r*0.5)
			pdf.Circle(cx, cy-r*0.35, size*0.045, "F")
		case "target":
			pdf.SetLineWidth(size * 0.07)
			pdf.Circle(cx, cy, r*0.85, "D")
			pdf.Circle(cx, cy, r*0.45, "D")
			pdf.Circle(cx, cy, size*0.06, "F")
		case "calendar", "calendarCheck":
			pdf.SetLineWidth(size * 0.07)
			pdf.RoundedRect(x+size*0.08, y+size*0.2, size*0.84, size*0.72, size*0.1, "1234", "D")
			pdf.Line(x+size*0.08, y+size*0.42, x+size*0.92, y+size*0.42)
			pdf.Line(x+size*0.3, y+size*0.06, x+size*0.3, y+size*0.28)
			pdf.Line(x+size*0.7, y+size*0.06, x+size*0.7, y+size*0.28)
			if kind == "calendarCheck" {
				pdf.Line(cx-r*0.28, cy+r*0.15, cx-r*0.05, cy+r*0.4)
				pdf.Line(cx-r*0.05, cy+r*0.4, cx+r*0.35, cy-r*0.15)
			}
		case "globe":
			pdf.SetLineWidth(size * 0.07)
			pdf.Circle(cx, cy, r*0.85, "D")
			pdf.Line(x+size*0.06, cy, x+size*0.94, cy)
			pdf.Ellipse(cx, cy, r*0.36, r*0.85, 0, "D")
		case "link":
			pdf.SetLineWidth(size * 0.08)
			pdf.Circle(cx-r*0.32, cy, r*0.5, "D")
			pdf.Circle(cx+r*0.32, cy, r*0.5, "D")
		case "clock":
			pdf.SetLineWidth(size * 0.07)
			pdf.Circle(cx, cy, r*0.85, "D")
			pdf.Line(cx, cy, cx, cy-r*0.5)
			pdf.Line(cx, cy, cx+r*0.35, cy+r*0.05)
		case "refresh":
			pdf.SetLineWidth(size * 0.08)
			pdf.Arc(cx, cy, r*0.75, r*0.75, 0, 40, 320, "D")
			pdf.Polygon([]fpdf.PointType{
				{X: cx + r*0.75*0.766, Y: cy - r*0.75*0.643},
				{X: cx + r*0.75*0.98, Y: cy - r*0.75*0.45},
				{X: cx + r*0.4, Y: cy - r*0.75*0.75},
			}, "F")
		case "terminal":
			pdf.SetLineWidth(size * 0.07)
			pdf.RoundedRect(x+size*0.05, y+size*0.12, size*0.9, size*0.76, size*0.1, "1234", "D")
			pdf.Line(x+size*0.22, y+size*0.34, x+size*0.4, y+size*0.5)
			pdf.Line(x+size*0.22, y+size*0.66, x+size*0.4, y+size*0.5)
			pdf.Line(x+size*0.48, y+size*0.66, x+size*0.68, y+size*0.66)
		case "database":
			pdf.SetLineWidth(size * 0.07)
			pdf.Ellipse(cx, cy-r*0.5, r*0.75, r*0.22, 0, "D")
			pdf.Line(cx-r*0.75, cy-r*0.5, cx-r*0.75, cy+r*0.5)
			pdf.Line(cx+r*0.75, cy-r*0.5, cx+r*0.75, cy+r*0.5)
			pdf.Ellipse(cx, cy+r*0.5, r*0.75, r*0.22, 0, "D")
		case "copy":
			pdf.SetLineWidth(size * 0.08)
			pdf.RoundedRect(x+size*0.08, y+size*0.28, size*0.58, size*0.58, size*0.08, "1234", "D")
			pdf.RoundedRect(x+size*0.34, y+size*0.08, size*0.58, size*0.58, size*0.08, "1234", "D")
		case "scanCorners":
			pdf.SetLineWidth(size * 0.09)
			l := size * 0.28
			for _, cnr := range [][4]float64{
				{x, y, l, 0}, {x, y, 0, l},
				{x + size, y, -l, 0}, {x + size, y, 0, l},
				{x, y + size, l, 0}, {x, y + size, 0, -l},
				{x + size, y + size, -l, 0}, {x + size, y + size, 0, -l},
			} {
				pdf.Line(cnr[0], cnr[1], cnr[0]+cnr[2], cnr[1]+cnr[3])
			}
		case "doc":
			pdf.SetLineWidth(size * 0.07)
			pdf.RoundedRect(x+size*0.18, y+size*0.06, size*0.64, size*0.88, size*0.08, "1234", "D")
			for _, off := range []float64{0.34, 0.52, 0.7} {
				pdf.Line(x+size*0.3, y+size*off, x+size*0.7, y+size*off)
			}
		case "chip":
			pdf.SetLineWidth(size * 0.07)
			pdf.RoundedRect(x+size*0.24, y+size*0.24, size*0.52, size*0.52, size*0.06, "1234", "D")
			for _, off := range []float64{0.36, 0.64} {
				pdf.Line(x+size*off, y+size*0.24, x+size*off, y+size*0.1)
				pdf.Line(x+size*off, y+size*0.76, x+size*off, y+size*0.9)
				pdf.Line(x+size*0.24, y+size*off, x+size*0.1, y+size*off)
				pdf.Line(x+size*0.76, y+size*off, x+size*0.9, y+size*off)
			}
		case "search":
			pdf.SetLineWidth(size * 0.08)
			pdf.Circle(cx-r*0.15, cy-r*0.15, r*0.5, "D")
			pdf.Line(cx+r*0.22, cy+r*0.22, cx+r*0.62, cy+r*0.62)
		}
		pdf.SetLineCapStyle("butt")
		pdf.SetLineWidth(0.2)
	}
	// iconCircled draws a thin outline circle of radius r centered at
	// (cx, cy) with the glyph kind inset inside it — the "badge" icon
	// treatment used for stat tiles and card headers.
	iconCircled := func(kind string, cx, cy, r float64, ringColor, glyphColor [3]int) {
		pdf.SetDrawColor(ringColor[0], ringColor[1], ringColor[2])
		pdf.SetLineWidth(0.28)
		pdf.Circle(cx, cy, r, "D")
		inset := r * 1.05
		icon(kind, cx-inset/2, cy-inset/2, inset, glyphColor)
	}

	// texture paints a faint, fixed (non-random, so the render stays
	// deterministic across runs) decoration on top of the flat canvas: a
	// radar-like ring cluster anchored in the top-right corner and a
	// sparse scatter of dots, both at very low alpha in the accent
	// color. It is intentionally subtle — the brief was to declutter the
	// report, not to reintroduce visual noise — but a perfectly flat
	// black page reads as unfinished next to the product's own
	// marketing surfaces, which all carry this texture.
	texture := func() {
		pdf.SetAlpha(0.05, "Normal")
		pdf.SetDrawColor(accent[0], accent[1], accent[2])
		pdf.SetLineWidth(0.3)
		for _, rr := range []float64{16, 28, 40, 52, 64} {
			pdf.Circle(pageW-4, 36, rr, "D")
		}
		pdf.SetAlpha(0.16, "Normal")
		pdf.SetFillColor(accent[0], accent[1], accent[2])
		for _, d := range [][2]float64{
			{182, 10}, {194, 48}, {160, 86}, {203, 110}, {172, 140},
			{14, 268}, {40, 288}, {6, 230}, {198, 250}, {150, 20},
			{60, 12}, {120, 8}, {8, 150}, {204, 180},
		} {
			pdf.Circle(d[0], d[1], 0.45, "F")
		}
		pdf.SetAlpha(1, "Normal")
	}

	// fpdf can create pages implicitly when MultiCell content crosses a page
	// boundary. Paint every implicit page before content lands on it.
	paintPage := func() {
		drawRect(0, 0, pageW, 297, darkBg)
		texture()
		drawRect(0, 0, pageW, 1.4, accent)
	}
	pdf.SetHeaderFunc(paintPage)

	// Page chrome: every page except the cover gets a thin footer rule —
	// brand + tagline on the left, page number on the right — stamped
	// automatically by fpdf on every page (including ones created by an
	// implicit page break mid-table), so continuation pages never go bare.
	pdf.SetFooterFunc(func() {
		if pdf.PageNo() <= 1 {
			return
		}
		pdf.SetY(-16)
		hairline(marginX, pdf.GetY(), marginX+cardW, border)
		pdf.SetY(-12)
		pdf.SetX(marginX)
		pdf.SetFont("Helvetica", "B", 7.5)
		setColor(accent)
		pdf.CellFormat(20, 5, "XALGORIX", "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 7)
		setColor(gray)
		pdf.CellFormat(140, 5, "  |  AUTONOMOUS AI-POWERED SECURITY ASSESSMENT", "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "B", 8)
		setColor(accent)
		pdf.CellFormat(cardW-160, 5, fmt.Sprintf("%02d", pdf.PageNo()), "", 0, "R", false, 0, "")
	})

	newPage := func() {
		pdf.AddPage()
		pdf.SetY(15)
	}
	// breakIfNeeded starts a fresh page when the cursor has crossed
	// threshold, so callers don't repeat "AddPage + reset Y" everywhere.
	breakIfNeeded := func(threshold float64) bool {
		if pdf.GetY() > threshold {
			newPage()
			return true
		}
		return false
	}

	// pageHeader renders the breadcrumb (page index + section label),
	// the big page title with its accent underline, and returns the Y
	// the caller's content should start at.
	pageHeader := func(title, sectionLabel string, accentColor [3]int) {
		pdf.SetXY(marginX, 14)
		pdf.SetFont("Helvetica", "B", 10)
		setColor(accentColor)
		pdf.CellFormat(90, 5, fmt.Sprintf("%02d", pdf.PageNo()), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 8)
		setColor(gray)
		pdf.CellFormat(cardW-90, 5, strings.ToUpper(sectionLabel), "", 1, "R", false, 0, "")
		hairline(marginX, pdf.GetY()+1, marginX+cardW, border)
		pdf.SetXY(marginX, 24)
		pdf.SetFont("Helvetica", "B", 20)
		setColor(white)
		pdf.CellFormat(cardW, 10, title, "", 1, "L", false, 0, "")
		drawRect(marginX, pdf.GetY()+1, 26, 0.8, accentColor)
		pdf.Ln(9)
	}
	// headingWithIcon renders a mid-page heading (e.g. "Risk Assessment")
	// with a small circled icon to its left, used to introduce a prose
	// block or a card without wrapping the heading itself in a card.
	headingWithIcon := func(kind, title string, accentColor [3]int, size float64) {
		y := pdf.GetY()
		iconCircled(kind, marginX+3.2, y+3.6, 3.2, accentColor, accentColor)
		pdf.SetXY(marginX+9, y+0.5)
		pdf.SetFont("Helvetica", "B", size)
		setColor(white)
		pdf.CellFormat(cardW-9, 7, title, "", 1, "L", false, 0, "")
		drawRect(marginX+9, pdf.GetY()+0.5, 18, 0.7, accentColor)
		pdf.Ln(6)
	}

	// severity color
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
			return gray
		}
	}
	sevIcon := func(sev string) string {
		switch strings.ToLower(sev) {
		case "critical":
			return "exclaim"
		case "high":
			return "chevronUp"
		case "medium":
			return "dots3"
		case "low":
			return "chevronDown"
		default:
			return "info"
		}
	}

	// paginatedRows draws n fixed-height rows wrapped in one or more
	// rounded cards, breaking cleanly across pages when the row count
	// would overflow. renderRow draws row idx's content at the given Y —
	// callers are responsible only for text/icon placement, not the
	// card chrome or the inter-row hairline.
	paginatedRows := func(rowH float64, n int, strokeColor [3]int, renderRow func(y float64, idx int)) {
		if n == 0 {
			return
		}
		y := pdf.GetY()
		idx := 0
		for idx < n {
			if footY-y < rowH {
				newPage()
				y = pdf.GetY()
			}
			rows := int((footY - y) / rowH)
			if rows < 1 {
				rows = 1
			}
			if rows > n-idx {
				rows = n - idx
			}
			chunkH := float64(rows) * rowH
			card(marginX, y, cardW, chunkH, strokeColor)
			for r := 0; r < rows; r++ {
				rowY := y + float64(r)*rowH
				if r > 0 {
					hairline(textX-2, rowY, marginX+cardW-4, border)
				}
				renderRow(rowY, idx)
				idx++
			}
			y += chunkH
			if idx < n {
				newPage()
				y = pdf.GetY()
			}
		}
		pdf.SetY(y + 8)
	}

	// paginatedTable is paginatedRows plus a repeating column header bar,
	// used for the data tables (Findings Summary, CWE/OWASP/PTES
	// reference index) that previously rendered as bare striped tables.
	paginatedTable := func(accentColor [3]int, cols []tableCol, n int, cellFn func(row, col int) (string, [3]int)) {
		if n == 0 {
			return
		}
		rowH := 8.0
		headerH := 9.0
		drawHeader := func(y float64) {
			card(marginX, y, cardW, headerH, border)
			cx := textX
			pdf.SetFont("Helvetica", "B", 7.3)
			setColor(accentColor)
			for _, c := range cols {
				pdf.SetXY(cx, y+2.6)
				pdf.CellFormat(c.w-2, 4, strings.ToUpper(c.header), "", 0, c.align, false, 0, "")
				cx += c.w
			}
		}
		y := pdf.GetY()
		drawHeader(y)
		y += headerH + 3
		idx := 0
		for idx < n {
			if footY-y < rowH {
				newPage()
				y = pdf.GetY()
				drawHeader(y)
				y += headerH + 3
			}
			rows := int((footY - y) / rowH)
			if rows < 1 {
				rows = 1
			}
			if rows > n-idx {
				rows = n - idx
			}
			chunkH := float64(rows) * rowH
			card(marginX, y, cardW, chunkH, border)
			for r := 0; r < rows; r++ {
				rowY := y + float64(r)*rowH
				if r > 0 {
					hairline(textX-2, rowY, marginX+cardW-4, border)
				}
				cx := textX
				pdf.SetFont("Helvetica", "", 7.3)
				for ci, c := range cols {
					text, color := cellFn(idx, ci)
					setColor(color)
					pdf.SetXY(cx, rowY+1.7)
					pdf.CellFormat(c.w-2, rowH-3, text, "", 0, c.align, false, 0, "")
					cx += c.w
				}
				idx++
			}
			y += chunkH
			if idx < n {
				newPage()
				y = pdf.GetY()
				drawHeader(y)
				y += headerH + 3
			}
		}
		pdf.SetY(y + 8)
	}

	// listCard renders one recon-style card: a circled icon + header on
	// the left edge, a vertical divider, and a bulleted list on the
	// right. cols > 1 lays the items out in a short-word grid (used for
	// the technology list) instead of one item per line. Long lists
	// split across multiple page-chunk cards (mirrors paginatedRows)
	// instead of overflowing past a single card's bottom edge.
	listCard := func(kind, title string, items []string, cols int, accentColor [3]int) {
		if len(items) == 0 {
			return
		}
		if cols < 1 {
			cols = 1
		}
		lineH := 5.6
		headerH := 11.0
		colW := (cardW - 40) / float64(cols)
		totalRows := (len(items) + cols - 1) / cols

		row := 0
		first := true
		for row < totalRows {
			topPad := 6.0
			if first {
				topPad = headerH
			}
			if footY-pdf.GetY() < topPad+lineH+6 {
				newPage()
			}
			y := pdf.GetY()
			avail := footY - y - topPad - 6
			rows := int(avail / lineH)
			if rows < 1 {
				rows = 1
			}
			if rows > totalRows-row {
				rows = totalRows - row
			}
			bodyH := float64(rows)*lineH + 6
			total := topPad + bodyH
			card(marginX, y, cardW, total, border)
			vline(marginX+24, y+4, y+total-4, border)
			if first {
				iconCircled(kind, marginX+13, y+total/2, 7, accentColor, accentColor)
				pdf.SetXY(marginX+30, y+7)
				pdf.SetFont("Helvetica", "B", 9)
				setColor(white)
				pdf.CellFormat(cardW-40, 5, strings.ToUpper(title), "", 1, "L", false, 0, "")
			}
			pdf.SetFont("Helvetica", "", 8)
			for r := 0; r < rows; r++ {
				for c := 0; c < cols; c++ {
					i := (row+r)*cols + c
					if i >= len(items) {
						break
					}
					ix := marginX + 30 + float64(c)*colW
					iy := y + topPad + float64(r)*lineH
					drawRect(ix, iy+1.8, 1.3, 1.3, accentColor)
					setColor([3]int{214, 214, 214})
					pdf.SetXY(ix+4, iy)
					pdf.CellFormat(colW-6, lineH, items[i], "", 0, "L", false, 0, "")
				}
			}
			row += rows
			pdf.SetY(y + total)
			first = false
			if row < totalRows {
				newPage()
			}
		}
		pdf.SetY(pdf.GetY() + 6)
	}

	// ─── COVER PAGE ────────────────────────────────────────
	// AddPage() already ran paintPage via SetHeaderFunc (canvas fill +
	// texture); only thicken the top accent bar for the cover's bolder
	// brand treatment, don't repaint over the texture.
	pdf.AddPage()
	drawRect(0, 0, pageW, 3, accent)

	pdf.SetXY(marginX, 16)
	pdf.SetFont("Helvetica", "B", 20)
	setColor(white)
	pdf.CellFormat(150, 8, "Xalgorix", "", 1, "L", false, 0, "")
	pdf.SetX(marginX)
	pdf.SetFont("Helvetica", "", 8.5)
	setColor(gray)
	pdf.CellFormat(150, 5, "Autonomous AI-powered security assessment", "", 1, "L", false, 0, "")

	titleW := cardW
	if hasLogo {
		titleW = cardW - 66
		logoX, logoY, logoSize := marginX+cardW-58, 40.0, 58.0
		var info *fpdf.ImageInfoType
		if len(opts.LogoData) > 0 {
			info = pdf.RegisterImageOptionsReader(logoPath, fpdf.ImageOptions{ImageType: opts.LogoType}, bytes.NewReader(opts.LogoData))
		} else {
			info = pdf.RegisterImage(logoPath, "")
		}
		if info != nil && info.Height() > 0 && info.Width() > 0 {
			imgW := logoSize
			imgH := info.Height() * imgW / info.Width()
			if imgH > logoSize {
				imgH = logoSize
				imgW = info.Width() * imgH / info.Height()
			}
			pdf.ImageOptions(logoPath, logoX+(logoSize-imgW)/2, logoY+(logoSize-imgH)/2, imgW, imgH, false, fpdf.ImageOptions{}, 0, "")
		}
	}

	pdf.SetXY(marginX, 42)
	pdf.SetFont("Helvetica", "B", 30)
	setColor(white)
	pdf.MultiCell(titleW, 12, "SECURITY\nASSESSMENT", "", "L", false)
	pdf.SetX(marginX)
	setColor(accent)
	pdf.CellFormat(titleW, 12, "REPORT", "", 1, "L", false, 0, "")
	drawRect(marginX, pdf.GetY()+2, 34, 1, accent)
	pdf.Ln(8)

	pdf.SetX(marginX)
	iconCircled("globe", marginX+3, pdf.GetY()+3, 3, accent, accent)
	pdf.SetXY(marginX+9, pdf.GetY())
	pdf.SetFont("Helvetica", "", 10)
	setColor(white)
	pdf.CellFormat(titleW-9, 6.5, DisplayText(brandName, "Target", 60), "", 1, "L", false, 0, "")
	pdf.SetX(marginX)
	iconCircled("link", marginX+3, pdf.GetY()+3, 3, accent, accent)
	pdf.SetXY(marginX+9, pdf.GetY())
	pdf.SetFont("Courier", "", 8.5)
	setColor(accent)
	pdf.CellFormat(titleW-9, 6.5, DisplayText(scan.Target, "No target recorded", 70), "", 1, "L", false, 0, "")
	pdf.Ln(4)

	coverScore := RiskScore(scan.Vulns)
	coverLabel := RiskLabel(coverScore)
	coverColor := sevColor(strings.ToLower(coverLabel))

	statY := pdf.GetY() + 4
	statGap := 6.0
	statW := (cardW - 3*statGap) / 4.0
	statH := 30.0
	coverStats := []struct {
		iconKind, label, value string
		color                  [3]int
	}{
		{"check", "STATUS", strings.ToUpper(DisplayText(scan.Status, "unknown", 14)), accent},
		{"shield", "RISK", coverLabel, coverColor},
		{"target", "FINDINGS", fmt.Sprintf("%d", len(scan.Vulns)), red},
		{"calendar", "STARTED", FormatDate(startTime), white},
	}
	for i, s := range coverStats {
		x := marginX + float64(i)*(statW+statGap)
		card(x, statY, statW, statH, border)
		iconCircled(s.iconKind, x+statW/2, statY+9, 4.4, s.color, s.color)
		pdf.SetXY(x+2, statY+16.5)
		pdf.SetFont("Helvetica", "", 7)
		setColor(gray)
		pdf.CellFormat(statW-4, 4, s.label, "", 1, "C", false, 0, "")
		hairline(x+statW/2-6, statY+21.5, x+statW/2+6, border)
		pdf.SetXY(x+2, statY+23.5)
		pdf.SetFont("Helvetica", "B", 11)
		setColor(s.color)
		pdf.CellFormat(statW-4, 6, s.value, "", 0, "C", false, 0, "")
	}

	scanIDY := statY + statH + 8
	card(marginX, scanIDY, cardW, 20, border)
	iconCircled("scanCorners", marginX+14, scanIDY+10, 7, accent, accent)
	vline(marginX+25, scanIDY+4, scanIDY+16, border)
	pdf.SetXY(marginX+31, scanIDY+4)
	pdf.SetFont("Helvetica", "B", 7.5)
	setColor(gray)
	pdf.CellFormat(130, 4, "SCAN ID", "", 1, "L", false, 0, "")
	pdf.SetXY(marginX+31, scanIDY+9.5)
	pdf.SetFont("Courier", "", 9.5)
	setColor(white)
	pdf.CellFormat(130, 5, DisplayText(scan.ID, "not recorded", 60), "", 0, "L", false, 0, "")
	icon("copy", marginX+cardW-16, scanIDY+6, 8, gray)

	pdf.SetY(258)
	hairline(marginX, pdf.GetY(), marginX+cardW, border)
	pdf.Ln(6)
	pdf.SetFont("Helvetica", "B", 9)
	setColor(accent)
	pdf.CellFormat(20, 5, "XALGORIX", "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 8)
	setColor(gray)
	pdf.CellFormat(160, 5, "  |  AUTONOMOUS AI-POWERED SECURITY ASSESSMENT", "", 1, "L", false, 0, "")
	pdf.SetFillColor(accent[0], accent[1], accent[2])
	pdf.Polygon([]fpdf.PointType{
		{X: marginX + cardW - 8, Y: 266}, {X: marginX + cardW, Y: 266}, {X: marginX + cardW, Y: 274},
	}, "F")
	drawRect(0, 294, pageW, 3, accent)

	// ─── EXECUTIVE SUMMARY ─────────────────────────────────
	newPage()
	pageHeader("Executive Summary", "Executive Summary", accent)

	type statCard struct {
		label, value, iconKind string
		color                  [3]int
	}

	// Count severity. The rollup is delegated to RollupSeverities so
	// the cover-page numbers stay in lock-step with the value
	// returned to API callers (e.g. the cloud Reports list endpoint).
	rollup := RollupSeverities(scan.Vulns)
	critCount := rollup.Critical
	highCount := rollup.High
	medCount := rollup.Medium
	lowCount := rollup.Low
	infoCount := rollup.Info

	cards := []statCard{
		{"Total Vulnerabilities", fmt.Sprintf("%d", len(scan.Vulns)), "target", accent},
		{"Critical", fmt.Sprintf("%d", critCount), sevIcon("critical"), red},
		{"High", fmt.Sprintf("%d", highCount), sevIcon("high"), orange},
		{"Medium", fmt.Sprintf("%d", medCount), sevIcon("medium"), amber},
		{"Low", fmt.Sprintf("%d", lowCount), sevIcon("low"), greenLow},
		{"Info", fmt.Sprintf("%d", infoCount), sevIcon(""), gray},
	}

	gap := 6.0
	sw := (cardW - 2*gap) / 3.0
	sh := 22.0
	y0 := pdf.GetY()
	for i, c := range cards {
		col := i % 3
		row := i / 3
		x := marginX + float64(col)*(sw+gap)
		cy := y0 + float64(row)*(sh+gap)
		card(x, cy, sw, sh, border)
		iconCircled(c.iconKind, x+8, cy+7, 4, c.color, c.color)
		pdf.SetXY(x+14, cy+4.5)
		pdf.SetFont("Helvetica", "", 8)
		setColor(gray)
		pdf.CellFormat(sw-16, 5, c.label, "", 1, "L", false, 0, "")
		pdf.SetXY(x+5, cy+12.5)
		pdf.SetFont("Helvetica", "B", 16)
		setColor(c.color)
		pdf.CellFormat(sw-10, 8, c.value, "", 0, "L", false, 0, "")
	}
	pdf.SetY(y0 + 2*(sh+gap) + 6)

	// ── Overall risk — one card, two halves ──
	score := RiskScore(scan.Vulns)
	label := RiskLabel(score)
	riskColor := sevColor(strings.ToLower(label))

	riskY := pdf.GetY()
	card(marginX, riskY, cardW, 24, riskColor)
	halfW := cardW / 2.0
	iconCircled("target", marginX+12, riskY+12, 6, riskColor, riskColor)
	pdf.SetXY(marginX+22, riskY+6)
	pdf.SetFont("Helvetica", "", 8.5)
	setColor(gray)
	pdf.CellFormat(halfW-22, 5, "OVERALL RISK SCORE", "", 1, "L", false, 0, "")
	pdf.SetXY(marginX+22, riskY+12)
	pdf.SetFont("Helvetica", "B", 19)
	setColor(riskColor)
	pdf.CellFormat(halfW-22, 9, fmt.Sprintf("%.1f / 10", score), "", 0, "L", false, 0, "")

	vline(marginX+halfW, riskY+4, riskY+20, border)
	iconCircled("shield", marginX+halfW+14, riskY+12, 6, riskColor, riskColor)
	pdf.SetXY(marginX+halfW+24, riskY+6)
	pdf.SetFont("Helvetica", "", 8.5)
	setColor(gray)
	pdf.CellFormat(halfW-26, 5, "RISK LEVEL", "", 1, "L", false, 0, "")
	pdf.SetXY(marginX+halfW+24, riskY+12)
	pdf.SetFont("Helvetica", "B", 19)
	setColor(riskColor)
	pdf.CellFormat(halfW-26, 9, label, "", 0, "L", false, 0, "")
	pdf.SetY(riskY + 24 + 8)

	// ── Executive Risk Narrative ──
	headingWithIcon("shield", "Risk Assessment", accent, 13)
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
	pdf.SetX(marginX)
	pdf.MultiCell(cardW, 4.5, narrative, "", "L", false)
	pdf.Ln(6)

	// Scan metadata
	headingWithIcon("search", "Scan Details", accent, 13)

	metaItems := [][3]string{
		{"globe", "Target", scan.Target},
		{"check", "Status", strings.ToUpper(scan.Status)},
		{"clock", "Duration", duration},
		{"refresh", "Iterations", fmt.Sprintf("%d", scan.Iterations)},
		{"terminal", "Tool Calls", fmt.Sprintf("%d", scan.ToolCalls)},
		{"database", "Total Tokens", fmt.Sprintf("%d", scan.TotalTokens)},
		{"calendar", "Started", FormatTimestamp(startTime)},
		{"calendarCheck", "Finished", FormatTimestamp(endTime)},
	}
	paginatedRows(9, len(metaItems), border, func(ry float64, i int) {
		m := metaItems[i]
		icon(m[0], textX-1, ry+2, 5, gray)
		pdf.SetXY(textX+7, ry+2.2)
		pdf.SetFont("Helvetica", "", 8.5)
		setColor(gray)
		pdf.CellFormat(42, 5, m[1], "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 8.5)
		setColor(white)
		pdf.CellFormat(textW-7-42, 5, DisplayText(m[2], naText, 90), "", 0, "L", false, 0, "")
	})

	// ─── METHODOLOGY ──────────────────────────────────────
	newPage()
	pageHeader("Testing Methodology", "Testing Methodology", accent)

	pdf.SetFont("Helvetica", "", 9)
	setColor(white)
	pdf.SetX(marginX)
	pdf.MultiCell(cardW, 4.5, "Xalgorix follows a comprehensive 22-phase penetration testing methodology "+
		"aligned with OWASP, PTES, and industry best practices. Each phase is executed by an autonomous AI agent "+
		"with tool access to terminal, browser, and specialized security utilities.", "", "L", false)
	pdf.Ln(5)

	executedPhases := scan.Phases
	allPhases := len(executedPhases) == 0 // empty = all phases
	type phaseRow struct {
		num      int
		name     string
		executed bool
	}
	var phaseRows []phaseRow
	for phaseNum := 1; phaseNum <= 22; phaseNum++ {
		name, ok := MethodologyPhaseNames[phaseNum]
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
		phaseRows = append(phaseRows, phaseRow{phaseNum, name, executed})
	}
	paginatedRows(8.4, len(phaseRows), border, func(ry float64, i int) {
		p := phaseRows[i]
		col := gray
		if p.executed {
			col = accent
		}
		pdf.SetXY(textX, ry+2.1)
		pdf.SetFont("Helvetica", "B", 8.5)
		setColor(col)
		pdf.CellFormat(9, 5, fmt.Sprintf("%02d", p.num), "", 0, "L", false, 0, "")
		setColor(border)
		pdf.SetFont("Helvetica", "", 8.5)
		pdf.CellFormat(4, 5, "|", "", 0, "L", false, 0, "")
		if p.executed {
			setColor(white)
		} else {
			setColor(gray)
		}
		pdf.CellFormat(textW-9-4-32, 5, fmt.Sprintf("Phase %d: %s", p.num, p.name), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "B", 7.3)
		status := "SKIPPED"
		if p.executed {
			status = "SELECTED"
			setColor(accent)
		} else {
			setColor(gray)
		}
		pdf.CellFormat(32, 5, status, "", 0, "R", false, 0, "")
	})

	pdf.SetFont("Helvetica", "", 7.5)
	setColor(gray)
	pdf.SetX(marginX)
	drawRect(marginX+2, pdf.GetY()+1.2, 2.6, 2.6, accent)
	pdf.SetX(marginX + 8)
	pdf.CellFormat(35, 5, "= Executed", "", 0, "L", false, 0, "")
	drawRect(marginX+56, pdf.GetY()+1.2, 2.6, 2.6, gray)
	pdf.SetX(marginX + 62)
	pdf.CellFormat(35, 5, "= Skipped", "", 1, "L", false, 0, "")

	// ─── RECONNAISSANCE FINDINGS ─────────────────────────
	recon := CollectReconSummary(scan.Events)
	if recon.HasData() {
		newPage()
		pageHeader("Reconnaissance Findings", "Reconnaissance Findings", accent)

		pdf.SetFont("Helvetica", "", 9)
		setColor(white)
		pdf.SetX(marginX)
		pdf.MultiCell(cardW, 4.5, "The following non-exploit reconnaissance observations were extracted from the scan feed and tool outputs. These are included for attack-surface documentation and operational handoff.", "", "L", false)
		pdf.Ln(5)

		listCard("globe", "DNS Records", recon.DNSRecords, 1, accent)
		listCard("globe", "Resolved IP Addresses", recon.IPAddresses, 1, accent)
		listCard("terminal", "Open Ports & Services", recon.Ports, 1, accent)
		listCard("chip", "Detected Technologies", recon.Technologies, 3, accent)
		listCard("link", "Observed URLs & Endpoints", recon.URLs, 1, accent)
	}

	// ─── BLUE TEAM TIMESTAMPS ─────────────────────────────
	pdf.Ln(4)
	breakIfNeeded(220)
	headingWithIcon("clock", "Blue Team Reference Timestamps", accent, 15)

	pdf.SetFont("Helvetica", "", 8)
	setColor(gray)
	pdf.SetX(marginX)
	pdf.MultiCell(cardW, 4, "The following RFC3339 timestamps enable Blue Team operators to correlate "+
		"scan activity with SIEM/log sources for use-case development and alert tuning.", "", "L", false)
	pdf.Ln(4)

	tsItems := [][2]string{
		{"Scan Start", scan.StartedAt},
		{"Scan End", scan.FinishedAt},
	}
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
	paginatedRows(7.6, len(tsItems), border, func(ry float64, i int) {
		ts := tsItems[i]
		pdf.SetXY(textX, ry+1.9)
		pdf.SetFont("Helvetica", "", 7.6)
		setColor(gray)
		titleStr := ts[0]
		if titleRunes := []rune(titleStr); len(titleRunes) > 68 {
			titleStr = string(titleRunes[:65]) + "..."
		}
		pdf.CellFormat(118, 5, titleStr, "", 0, "L", false, 0, "")
		pdf.SetFont("Courier", "", 7.6)
		setColor(accent)
		pdf.CellFormat(textW-118, 5, ts[1], "", 0, "L", false, 0, "")
	})

	// Pre-compute all vuln mappings once for the entire report.
	allMappings := make([]Mappings, len(scan.Vulns))
	owaspCounts := make(map[string]int)
	ptesCounts := make(map[string]int)
	for i, v := range scan.Vulns {
		allMappings[i] = InferMappings(v)
		if allMappings[i].OWASP != "" {
			owaspCounts[allMappings[i].OWASP]++
		}
		if allMappings[i].PTES != "" {
			ptesCounts[allMappings[i].PTES]++
		}
	}

	// ─── FINDINGS SUMMARY TABLE ──────────────────────────
	if len(scan.Vulns) > 0 {
		newPage()
		pageHeader("Findings Summary", "Findings Summary", accent)

		pdf.SetFont("Helvetica", "", 8)
		setColor(white)
		pdf.SetX(marginX)
		pdf.MultiCell(cardW, 4, "The following table summarizes all findings with their security framework mappings (CWE, OWASP Top 10 2021). Detailed write-ups follow in the Vulnerability Details section.", "", "L", false)
		pdf.Ln(4)

		cols := []tableCol{
			{"ID", 12, "L"},
			{"Finding", 63, "L"},
			{"Severity", 20, "C"},
			{"CVSS", 13, "C"},
			{"CVE", 32, "L"},
			{"CWE", 18, "L"},
			{"OWASP", 20, "L"},
		}
		paginatedTable(accent, cols, len(scan.Vulns), func(row, col int) (string, [3]int) {
			v := scan.Vulns[row]
			m := allMappings[row]
			switch col {
			case 0:
				return fmt.Sprintf("F-%02d", row+1), gray
			case 1:
				return DisplayText(v.Title, "", 42), white
			case 2:
				return strings.ToUpper(v.Severity), sevColor(v.Severity)
			case 3:
				if v.CVSS > 0 {
					return fmt.Sprintf("%.1f", v.CVSS), white
				}
				return naText, white
			case 4:
				if v.CVE == "" {
					return naText, gray
				}
				return DisplayText(v.CVE, naText, 22), gray
			case 5:
				if m.CWEID == "" {
					return naText, accent
				}
				return m.CWEID, accent
			default:
				if m.OWASP == "" {
					return naText, gray
				}
				return m.OWASP, gray
			}
		})

		// ─── VULNERABILITY DETAILS ─────────────────────────────
		newPage()
		pageHeader("Vulnerability Details", "Vulnerability Details", accent)

		type findSection struct {
			label, kind, content string
			code                 bool
		}

		for idx, v := range scan.Vulns {
			sc := sevColor(v.Severity)
			m := allMappings[idx]

			// Assemble the section list once so height can be
			// pre-computed before the card is drawn.
			var sections []findSection
			add := func(label, kind, content string, code bool) {
				if content != "" {
					sections = append(sections, findSection{label, kind, content, code})
				}
			}
			add("Endpoint", "link", v.Endpoint, true)
			add("Description", "doc", v.Description, false)
			add("Impact", "exclaim", v.Impact, false)
			add("Technical Analysis", "chip", v.TechnicalAnalysis, false)
			add("Proof of Concept", "search", v.PoCDescription, false)
			add("PoC Script", "terminal", v.PoCScript, true)
			add("Exploitation Proof", "target", v.ExploitationProof, true)
			add("Remediation", "check", v.Remediation, false)
			add("Suggested Fix", "check", v.Fix, false)

			// ── Pre-compute the header block height, plus each
			// section's own height, so the finding can be split across
			// page-chunk cards (mirroring paginatedRows/paginatedTable)
			// instead of ever falling back to an unboxed layout. ──
			headH := 11.0 // title + badge row
			if v.VerificationMethod != "" {
				headH += 5
			}
			if v.CVSS > 0 || v.CVE != "" || v.Method != "" {
				headH += 6
			}
			if m.CWEID != "" || m.OWASP != "" {
				headH += 6
			}
			headH += 4 // breathing room before first section

			secH := make([]float64, len(sections))
			codeBlocks := make([]string, len(sections))
			for i, sec := range sections {
				if sec.code {
					content := PrepareCodeBlock(sec.content, 34, 96)
					codeBlocks[i] = content
					lines := strings.Count(content, "\n") + 1
					h := float64(lines)*4 + 6
					if h < 15 {
						h = 15
					}
					if h > 120 {
						h = 120
					}
					secH[i] = 7 + h + 4 // kicker row + code block
				} else {
					pdf.SetFont("Helvetica", "", 9)
					wrapped := pdf.SplitLines([]byte(sec.content), textW-4)
					n := len(wrapped)
					if n < 1 {
						n = 1
					}
					secH[i] = 7 + float64(n)*5 + 4 // kicker row + prose
				}
			}

			// blockHeightOf returns the height of block bi: 0 is the
			// header, 1..len(sections) are the finding's sections.
			blockHeightOf := func(bi int) float64 {
				if bi == 0 {
					return headH
				}
				return secH[bi-1]
			}
			totalBlocks := 1 + len(sections)

			// Leave enough headroom that the header block always lands
			// fully on the page it starts on.
			if footY-pdf.GetY() < headH+10 {
				newPage()
			}

			bi := 0
			for bi < totalBlocks {
				chunkTop := pdf.GetY()
				used := 0.0
				chunkStart := bi
				for bi < totalBlocks {
					h := blockHeightOf(bi)
					if used > 0 && chunkTop+used+h > footY {
						break
					}
					used += h
					bi++
				}
				card(marginX, chunkTop, cardW, used, sc)

				cy := chunkTop + 4
				if chunkStart == 0 {
					hx := marginX + 4
					hy := chunkTop + 4
					pdf.SetXY(hx, hy)
					vulnTitle := fmt.Sprintf("#%d  %s", idx+1, v.Title)
					pdf.SetFont("Helvetica", "B", 11)
					maxTitleW := cardW - 8 - 30
					for len(vulnTitle) > 0 && pdf.GetStringWidth(vulnTitle) > maxTitleW {
						runes := []rune(vulnTitle)
						vulnTitle = string(runes[:len(runes)-1])
					}
					if len(vulnTitle) < len(fmt.Sprintf("#%d  %s", idx+1, v.Title)) {
						vulnTitle = strings.TrimSpace(vulnTitle) + "..."
					}
					setColor(white)
					pdf.CellFormat(maxTitleW, 7, vulnTitle, "", 0, "L", false, 0, "")

					pdf.SetFont("Helvetica", "B", 8)
					badgeW := 26.0
					drawRect(marginX+cardW-4-badgeW, hy-1, badgeW, 6, sc)
					pdf.SetXY(marginX+cardW-4-badgeW, hy-1)
					pdf.SetTextColor(255, 255, 255)
					pdf.CellFormat(badgeW, 6, strings.ToUpper(v.Severity), "", 0, "C", false, 0, "")

					cy = hy + 8
					hairline(marginX+4, cy, marginX+cardW-4, border)
					cy += 3

					if v.VerificationMethod != "" {
						pdf.SetXY(hx, cy)
						pdf.SetFont("Helvetica", "I", 7)
						if v.Verified {
							setColor(accent)
							pdf.CellFormat(cardW-8, 4.5, fmt.Sprintf("Verified via: %s", strings.ToUpper(v.VerificationMethod)), "", 1, "L", false, 0, "")
						} else {
							pdf.SetTextColor(200, 120, 0)
							pdf.CellFormat(cardW-8, 4.5, fmt.Sprintf("UNVERIFIED - manual review required (reported via %s)", strings.ToUpper(v.VerificationMethod)), "", 1, "L", false, 0, "")
						}
						cy += 5
					}

					if v.CVSS > 0 || v.CVE != "" || v.Method != "" {
						pdf.SetXY(hx, cy)
						if v.CVSS > 0 {
							setColor(gray)
							pdf.SetFont("Helvetica", "", 8)
							pdf.CellFormat(13, 5, "CVSS", "", 0, "L", false, 0, "")
							setColor(sc)
							pdf.SetFont("Helvetica", "B", 8)
							pdf.CellFormat(13, 5, fmt.Sprintf("%.1f", v.CVSS), "", 0, "L", false, 0, "")
							if v.CVSSVector != "" {
								setColor(gray)
								pdf.SetFont("Helvetica", "", 7)
								pdf.CellFormat(58, 5, v.CVSSVector, "", 0, "L", false, 0, "")
							}
						}
						if v.CVE != "" {
							setColor(gray)
							pdf.SetFont("Helvetica", "", 8)
							pdf.CellFormat(10, 5, "CVE", "", 0, "L", false, 0, "")
							setColor(white)
							pdf.CellFormat(45, 5, DisplayText(v.CVE, "", 40), "", 0, "L", false, 0, "")
						}
						if v.Method != "" {
							setColor(gray)
							pdf.SetFont("Helvetica", "", 8)
							pdf.CellFormat(16, 5, "Method", "", 0, "L", false, 0, "")
							setColor(white)
							pdf.CellFormat(20, 5, v.Method, "", 0, "L", false, 0, "")
						}
						cy += 6
					}

					if m.CWEID != "" || m.OWASP != "" {
						pdf.SetXY(hx, cy)
						if m.CWEID != "" {
							badgeW := pdf.GetStringWidth(m.CWEID) + 6
							pdf.SetFont("Helvetica", "B", 7)
							drawRect(pdf.GetX(), pdf.GetY(), badgeW, 5.5, palette.Muted)
							setColor(accent)
							pdf.CellFormat(badgeW, 5.5, m.CWEID, "", 0, "C", false, 0, "")
							if m.CWEName != "" {
								pdf.SetX(pdf.GetX() + 2)
								pdf.SetFont("Helvetica", "", 7)
								setColor(gray)
								nameStr := m.CWEName
								if nameRunes := []rune(nameStr); len(nameRunes) > 30 {
									nameStr = string(nameRunes[:27]) + "..."
								}
								pdf.CellFormat(62, 5.5, nameStr, "", 0, "L", false, 0, "")
							}
						}
						if m.OWASP != "" {
							owaspLabel := m.OWASP
							if m.OWASPName != "" {
								owaspLabel = m.OWASP + " - " + m.OWASPName
							}
							badgeW := pdf.GetStringWidth(owaspLabel) + 6
							pdf.SetFont("Helvetica", "B", 7)
							drawRect(pdf.GetX(), pdf.GetY(), badgeW, 5.5, palette.Muted)
							setColor(accent)
							pdf.CellFormat(badgeW, 5.5, owaspLabel, "", 0, "C", false, 0, "")
						}
						cy += 6
					}
					cy += 2
				}

				for i := chunkStart; i < bi; i++ {
					if i == 0 {
						continue // header block, already drawn above
					}
					sec := sections[i-1]
					sy := cy
					iconCircled(sec.kind, marginX+4+2.6, sy+2.6, 2.6, accent, accent)
					pdf.SetXY(marginX+11, sy)
					pdf.SetFont("Helvetica", "B", 8)
					setColor(accent)
					pdf.CellFormat(cardW-15, 5, strings.ToUpper(sec.label), "", 1, "L", false, 0, "")
					sy += 6

					if sec.code {
						content := codeBlocks[i-1]
						lines := strings.Count(content, "\n") + 1
						cbH := float64(lines)*4 + 6
						if cbH < 15 {
							cbH = 15
						}
						if cbH > 120 {
							cbH = 120
						}
						drawRect(marginX+8, sy, cardW-16, cbH, codeBg)
						pdf.SetXY(marginX+11, sy+3)
						pdf.SetFont("Courier", "", 7)
						if sec.label == "Exploitation Proof" {
							setColor([3]int{255, 200, 100})
						} else {
							setColor(gray)
						}
						pdf.MultiCell(cardW-22, 4, content, "", "L", false)
						cy = sy + cbH + 4
					} else {
						pdf.SetXY(marginX+8, sy)
						setColor(white)
						pdf.SetFont("Helvetica", "", 9)
						pdf.MultiCell(cardW-16, 5, sec.content, "", "L", false)
						cy = pdf.GetY() + 4
					}
				}

				pdf.SetY(chunkTop + used)
				if bi < totalBlocks {
					newPage()
				}
			}
			pdf.SetY(pdf.GetY() + 6)
		}
	}

	// ─── TESTED ENDPOINTS ─────────────────────────────────
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
								u := ExtractURL(word)
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
		newPage()
		pageHeader("Tested Endpoints & URLs", "Tested Endpoints", accent)

		displayEndpoints := endpoints
		more := 0
		if len(displayEndpoints) > 40 {
			more = len(displayEndpoints) - 40
			displayEndpoints = displayEndpoints[:40]
		}
		listCard("link", fmt.Sprintf("%d endpoints observed", len(endpoints)), displayEndpoints, 1, accent)
		if more > 0 {
			pdf.SetFont("Helvetica", "", 8.5)
			setColor(gray)
			pdf.SetX(marginX)
			pdf.CellFormat(cardW, 5, fmt.Sprintf("... and %d more endpoints", more), "", 1, "L", false, 0, "")
		}
	}

	// ─── DISCLAIMER ──────────────────────────────────────
	newPage()
	pageHeader("Disclaimer", "Legal", red)

	disclaimer := `This penetration test was conducted by Xalgorix, an autonomous AI-powered security assessment tool. The findings in this report are based on automated testing and manual verification where possible.

IMPORTANT NOTICES:

* Scope: This assessment was limited to the target systems explicitly listed in this report. Any systems or services outside the defined scope were not tested.

* False Positives: While Xalgorix attempts to verify findings before reporting, some findings may require manual validation. We recommend validating all critical and high-severity findings before taking remediation actions.

* Limitations: Automated testing cannot discover all vulnerabilities. Manual testing, code review, and other complementary security activities are recommended for comprehensive security coverage.

* Legal: This assessment was conducted with authorization from the target owner. Unauthorized security testing is illegal. Ensure you have proper authorization before testing any system.

* Report Accuracy: This report is provided "as is" without warranties of any kind. The testing methodology and findings are based on the tools and techniques available at the time of testing.

* Remediation: For any vulnerabilities found, follow industry best practices for remediation. Consult with security professionals for complex vulnerabilities.

Generated by Xalgorix - Autonomous AI Pentesting Engine
https://github.com/xalgorix/xalgorix`

	pdf.SetFont("Helvetica", "", 10)
	setColor(white)
	pdf.SetX(marginX)
	pdf.MultiCell(cardW, 5, disclaimer, "", "L", false)

	// ─── REFERENCE INDEX APPENDIX ──────────────────────────
	if len(scan.Vulns) > 0 {
		newPage()
		pageHeader("Reference Index", "Reference Index", accent)

		pdf.SetFont("Helvetica", "", 8)
		setColor(white)
		pdf.SetX(marginX)
		pdf.MultiCell(cardW, 4, "The mappings below are inferred from each finding's vulnerability class and are provided as a consolidated index for traceability and compliance reporting.", "", "L", false)
		pdf.Ln(5)

		headingWithIcon("chip", "CWE Reference Table", accent, 12)
		cweCols := []tableCol{
			{"Finding", 14, "L"},
			{"CWE", 20, "L"},
			{"CWE Name", 72, "L"},
			{"Finding Title", 72, "L"},
		}
		paginatedTable(accent, cweCols, len(scan.Vulns), func(row, col int) (string, [3]int) {
			v := scan.Vulns[row]
			m := allMappings[row]
			switch col {
			case 0:
				return fmt.Sprintf("F-%02d", row+1), gray
			case 1:
				if m.CWEID == "" {
					return naText, accent
				}
				return m.CWEID, accent
			case 2:
				if m.CWEName == "" {
					return naText, white
				}
				return DisplayText(m.CWEName, naText, 46), white
			default:
				return DisplayText(v.Title, "", 36), gray
			}
		})

		breakIfNeeded(210)
		headingWithIcon("shield", "OWASP Top 10 (2021) Coverage", accent, 12)
		owaspCols := []tableCol{
			{"ID", 16, "L"},
			{"OWASP Category", 108, "L"},
			{"Findings", 24, "C"},
			{"Status", 30, "C"},
		}
		paginatedTable(accent, owaspCols, len(OWASPCategories), func(row, col int) (string, [3]int) {
			cat := OWASPCategories[row]
			count := owaspCounts[cat.ID]
			has := count > 0
			switch col {
			case 0:
				if has {
					return cat.ID, accent
				}
				return cat.ID, gray
			case 1:
				if has {
					return cat.Name, white
				}
				return cat.Name, gray
			case 2:
				if has {
					return fmt.Sprintf("%d", count), red
				}
				return "0", gray
			default:
				if has {
					return "FOUND", red
				}
				return "CLEAR", accent
			}
		})

		if len(ptesCounts) > 0 {
			breakIfNeeded(220)
			headingWithIcon("target", "PTES Phase Mapping", accent, 12)
			ptesPhases := []string{
				"Intelligence Gathering",
				"Vulnerability Analysis",
				"Exploitation",
				"Post-Exploitation",
				"Reporting",
			}
			ptesCols := []tableCol{
				{"PTES Phase", 98, "L"},
				{"Findings", 34, "C"},
				{"Status", 46, "C"},
			}
			paginatedTable(accent, ptesCols, len(ptesPhases), func(row, col int) (string, [3]int) {
				phase := ptesPhases[row]
				count := ptesCounts[phase]
				has := count > 0
				switch col {
				case 0:
					if has {
						return phase, white
					}
					return phase, gray
				case 1:
					if has {
						return fmt.Sprintf("%d", count), accent
					}
					return "0", gray
				default:
					if has {
						return "TESTED", accent
					}
					return naText, gray
				}
			})
		}
	}

	// Save PDF — use ScanDir which is the actual scan directory.
	// Mirrors the previous (*Server).generateReport behavior exactly:
	// reportID falls back to filepath.Base(ScanDir) and finally to "scan",
	// and the file is written to ScanDir when set, FallbackDir otherwise.
	reportID := scan.ID
	if strings.TrimSpace(reportID) == "" && opts.ScanDir != "" {
		reportID = filepath.Base(opts.ScanDir)
	}
	if strings.TrimSpace(reportID) == "" {
		reportID = "scan"
	}
	filename := fmt.Sprintf("xalgorix_report_%s.pdf", reportID)
	outPath := filepath.Join(opts.ScanDir, filename)
	if opts.ScanDir == "" {
		outPath = filepath.Join(opts.FallbackDir, filename)
	}
	if err := pdf.OutputFileAndClose(outPath); err != nil {
		return "", fmt.Errorf("failed to generate PDF: %w", err)
	}

	return outPath, nil
}
