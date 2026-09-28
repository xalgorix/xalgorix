// Package agent — surface.go introduces the typed, machine-readable attack
// surface the planner and applicability logic consume. The "Endpoint
// Inventory" note remains the human/model-facing mirror; this store adds what
// prose cannot carry reliably: per-endpoint method, parameters, content types,
// and derived features (graphql, websocket, upload, workflow, xml, …).
//
// Applicability replaces the old "every required class against every
// discovered endpoint" completion floor: a coverage gap now exists only for
// (class, endpoint) pairs the OBSERVED surface says are testable — /robots.txt
// is no longer demanded through XXE/SSTI/CSRF, while a state-changing
// /api/checkout automatically carries business-logic and race-condition
// obligations. Rules are generic (method + parameters + content type + path
// semantics), never target-specific.
package agent

import (
	"regexp"
	"sort"
	"strings"
)

// SeededSurfaceEndpoint is one endpoint from an operator-supplied artifact
// (OpenAPI/Swagger, HAR, Postman) — the richest per-endpoint metadata source.
type SeededSurfaceEndpoint struct {
	Path   string
	Method string
	Params []string
	Source string
}

// SurfaceParameter is one observed input location on an endpoint.
type SurfaceParameter struct {
	Name     string
	Location string // query | body | header | path | unknown
}

// SurfaceEndpoint is the typed per-endpoint record. It is derived from
// evidence (seeded artifacts, observed requests, the notes inventory) and
// never invented: an unknown method stays "".
type SurfaceEndpoint struct {
	Endpoint     string // coverage-matrix alias (host+path or path)
	Path         string
	Method       string // GET/POST/PUT/PATCH/DELETE; "" unknown
	ContentTypes []string
	Parameters   []SurfaceParameter
	Features     []string // graphql, websocket, upload, workflow, xml, json, object-scoped, static-asset, auth-surface, admin-surface, jwt
	Source       string
}

// HasFeature reports whether the endpoint carries a derived feature.
func (se *SurfaceEndpoint) HasFeature(f string) bool {
	for _, x := range se.Features {
		if x == f {
			return true
		}
	}
	return false
}

// stateChanging reports whether the method mutates state.
func (se *SurfaceEndpoint) stateChanging() bool {
	switch strings.ToUpper(se.Method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// ── Feature detection (path/param/content-type evidence only) ────────────────

var staticAssetExts = []string{".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"}
var staticAssetPaths = []string{"/robots.txt", "/sitemap.xml", "/favicon", "/.well-known/", "/static/", "/assets/", "/vendor/"}

func isStaticAssetPath(path string) bool {
	lp := strings.ToLower(path)
	for _, p := range staticAssetPaths {
		if strings.HasPrefix(lp, p) || strings.Contains(lp, p) {
			return true
		}
	}
	for _, ext := range staticAssetExts {
		if strings.HasSuffix(lp, ext) {
			return true
		}
	}
	return false
}

func isGraphQLPath(path string) bool {
	return strings.Contains(strings.ToLower(path), "graphql")
}

func isWebSocketPath(path string) bool {
	lp := strings.ToLower(path)
	return strings.HasPrefix(lp, "/ws") || strings.Contains(lp, "/websocket") || strings.Contains(lp, "/socket")
}

var uploadPathKeywords = []string{"upload", "import", "attach", "avatar", "media", "photo", "image", "document", "file"}

func isUploadPath(path string) bool {
	lp := strings.ToLower(path)
	for _, k := range uploadPathKeywords {
		if strings.Contains(lp, k) {
			return true
		}
	}
	return false
}

var authPathKeywords = []string{"login", "signin", "sign-in", "signup", "sign-up", "register", "auth", "token", "session", "password", "logout", "mfa", "otp", "oauth", "sso"}
var adminPathKeywords = []string{"admin", "dashboard", "console", "internal", "management"}
var workflowPathKeywords = []string{"checkout", "order", "cart", "payment", "pay", "coupon", "promo", "booking", "reservation", "ticket", "vote", "transfer", "withdraw", "refund", "invoice", "subscription", "subscribe", "redeem", "referral", "balance", "checkout"}

func containsAnyKeyword(s string, keywords []string) bool {
	ls := strings.ToLower(s)
	for _, k := range keywords {
		if strings.Contains(ls, k) {
			return true
		}
	}
	return false
}

// isObjectScopedPath reports a path whose final segments reference a concrete
// object (id, uuid, number) — the classic BOLA/IDOR surface.
func isObjectScopedPath(path string) bool {
	segs := strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
	if len(segs) == 0 {
		return false
	}
	last := strings.ToLower(segs[len(segs)-1])
	if last == "" {
		return false
	}
	if strings.Contains(last, "{") || strings.Contains(last, "<") {
		return true // route template: /api/users/{id}
	}
	// pure number or uuid-like token
	isNum := last != "" && strings.Trim(last, "0123456789") == ""
	if isNum {
		return true
	}
	if len(last) >= 8 {
		hexish := strings.Trim(last, "0123456789abcdefABCDEF-")
		if len(hexish) <= 1 && strings.Count(last, "-") >= 2 {
			return true // uuid-like
		}
	}
	return false
}

var idLikeParams = []string{"id", "uid", "user_id", "userid", "order_id", "orderid", "account", "account_id", "customer", "customer_id", "owner", "owner_id", "doc", "doc_id", "file", "file_id", "uuid", "ref", "reference"}
var fileishParams = []string{"file", "path", "filename", "filepath", "template", "tpl", "page", "doc", "document", "download", "view", "include", "load", "lang", "theme", "name", "resource"}
var urlishParams = []string{"url", "uri", "link", "next", "redirect", "redirect_uri", "callback", "webhook", "host", "domain", "site", "fetch", "dest", "target", "return", "return_url", "continue"}
var roleParams = []string{"role", "roles", "isadmin", "admin", "is_admin", "privilege", "permissions", "scopes", "scope", "user_type", "usertype", "account_type"}

func hasParamLike(params []string, candidates []string) bool {
	for _, p := range params {
		lp := strings.ToLower(p)
		for _, c := range candidates {
			if lp == c {
				return true
			}
		}
	}
	return false
}

// ── Surface construction ──────────────────────────────────────────────────────

// buildSurfaceEndpoint derives the typed record for one discovered endpoint
// from every evidence source the state holds.
func buildSurfaceEndpoint(state *ScanState, endpoint string) *SurfaceEndpoint {
	se := &SurfaceEndpoint{Endpoint: endpoint, Source: "notes"}
	// Split host/path like the coverage aliases.
	value := strings.TrimSpace(endpoint)
	path := value
	if parsed, ok := parseSurfacePath(value); ok {
		path = parsed
	}
	se.Path = path

	// Seed artifact metadata (richest source).
	for _, s := range state.SeededSurface {
		if samePath(s.Path, path) || samePath(s.Path, value) {
			if m := strings.ToUpper(strings.TrimSpace(s.Method)); m != "" {
				se.Method = m
			}
			for _, p := range s.Params {
				se.Parameters = append(se.Parameters, SurfaceParameter{Name: p, Location: "unknown"})
			}
			se.Source = "context"
		}
	}
	// Observed method from real requests.
	if m, ok := state.ObservedEndpointMethods[endpoint]; ok && se.Method == "" {
		se.Method = strings.ToUpper(m)
	}
	// Content types observed for this endpoint.
	if cts, ok := state.EndpointContentTypes[endpoint]; ok && cts != "" {
		se.ContentTypes = strings.FieldsFunc(cts, func(r rune) bool { return r == ',' || r == ';' || r == ' ' })
	}

	se.Features = deriveEndpointFeatures(se, state)
	return se
}

func deriveEndpointFeatures(se *SurfaceEndpoint, state *ScanState) []string {
	features := []string{}
	path := se.Path
	if isStaticAssetPath(path) {
		features = append(features, "static-asset")
	}
	if isGraphQLPath(path) {
		features = append(features, "graphql")
	}
	if isWebSocketPath(path) {
		features = append(features, "websocket")
	}
	if isUploadPath(path) {
		features = append(features, "upload")
	}
	if containsAnyKeyword(path, authPathKeywords) {
		features = append(features, "auth-surface")
	}
	if containsAnyKeyword(path, adminPathKeywords) {
		features = append(features, "admin-surface")
	}
	if containsAnyKeyword(path, workflowPathKeywords) {
		features = append(features, "workflow")
	}
	if isObjectScopedPath(path) {
		features = append(features, "object-scoped")
	}
	for _, ct := range se.ContentTypes {
		lct := strings.ToLower(ct)
		switch {
		case strings.Contains(lct, "xml"):
			features = append(features, "xml")
		case strings.Contains(lct, "json"):
			features = append(features, "json")
		case strings.Contains(lct, "multipart"):
			features = append(features, "multipart")
		}
	}
	var paramNames []string
	for _, p := range se.Parameters {
		paramNames = append(paramNames, p.Name)
	}
	if hasParamLike(paramNames, roleParams) {
		features = append(features, "role-param")
	}
	if hasParamLike(paramNames, idLikeParams) {
		features = append(features, "object-scoped")
	}
	if hasParamLike(paramNames, fileishParams) {
		features = append(features, "file-param")
	}
	if hasParamLike(paramNames, urlishParams) {
		features = append(features, "url-param")
	}
	if len(se.Parameters) > 0 {
		features = append(features, "parameterized")
	}
	// Global tech signals apply to every endpoint conservatively.
	if state != nil && state.DetectedTechs["graphql"] && isGraphQLPath(path) {
		// already covered
		_ = se
	}
	return dedupeStrings(features)
}

// parseSurfacePath extracts the path portion of a URL-ish endpoint string.
func parseSurfacePath(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if cut := strings.Index(value, "://"); cut > 0 {
			rest := value[cut+3:]
			if slash := strings.Index(rest, "/"); slash >= 0 {
				return rest[slash:], true
			}
			return "/", true
		}
	}
	if strings.HasPrefix(value, "/") {
		return value, true
	}
	if slash := strings.Index(value, "/"); slash > 0 {
		return value[slash:], true
	}
	return "", false
}

func samePath(a, b string) bool {
	return normalizeCoveragePath(strings.ToLower(strings.TrimSpace(a))) == normalizeCoveragePath(strings.ToLower(strings.TrimSpace(b)))
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ApplicableClassesForEndpoint returns the canonical vulnerability classes the
// OBSERVED surface makes testable on this endpoint. Evidence-lean endpoints
// (a bare path from the notes inventory) conservatively keep the full
// baseline-class floor, except static assets which are discovery-only.
func ApplicableClassesForEndpoint(state *ScanState, endpoint string) []string {
	se := buildSurfaceEndpoint(state, endpoint)
	return se.ApplicableClasses()
}

// ApplicableClasses computes the applicable class set from typed evidence.
//
// Compatibility contract: with no method/content/param evidence beyond the
// path, every baseline class applies (matching historical behavior) unless
// the path is a static asset, which drops to discovery-only.
func (se *SurfaceEndpoint) ApplicableClasses() []string {
	classes := make(map[string]bool)
	add := func(ids ...string) {
		for _, id := range ids {
			if CanonicalVulnClassID(id) != "" || id == "information-exposure" {
				classes[id] = true
			}
		}
	}

	if se.HasFeature("static-asset") {
		// Discovery-only: content discovery covers it; no injection/authz
		// obligation exists for robots.txt or an asset path.
		return []string{"information-exposure"}
	}

	structured := se.Method != "" || len(se.Parameters) > 0 || len(se.ContentTypes) > 0

	// Surface-specific lanes first.
	if se.HasFeature("graphql") {
		add("idor", "business-logic", "race-conditions", "sqli", "graphql", "authorization")
	}
	if se.HasFeature("websocket") {
		add("auth", "idor", "sqli", "xss", "race-conditions", "websocket")
	}
	if se.HasFeature("upload") || se.HasFeature("multipart") {
		add("file-upload", "xss", "path_traversal", "idor")
	}
	if se.HasFeature("xml") {
		add("xxe", "sqli")
	}
	if se.HasFeature("auth-surface") {
		add("auth", "auth-bypass")
	}
	if se.HasFeature("admin-surface") {
		add("idor", "privilege-escalation", "auth-bypass")
	}
	if se.HasFeature("workflow") {
		add("business-logic", "race-conditions")
	}
	if se.HasFeature("object-scoped") {
		add("idor")
	}
	if se.HasFeature("role-param") {
		add("privilege-escalation", "mass-assignment")
	}
	if se.HasFeature("url-param") {
		add("ssrf", "open-redirect")
	}
	if se.HasFeature("file-param") {
		add("path_traversal")
	}
	if se.HasFeature("json") {
		add("nosqli", "sqli")
	}

	// Generic input classes for any parameterized endpoint.
	if se.HasFeature("parameterized") || (se.Method != "" && se.Method != "GET" && se.Method != "HEAD") {
		add("sqli", "xss", "parameter_mining")
	}
	// State-changing obligations.
	if se.stateChanging() {
		add("csrf", "idor", "business-logic", "race-conditions")
		if strings.EqualFold(se.Method, "PUT") || strings.EqualFold(se.Method, "PATCH") {
			add("mass-assignment")
		}
	}
	if strings.EqualFold(se.Method, "GET") && se.HasFeature("parameterized") {
		add("sqli", "xss", "parameter_mining", "ssrf")
	}

	if structured {
		// Only keep classes that are applicable by evidence, but never drop
		// below the baseline for endpoints we may under-observe: baseline
		// classes stay applicable when the endpoint carries parameters or a
		// state-changing method, which the rules above already added.
	} else {
		// No structured evidence beyond the path: keep the historical
		// baseline floor so a notes-only inventory never silently loses class
		// obligations.
		for _, c := range requiredCoverageClasses() {
			classes[c] = true
		}
	}

	out := make([]string, 0, len(classes))
	for c := range classes {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// classAppliesToEndpoint answers whether a (class, endpoint) pair is an
// applicable coverage obligation. Unknown classes conservatively apply.
func classAppliesToEndpoint(state *ScanState, endpoint, class string) bool {
	classID := CanonicalVulnClassID(class)
	if classID == "" {
		return true // unknown class: never silently drop obligations
	}
	for _, c := range ApplicableClassesForEndpoint(state, endpoint) {
		if c == classID {
			return true
		}
	}
	return false
}

// ApplicableEndpointsForClass returns the discovered endpoints where a class
// is applicable (bounded, deterministic order).
func ApplicableEndpointsForClass(state *ScanState, class string) []string {
	if state == nil {
		return nil
	}
	var out []string
	for _, ep := range state.DiscoveredEndpoints {
		if classAppliesToEndpoint(state, ep, class) {
			out = append(out, ep)
		}
	}
	sort.Strings(out)
	return out
}

// ── Observation recording ─────────────────────────────────────────────────────

// curlMethodRe matches curl's explicit method flag.
var curlMethodRe = regexp.MustCompile(`(?i)(?:-X\s*|--request[= ]\s*)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b`)

// methodFromCurlCmd extracts the HTTP method a command uses. -X/--request is
// authoritative; --data/-d/--json imply POST; -T implies PUT; a bare curl is
// a GET.
func methodFromCurlCmd(cmd string) string {
	if m := curlMethodRe.FindStringSubmatch(cmd); m != nil {
		return strings.ToUpper(m[1])
	}
	lc := strings.ToLower(cmd)
	if strings.Contains(lc, "--data") || strings.Contains(lc, " -d") || strings.Contains(lc, "--json") {
		return "POST"
	}
	if strings.Contains(lc, " -t ") || strings.Contains(lc, "--upload-file") {
		return "PUT"
	}
	if strings.Contains(lc, "curl") {
		return "GET"
	}
	return ""
}

// contentTypeHdrRe matches a Content-Type header value in a command or headers
// argument.
var contentTypeHdrRe = regexp.MustCompile(`(?i)content-type["']?\s*[:=]\s*["']?([a-z0-9/+.-]+)`)

func contentTypeFromCmd(cmd string) string {
	if m := contentTypeHdrRe.FindStringSubmatch(cmd); m != nil {
		return strings.ToLower(m[1])
	}
	return ""
}

// recordEndpointMethod stores the observed method for an endpoint. A
// state-changing observation is never downgraded by a later GET (same route
// observed both ways); GET never overwrites a known mutating method.
func recordEndpointMethod(state *ScanState, endpoint, method string) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if state == nil || endpoint == "" || method == "" {
		return
	}
	if state.ObservedEndpointMethods == nil {
		state.ObservedEndpointMethods = make(map[string]string)
	}
	switch state.ObservedEndpointMethods[endpoint] {
	case "POST", "PUT", "PATCH", "DELETE":
		if method == "GET" || method == "HEAD" {
			return
		}
	}
	if state.ObservedEndpointMethods[endpoint] == "" {
		state.ObservedEndpointMethods[endpoint] = method
	}
}

func recordEndpointContentType(state *ScanState, endpoint, contentType string) {
	contentType = strings.TrimSpace(strings.ToLower(contentType))
	if state == nil || endpoint == "" || contentType == "" {
		return
	}
	if state.EndpointContentTypes == nil {
		state.EndpointContentTypes = make(map[string]string)
	}
	existing := state.EndpointContentTypes[endpoint]
	if !strings.Contains(existing, contentType) {
		if existing == "" {
			state.EndpointContentTypes[endpoint] = contentType
		} else {
			state.EndpointContentTypes[endpoint] = existing + "," + contentType
		}
	}
}
