package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/safe"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

// notifyHTTPTimeout bounds every outbound notification request so a slow or
// unresponsive endpoint never pins a goroutine.
const notifyHTTPTimeout = 30 * time.Second

var (
	errWebhookURL = errors.New("discord_webhook must be an absolute http(s) URL")
	// errWebhookDestination is returned for a per-scan webhook that points at
	// this machine, the dashboard listener, or a link-local / cloud-metadata
	// address. Scan targets get the same self-scan protection (scopeguard);
	// notifications must not become a way around it.
	errWebhookDestination = errors.New("discord_webhook must not point at this machine, the dashboard listener, or a link-local/metadata address")

	// cloudMetadataIPs are instance-metadata / host-agent addresses that sit
	// outside the link-local range, so the range checks below miss them.
	cloudMetadataIPs = []net.IP{
		net.ParseIP("fd00:ec2::254"),
		net.ParseIP("fd20:ce::254"),
		net.ParseIP("100.100.100.200"),
		net.ParseIP("168.63.129.16"),
	}

	// numericHostRe matches host names made only of decimal or 0x-hex
	// numbers ("2130706433", "0x7f.1", "127.1", "0"). net.ParseIP rejects
	// them, but some resolvers and proxies read them as IPv4 addresses.
	numericHostRe = regexp.MustCompile(`(?i)^(0x[0-9a-f]*|[0-9]+)(\.(0x[0-9a-f]*|[0-9]+)){0,3}$`)
)

// webhookIPBlocked reports address classes no notification webhook has a
// legitimate reason to reach, independent of the scope-guard configuration:
// unspecified, link-local (which includes the 169.254.169.254 metadata
// service), multicast, IPv4-compatible IPv6 (::a.b.c.d, which some stacks
// route to the embedded IPv4 address), and the known metadata addresses
// outside link-local.
func webhookIPBlocked(ip net.IP) bool {
	if ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	if ip.To4() == nil && len(ip) == net.IPv6len && !ip.IsLoopback() && bytes.Equal(ip[:12], make([]byte, 12)) {
		return true
	}
	for _, m := range cloudMetadataIPs {
		if ip.Equal(m) {
			return true
		}
	}
	return false
}

// isOperatorWebhook reports whether webhook is the operator-configured global
// endpoint (XALGORIX_DISCORD_WEBHOOK / settings). Only the operator can set
// that value, so it is trusted as-is; every other webhook arrives with a scan
// or schedule request and is guarded.
func (s *Server) isOperatorWebhook(webhook string) bool {
	global := strings.TrimSpace(s.discordWebhook)
	return global != "" && strings.TrimSpace(webhook) == global
}

// validateScanWebhook checks a per-scan or per-schedule webhook URL supplied
// by an API caller before it is stored. Empty means "use the global default".
// RFC1918 hosts stay allowed (a LAN relay is legitimate and scan targets may
// be private too); this machine's own addresses follow the same
// AllowLocalTargets opt-in as scan targets, and the dashboard listener is
// never reachable. The dial-time guard in notificationClient enforces the same
// rules against the address actually connected to, which covers DNS answers
// that change after this check.
func (s *Server) validateScanWebhook(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" || s.isOperatorWebhook(raw) {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return errWebhookURL
	}
	// A trailing dot ("169.254.169.254.") still names the same host, and a
	// zone ("fe80::1%eth0") or a non-canonical numeric form can reach a
	// blocked address without parsing as an IP here. When an egress proxy
	// applies, this check is the only one, so refuse those forms outright.
	host := strings.TrimSuffix(u.Hostname(), ".")
	if strings.Contains(host, "%") || (net.ParseIP(host) == nil && numericHostRe.MatchString(host)) {
		return errWebhookDestination
	}
	if ip := net.ParseIP(host); ip != nil {
		if webhookIPBlocked(ip) {
			return errWebhookDestination
		}
	} else if addrs, err := scopeguard.LookupHost(host); err == nil {
		// A name that resolves to a link-local/metadata address is refused
		// up front too: when an egress proxy applies, the dial guard below
		// never sees the destination address.
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && webhookIPBlocked(ip) {
				return errWebhookDestination
			}
		}
	}
	if s.isBlockedTarget(raw) {
		return errWebhookDestination
	}
	return nil
}

// webhookDialGuard is a net.Dialer Control hook: it runs after DNS resolution,
// against the exact IP being connected to, so a hostname that re-resolves to
// a blocked address between validation and delivery is still refused.
func (s *Server) webhookDialGuard(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errWebhookDestination
	}
	ip := net.ParseIP(host)
	if ip == nil || webhookIPBlocked(ip) || s.isBlockedTarget(address) {
		return errWebhookDestination
	}
	return nil
}

// notificationClient returns the HTTP client used to deliver a Discord
// notification to webhook. The operator's global webhook keeps a plain client.
// Any other (caller-supplied) webhook gets a client that checks every
// connection with webhookDialGuard and does not follow redirects, so neither
// a redirect nor a re-resolving hostname can steer the POST somewhere the
// request-time validation would have refused. When an egress proxy from the
// environment applies, the proxy resolves and connects to the destination, so
// only the request-time validation applies (no dial-time re-check).
//
// Whether a webhook is the operator's is decided at send time: if the global
// webhook changes mid-scan, a scan still holding the old value is treated as
// caller-supplied from then on.
func (s *Server) notificationClient(webhook string) *http.Client {
	if s.isOperatorWebhook(webhook) {
		return &http.Client{Timeout: notifyHTTPTimeout}
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		base = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	tr := base.Clone()
	tr.DisableKeepAlives = true
	proxied := false
	if u, err := url.Parse(webhook); err == nil && tr.Proxy != nil {
		if p, perr := tr.Proxy(&http.Request{URL: u}); perr == nil && p != nil {
			proxied = true
		}
	}
	if !proxied {
		d := &net.Dialer{Timeout: notifyHTTPTimeout, KeepAlive: 30 * time.Second, Control: s.webhookDialGuard}
		tr.DialContext = d.DialContext
	}
	return &http.Client{
		Timeout:   notifyHTTPTimeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// The finding notification body is authored once in Discord Markdown
// (**bold**, `code`, ```fenced```) and reused for Telegram. Telegram's HTML
// parse_mode doesn't understand Markdown, so these convert the Discord markers
// to Telegram HTML tags. Fenced blocks are matched before inline code so a
// ``` block isn't chopped up by the single-backtick rule.
var (
	tgFencedCodeRe = regexp.MustCompile("(?s)```[a-zA-Z0-9_-]*\\n?(.*?)```")
	tgInlineCodeRe = regexp.MustCompile("`([^`\n]+?)`")
	tgBoldRe       = regexp.MustCompile(`\*\*([^*]+?)\*\*`)
)

func (s *Server) discordWebhookForScan(webhook string) string {
	if webhook = strings.TrimSpace(webhook); webhook != "" {
		return webhook
	}
	return s.discordWebhook
}

// sendDiscord sends a rich embed message to the configured Discord webhook.
func (s *Server) sendDiscord(color int, title, description string) {
	s.sendDiscordTo(s.discordWebhook, color, title, description)
}

func (s *Server) sendDiscordTo(webhook string, color int, title, description string) {
	s.sendDiscordWithFileTo(webhook, color, title, description, "")
}

// sendDiscordWithFile sends to the global endpoint for legacy callers.
func (s *Server) sendDiscordWithFile(color int, title, description, filePath string) {
	s.sendDiscordWithFileTo(s.discordWebhook, color, title, description, filePath)
}

// sendDiscordWithFileTo captures an immutable per-scan endpoint before the
// asynchronous send. Concurrent scans can never overwrite each other's URL.
func (s *Server) sendDiscordWithFileTo(webhook string, color int, title, description, filePath string) {
	if webhook == "" {
		return
	}

	// If no file, send simple embed
	if filePath == "" {
		s.sendSimpleEmbedTo(webhook, color, title, description)
		return
	}

	// Check if file exists
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Failed to read PDF for Discord: %v", err)
		// Send embed without file
		s.sendSimpleEmbedTo(webhook, color, title, description+" (PDF generation failed)")
		return
	}

	// Create multipart form data
	var b bytes.Buffer
	writer := multipart.NewWriter(&b)

	// Add payload JSON
	embedPayload := map[string]any{
		"username":   "Xalgorix",
		"avatar_url": "https://raw.githubusercontent.com/xalgord/xalgord/main/assets/logo.png",
		"embeds": []map[string]any{
			{
				"title":       title,
				"description": description,
				"color":       color,
				"timestamp":   time.Now().Format(time.RFC3339),
				"footer": map[string]string{
					"text": "Xalgorix — Autonomous AI Pentesting Engine",
				},
			},
		},
	}
	embedJSON, err := json.Marshal(embedPayload)
	if err != nil {
		log.Printf("Error: failed to marshal Discord embed payload: %v", err)
		return
	}
	if err := writer.WriteField("payload_json", string(embedJSON)); err != nil {
		log.Printf("Error: failed to write Discord payload field: %v", err)
		return
	}

	// Add file
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		log.Printf("Error: failed to create form file for Discord: %v", err)
		return
	}
	if _, err := part.Write(fileData); err != nil {
		log.Printf("Error: failed to write file data for Discord: %v", err)
		return
	}
	_ = writer.Close()

	// Capture content type before goroutine to avoid fragile writer capture
	contentType := writer.FormDataContentType()
	client := s.notificationClient(webhook)

	// Send request
	go func() {
		resp, err := client.Post(webhook, contentType, &b)
		if err != nil {
			log.Printf("Discord webhook file upload error: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 && resp.StatusCode != 204 {
			respBody, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				log.Printf("Warning: failed to read Discord error response: %v", readErr)
			}
			log.Printf("Discord webhook error: %d %s", resp.StatusCode, string(respBody))
		}
	}()
}

func (s *Server) sendSimpleEmbedTo(webhook string, color int, title, description string) {
	if webhook == "" {
		return
	}
	payload := map[string]any{
		"username":   "Xalgorix",
		"avatar_url": "https://raw.githubusercontent.com/xalgord/xalgord/main/assets/logo.png",
		"embeds": []map[string]any{
			{
				"title":       title,
				"description": description,
				"color":       color,
				"timestamp":   time.Now().Format(time.RFC3339),
				"footer": map[string]string{
					"text": "Xalgorix — Autonomous AI Pentesting Engine",
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	client := s.notificationClient(webhook)
	go func() {
		// The destination is the configured notification endpoint; for a
		// caller-supplied webhook, notificationClient refuses this machine,
		// the dashboard listener, link-local/metadata addresses and redirects.
		resp, err := client.Post(webhook, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("Discord webhook error: %v", err)
			return
		}
		resp.Body.Close()
	}()
}

// isBlockedTarget delegates to scopeguard.IsLocalOrListener, the
// authoritative classifier for Local_Or_Listener_Host shared by the
// web fetcher and the agent-side gate. Verdict for every target is
// identical to the pre-relocation in-package implementation; the
// shared package preserves the single-DNS-lookup-per-call contract
// (Requirement 3.8 / design.md → "DNS Lookup Semantics").
func (s *Server) isBlockedTarget(target string) bool {
	return scopeguard.IsLocalOrListener(scopeguard.Config{
		BindAddr:          s.cfg.BindAddr,
		Port:              s.port,
		AllowLocalTargets: s.cfg.AllowLocalTargets,
	}, target)
}

// severityMeetsThreshold returns true if the vuln severity is at or above the minimum
// threshold. Empty threshold means "send everything".
// Severity hierarchy: info < low < medium < high < critical
func severityMeetsThreshold(severity, minSeverity string) bool {
	if minSeverity == "" {
		return true // no threshold = send all
	}
	order := map[string]int{
		"info":     0,
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}
	vulnLevel, ok1 := order[strings.ToLower(severity)]
	minLevel, ok2 := order[strings.ToLower(minSeverity)]
	if !ok1 || !ok2 {
		return true // unknown severity = send it
	}
	return vulnLevel >= minLevel
}

// telegramAPIBase is the fixed Telegram Bot API host. Pinned (not
// operator-configurable) so an attacker-influenced base URL cannot
// create an SSRF surface — the destination is always api.telegram.org
// over HTTPS, matching the security model described in issue #157.
// Declared as a var (not const) solely so tests can point it at a
// local httptest.Server stub; production code never reassigns it.
var telegramAPIBase = "https://api.telegram.org"

// telegramConfigured reports whether Telegram notifications are
// enabled (a bot token AND a chat ID are both set). Used by the
// status/scan endpoints to surface a telegram_configured boolean
// without exposing the token itself.
func (s *Server) telegramConfigured() bool {
	return s.telegramBotToken != "" && s.telegramChatID != ""
}

// telegramFormat builds an HTML-formatted message body from a
// (title, description) pair, mirroring the (color, title, description)
// shape Discord consumes. Telegram has no embed/color concept, so the
// color is ignored; we emit a bold title followed by the description.
// HTML parse_mode is used (rather than MarkdownV2) to avoid
// Markdown-escaping pitfalls noted in issue #157.
func telegramFormat(title, description string) string {
	title = strings.TrimSpace(title)
	description = strings.TrimSpace(description)
	if title == "" {
		return description
	}
	if description == "" {
		return "<b>" + htmlEscape(title) + "</b>"
	}
	return "<b>" + htmlEscape(title) + "</b>\n" + discordMarkdownToTelegramHTML(description)
}

// discordMarkdownToTelegramHTML converts the Discord-flavored Markdown used in
// notification bodies (**bold**, `inline code`, ```fenced blocks```) into the
// subset of HTML Telegram's HTML parse_mode supports (<b>, <code>, <pre>).
// Text is HTML-escaped FIRST so finding content can't inject markup; the
// Markdown markers (*, `) are not HTML-special, so escaping never disturbs
// them. Without this, Telegram renders the raw "**", "`" characters literally.
func discordMarkdownToTelegramHTML(s string) string {
	s = htmlEscape(s)
	// Fenced code first (so its contents aren't mangled by the inline rule).
	s = tgFencedCodeRe.ReplaceAllString(s, "<pre>$1</pre>")
	s = tgInlineCodeRe.ReplaceAllString(s, "<code>$1</code>")
	s = tgBoldRe.ReplaceAllString(s, "<b>$1</b>")
	return s
}

// htmlEscape escapes the four characters Telegram's HTML parse_mode
// treats specially (& < >), so operator/finding text cannot break out
// of the message body or inject markup.
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// sendTelegram sends a text notification to the configured Telegram
// chat. It is the Telegram counterpart of sendDiscord. Fire-and-forget
// in a goroutine with a 30s timeout, identical to sendSimpleEmbed; a
// slow or blocked Telegram endpoint never stalls a scan. The color
// argument is accepted for signature symmetry with sendDiscord but is
// ignored (Telegram has no color concept).
//
// Early-returns when Telegram is not configured (no bot token or no
// chat ID) so an unconfigured instance makes zero outbound requests.
func (s *Server) sendTelegram(color int, title, description string) {
	s.sendTelegramWithFile(color, title, description, "")
}

// sendTelegramWithFile sends a text notification with an optional file
// attachment (the PDF report) to the configured Telegram chat. It is the
// Telegram counterpart of sendDiscordWithFile. When filePath is empty it
// sends a plain sendMessage; otherwise it sends a sendDocument
// (multipart/form-data) with the file attached and a caption.
//
// Telegram returns HTTP 200 with {"ok": false, ...} on logical errors
// (bad chat ID, bot not in channel, etc.), so in addition to non-2xx
// status codes we log when the response body indicates ok:false.
func (s *Server) sendTelegramWithFile(color int, title, description, filePath string) {
	if !s.telegramConfigured() {
		return
	}

	text := telegramFormat(title, description)

	if filePath == "" {
		// Plain text message via sendMessage.
		payload := url.Values{
			"chat_id":                  {s.telegramChatID},
			"text":                     {text},
			"parse_mode":               {"HTML"},
			"disable_web_page_preview": {"true"},
		}
		endpoint := telegramAPIBase + "/bot" + s.telegramBotToken + "/sendMessage"

		go func() {
			defer safe.Recover("telegram.sendMessage", "")
			client := &http.Client{Timeout: 30 * time.Second}
			resp, err := client.PostForm(endpoint, payload)
			if err != nil {
				log.Printf("Telegram sendMessage error: %v", err)
				return
			}
			defer resp.Body.Close()
			s.logTelegramResponse(resp)
		}()
		return
	}

	// Message + file via sendDocument (multipart/form-data).
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Failed to read file for Telegram: %v", err)
		// Fall back to a plain text message noting the attachment failed.
		s.sendTelegram(color, title, description+" (report delivery failed)")
		return
	}

	var b bytes.Buffer
	writer := multipart.NewWriter(&b)
	if err := writer.WriteField("chat_id", s.telegramChatID); err != nil {
		log.Printf("Error: failed to write Telegram chat_id field: %v", err)
		return
	}
	if err := writer.WriteField("caption", text); err != nil {
		log.Printf("Error: failed to write Telegram caption field: %v", err)
		return
	}
	if err := writer.WriteField("parse_mode", "HTML"); err != nil {
		log.Printf("Error: failed to write Telegram parse_mode field: %v", err)
		return
	}
	part, err := writer.CreateFormFile("document", filepath.Base(filePath))
	if err != nil {
		log.Printf("Error: failed to create form file for Telegram: %v", err)
		return
	}
	if _, err := part.Write(fileData); err != nil {
		log.Printf("Error: failed to write file data for Telegram: %v", err)
		return
	}
	_ = writer.Close()
	contentType := writer.FormDataContentType()

	endpoint := telegramAPIBase + "/bot" + s.telegramBotToken + "/sendDocument"
	go func() {
		defer safe.Recover("telegram.sendDocument", "")
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Post(endpoint, contentType, &b)
		if err != nil {
			log.Printf("Telegram sendDocument error: %v", err)
			return
		}
		defer resp.Body.Close()
		s.logTelegramResponse(resp)
	}()
}

// logTelegramResponse logs non-2xx responses and logical ok:false
// bodies. Telegram returns 200 with {"ok": false, ...} on logical
// errors (e.g. bot lacks permission, chat not found), so a status-code
// check alone misses those. We read a bounded copy of the body and
// inspect the "ok" field; non-2xx is logged regardless.
func (s *Server) logTelegramResponse(resp *http.Response) {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10)) // 4 KiB cap
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("Telegram API error: HTTP %d %s", resp.StatusCode, string(body))
		return
	}
	var parsed struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil && !parsed.OK {
		desc := parsed.Description
		if desc == "" {
			desc = string(body)
		}
		log.Printf("Telegram API logical error: ok=false %s", desc)
	}
}
