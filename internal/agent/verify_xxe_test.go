package agent

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestXxeLeakVerdict covers the decision logic of the XXE confirmer without any
// HTTP: the caller supplies the baseline and external-entity probe bodies.
func TestXxeLeakVerdict(t *testing.T) {
	const passwd = "imported 1 record: root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
	const benign = "imported 0 records"
	const echoed = "imported 1 record: &xxe;" // entities disabled: literal entity echoed, no file

	tests := []struct {
		name          string
		baseline      string
		probe         string
		wantConfirmed bool
	}{
		{
			// Classic in-band XXE: the passwd content appears only on the payload.
			name: "leak on payload only", baseline: benign, probe: passwd, wantConfirmed: true,
		},
		{
			// External entities disabled (safe): the literal entity is echoed, no file content.
			name: "entities disabled — literal echo", baseline: benign, probe: echoed, wantConfirmed: false,
		},
		{
			// The payload returns nothing recognizable → not confirmed.
			name: "no leak", baseline: benign, probe: benign, wantConfirmed: false,
		},
		{
			// The baseline ALREADY shows passwd markers → not controlled by the entity.
			name: "baseline already leaks", baseline: passwd, probe: passwd, wantConfirmed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confirmed, note := xxeLeakVerdict(tt.baseline, tt.probe, "/etc/passwd")
			if confirmed != tt.wantConfirmed {
				t.Fatalf("confirmed=%v want %v (note=%s)", confirmed, tt.wantConfirmed, note)
			}
			if note == "" {
				t.Error("expected a non-empty explanation note")
			}
		})
	}
}

func TestLooksLikeFileLeak(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{"root:x:0:0:root:/root:/bin/bash", true},
		{"nobody:*:65534:65534:Unprivileged User:/var/empty:/usr/bin/false", true}, // passwd shape
		{"imported 0 records", false},
		{"<data>&xxe;</data>", false},
		{"hello world, no passwd here", false},
	}
	for _, c := range cases {
		if got := looksLikeFileLeak(c.body, "/etc/passwd"); got != c.want {
			t.Errorf("looksLikeFileLeak(%q) = %v, want %v", c.body, got, c.want)
		}
	}
}

func TestXXEDifferentialLeakVerdict(t *testing.T) {
	markers := xxeProbeMarkers{
		Nonce:   "0123456789abcdef",
		Start:   "xalgorix-xxe-start-0123456789abcdef",
		End:     "xalgorix-xxe-end-0123456789abcdef",
		Control: "xalgorix-xxe-control-0123456789abcdef",
	}
	anchored := func(value string) string {
		return "response:" + markers.Start + value + markers.End + ":done"
	}
	capture := func(body string, status int) xxeProbeCapture {
		return xxeProbeCapture{Body: body, StatusCode: status}
	}
	baseline := capture(anchored(markers.Control), 200)
	missing := capture("external entity file was not found", 400)
	custom := "fixture-only-canary-8490362715\n"
	rawEcho := "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY xxe SYSTEM \"file:///oracle/canary\">]><data>" +
		markers.Start + "&xxe;" + markers.End + "</data>"

	tests := []struct {
		name     string
		baseline xxeProbeCapture
		missing  xxeProbeCapture
		first    xxeProbeCapture
		second   xxeProbeCapture
		want     bool
	}{
		{"stable custom content", baseline, missing, capture(anchored(custom), 200), capture(anchored(custom), 200), true},
		{"patched parser drops entity", baseline, capture(anchored(""), 200), capture(anchored(""), 200), capture(anchored(""), 200), false},
		{"raw request echo", baseline, capture(rawEcho, 200), capture(rawEcho, 200), capture(rawEcho, 200), false},
		{"escaped literal entity", baseline, capture(anchored("&amp;xxe;"), 200), capture(anchored("&amp;xxe;"), 200), capture(anchored("&amp;xxe;"), 200), false},
		{"fixed documentation", capture("Documentation example: "+custom, 200), missing, capture("Documentation example: "+custom, 200), capture("Documentation example: "+custom, 200), false},
		{"blocked substitution", baseline, capture(anchored("external entity blocked"), 200), capture(anchored("external entity blocked"), 200), capture(anchored("external entity blocked"), 200), false},
		{"unstable substitution", baseline, missing, capture(anchored("volatile-substitution-one"), 200), capture(anchored("volatile-substitution-two"), 200), false},
		{"baseline contamination", capture(anchored(markers.Control)+" docs "+custom, 200), missing, capture(anchored(custom), 200), capture(anchored(custom), 200), false},
		{"status instability", baseline, missing, capture(anchored(custom), 200), capture(anchored(custom), 500), false},
		{"truncated response", baseline, missing, capture(anchored(custom), 200), xxeProbeCapture{Body: anchored(custom), StatusCode: 200, Truncated: true}, false},
		{"short placeholder", baseline, missing, capture(anchored("short"), 200), capture(anchored("short"), 200), false},
		{"duplicate probe anchors", baseline, missing, capture(anchored(custom)+anchored(custom), 200), capture(anchored(custom)+anchored(custom), 200), false},
		{"requested path reflection", baseline, missing, capture(anchored("/oracle/canary"), 200), capture(anchored("/oracle/canary"), 200), false},
		{"requested URI reflection", baseline, missing, capture(anchored("file:///oracle/canary"), 200), capture(anchored("file:///oracle/canary"), 200), false},
		{"ambiguous missing control", baseline, capture(anchored("")+anchored(""), 400), capture(anchored(custom), 200), capture(anchored(custom), 200), false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, note, leaked := xxeDifferentialLeakVerdict(
				test.baseline,
				test.missing,
				test.first,
				test.second,
				"/oracle/canary",
				markers,
			)
			if got != test.want {
				t.Fatalf("confirmed=%v want=%v (note=%s)", got, test.want, note)
			}
			if note == "" {
				t.Fatal("expected a non-empty explanation")
			}
			if test.want && leaked != custom {
				t.Fatalf("leaked content=%q want %q", leaked, custom)
			}
			if !test.want && leaked != "" {
				t.Fatalf("negative control retained purported leaked content %q", leaked)
			}
		})
	}

	passwdLine := "root:x:0:0:root:/root:/bin/bash"
	for _, test := range []struct {
		name   string
		first  string
		second string
		want   bool
	}{
		{"stable transformed passwd without anchors", "converted: " + passwdLine, "converted: " + passwdLine, true},
		{"different passwd evidence", "converted: " + passwdLine, "converted: root:x:0:0:root:/root:/bin/zsh", false},
		{"passwd-shaped entity block", "external entity blocked: " + passwdLine, "external entity blocked: " + passwdLine, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, note, leaked := xxeDifferentialLeakVerdict(
				baseline,
				missing,
				capture(test.first, 200),
				capture(test.second, 200),
				"/etc/passwd",
				markers,
			)
			if got != test.want {
				t.Fatalf("confirmed=%v want=%v (note=%s)", got, test.want, note)
			}
			if note == "" {
				t.Fatal("expected a non-empty explanation")
			}
			if test.want && leaked != passwdLine {
				t.Fatalf("leaked content=%q want %q", leaked, passwdLine)
			}
			if !test.want && leaked != "" {
				t.Fatalf("negative control retained purported leaked content %q", leaked)
			}
		})
	}

	if !looksLikeRequestedFileReflection("canary", "/oracle/canary") {
		t.Fatal("expected a bare requested filename to be rejected as reflection")
	}
	if !looksLikeRequestedFileReflection("requested file: canary", "/oracle/canary") {
		t.Fatal("expected a labeled requested filename to be rejected as reflection")
	}
	if looksLikeRequestedFileReflection(custom, "/oracle/canary") {
		t.Fatal("custom file contents containing the filename as a substring were rejected")
	}
}

func TestXXEFileURI(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"unix path", "/etc/passwd", "file:///etc/passwd", false},
		{"local URI", "file:///oracle/canary", "file:///oracle/canary", false},
		{"encoded local URI", "file:///tmp/a%20b%23%3F%22.xml", "file:///tmp/a%20b%23%3F%22.xml", false},
		{"localhost URI", "file://localhost/etc/passwd", "file://localhost/etc/passwd", false},
		{"windows path", "C:\\Windows\\win.ini", "file:///C:/Windows/win.ini", false},
		{"special path characters", "/tmp/a b#?\"<>&.xml", "file:///tmp/a%20b%23%3F%22%3C%3E%26.xml", false},
		{"quote is encoded", "/tmp/bad\"path", "file:///tmp/bad%22path", false},
		{"relative path", "etc/passwd", "", true},
		{"remote file host", "file://remote.example/share/file", "", true},
		{"remote path", "//remote.example/share/file", "", true},
		{"URI user info", "file://user@localhost/etc/passwd", "", true},
		{"URI query", "file:///etc/passwd?format=raw", "", true},
		{"URI fragment", "file:///etc/passwd#proof", "", true},
		{"opaque URI", "file:/etc/passwd", "", true},
		{"control character", "/tmp/bad\npath", "", true},
		{"encoded control character", "file:///tmp/bad%0Apath", "", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := xxeFileURI(test.input)
			if (err != nil) != test.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("URI=%q want %q", got, test.want)
			}
		})
	}
}

func TestPollBlindXXECancelledImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	hits, err := pollBlindXXE(ctx, "unused-token", []time.Duration{time.Hour})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v want context.Canceled", err)
	}
	if len(hits) != 0 {
		t.Fatalf("unexpected interactions after cancellation: %d", len(hits))
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("canceled poll took %s; expected immediate return", elapsed)
	}
}

func TestBlindXXEVerifyReturnsShutdownError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := &Agent{ctx: ctx}

	result := a.blindXXEVerify("POST", "https://target.example.test/xml", nil, "/xml", "")
	if result == nil || result.Error == "" {
		t.Fatal("canceled blind verification fell through to an ordinary negative")
	}
}
