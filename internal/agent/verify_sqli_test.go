package agent

import (
	"net/url"
	"strings"
	"testing"
)

// TestSqliErrorVerdict covers the decision logic of the error-based SQLi
// confirmer without any HTTP: the caller supplies the three response bodies.
func TestSqliErrorVerdict(t *testing.T) {
	const dbErr = "Database error: You have an error in your SQL syntax; check the manual near '''"
	const clean = "<html><body>ok: 3 rows</body></html>"

	tests := []struct {
		name          string
		baseline      string
		broken        string
		balanced      string
		wantConfirmed bool
		wantConf      float64
	}{
		{
			// Classic break/recover: only the single-quote request errors.
			name: "break then recover", baseline: clean, broken: dbErr, balanced: clean,
			wantConfirmed: true, wantConf: 0.95,
		},
		{
			// Simulated/any-quote apps: broken AND balanced error, baseline clean.
			// Quote rejection is also possible; this is not a reproduced break/recover.
			name: "broken and balanced both error", baseline: clean, broken: dbErr, balanced: dbErr,
			wantConfirmed: false, wantConf: 0,
		},
		{
			// Always-on error page: baseline already errors → reject.
			name: "baseline already errors", baseline: dbErr, broken: dbErr, balanced: dbErr,
			wantConfirmed: false, wantConf: 0,
		},
		{
			// No DBMS error on the quote injection → not error-based here.
			name: "no error on injection", baseline: clean, broken: clean, balanced: clean,
			wantConfirmed: false, wantConf: 0,
		},
		{
			// A generic 500 without a DBMS signature must not confirm.
			name: "generic error not sql", baseline: clean, broken: "HTTP 500 Internal Server Error", balanced: clean,
			wantConfirmed: false, wantConf: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confirmed, conf, note := sqliErrorVerdict(tt.baseline, tt.broken, tt.balanced)
			if confirmed != tt.wantConfirmed {
				t.Fatalf("confirmed=%v want %v (note=%s)", confirmed, tt.wantConfirmed, note)
			}
			if conf != tt.wantConf {
				t.Errorf("confidence=%.2f want %.2f", conf, tt.wantConf)
			}
			if note == "" {
				t.Errorf("expected a non-empty explanation note")
			}
			if confirmed && conf < 0.5 {
				t.Errorf("a confirmed verdict must carry meaningful confidence, got %.2f", conf)
			}
		})
	}
}

func TestWithQueryParam(t *testing.T) {
	u, _ := url.Parse("http://t.example/internal/report?x=9")
	got, err := withQueryParam(u, "uid", "1'")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The single quote must be percent-encoded and the existing param preserved.
	if !strings.Contains(got, "uid=1%27") {
		t.Errorf("expected encoded quote in %q", got)
	}
	if !strings.Contains(got, "x=9") {
		t.Errorf("expected existing query param preserved in %q", got)
	}
	// The original URL must be unmodified (withQueryParam copies).
	if u.RawQuery != "x=9" {
		t.Errorf("source URL mutated: %q", u.RawQuery)
	}
}

func TestBaseURLOf(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/a/b?c=d")
	if got := baseURLOf(u); got != "https://api.example.com" {
		t.Errorf("baseURLOf = %q, want https://api.example.com", got)
	}
	if got := baseURLOf(nil); got != "" {
		t.Errorf("baseURLOf(nil) = %q, want empty", got)
	}
}

func TestBoundedText(t *testing.T) {
	if got := boundedText("  hello  ", 100); got != "hello" {
		t.Errorf("boundedText trim = %q", got)
	}
	long := strings.Repeat("a", 50)
	got := boundedText(long, 10)
	if !strings.HasSuffix(got, "…") || len([]rune(got)) != 11 {
		t.Errorf("boundedText truncation = %q (len=%d)", got, len([]rune(got)))
	}
}
