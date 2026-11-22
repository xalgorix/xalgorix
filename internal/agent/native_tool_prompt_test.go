package agent

import (
	"strings"
	"testing"
)

// TestNativeToolPromptRewrite verifies the XML blocks are actually replaced.
//
// This is a canary: if the upstream prompt text drifts, the constants stop
// matching and the native channel silently keeps teaching the XML dialect. The
// assertion on the composed input fails loudly in that case.
func TestNativeToolPromptRewrite(t *testing.T) {
	in := "prefix\n" + xmlCallRule + "\n\n" + xmlFormatBlock + "\n\n" + xmlReportRule + "\nsuffix"

	out := nativeToolPromptRewrite(in)

	if strings.Contains(out, "You MUST call tools using the XML format") {
		t.Fatal("the XML call rule was not replaced")
	}
	if !strings.Contains(out, "native tool interface") {
		t.Fatal("the native call rule is missing")
	}
	if strings.Contains(out, "<parameter=param_name>") {
		t.Fatal("the XML format block was not replaced")
	}
	if !strings.Contains(out, "never reproduce them") {
		t.Fatal("the legacy-examples warning is missing")
	}
	if strings.Contains(out, "EXECUTE THE XML TOOL CALL") || !strings.Contains(out, nativeReportRule) {
		t.Fatal("the XML report rule (17b) was not replaced")
	}
	// The surrounding prompt must be untouched.
	if !strings.HasPrefix(out, "prefix\n") || !strings.HasSuffix(out, "\nsuffix") {
		t.Fatalf("surrounding text was altered: %q", out)
	}
}

// TestNativeToolPromptRewriteLeavesLegacyAlone guards the other direction: a
// prompt without the XML blocks must come back unchanged.
func TestNativeToolPromptRewriteLeavesLegacyAlone(t *testing.T) {
	in := "## Methodology\n\nNothing about tool formats here.\n"
	if out := nativeToolPromptRewrite(in); out != in {
		t.Fatalf("prompt changed unexpectedly:\ngot  %q\nwant %q", out, in)
	}
}
