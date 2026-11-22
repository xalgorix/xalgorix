package tools

import (
	"errors"
	"strings"
	"testing"
)

func registryWithRequiredParams() *Registry {
	r := NewRegistry()
	ok := func(map[string]string) (Result, error) { return Result{Output: "ok"}, nil }
	r.Register(&Tool{Name: "one", Parameters: []Parameter{{Name: "target", Required: true}}, Execute: ok})
	r.Register(&Tool{Name: "two", Parameters: []Parameter{{Name: "a", Required: true}, {Name: "b", Required: true}}, Execute: ok})
	r.Register(&Tool{Name: "report_vulnerability", Parameters: []Parameter{{Name: "title", Required: true}}, Execute: ok})
	return r
}

// TestMissingParamsErrorXMLWording pins the XML-channel text byte for byte:
// it is what every model on the XML dialect has always received.
func TestMissingParamsErrorXMLWording(t *testing.T) {
	r := registryWithRequiredParams()
	cases := map[string]string{
		"one":                  "missing required parameter 'target' for tool 'one' — you MUST include <parameter=target>value</parameter> inside <function=one>...</function>",
		"two":                  "missing required parameters for tool 'two': a, b — provide ALL of them in a single call (one <parameter=NAME>…</parameter> per field)",
		"report_vulnerability": "missing required parameter for tool 'report_vulnerability': title — 'title' is the only hard-required field; include it (with severity + description + exploitation_proof for a complete report) inside a single <function=report_vulnerability>...</function> block. severity/description are salvaged if omitted, but proof is still enforced by the reporting policy for actionable severities",
	}
	for tool, want := range cases {
		_, err := r.Execute(tool, map[string]string{})
		var missing *MissingParamsError
		if !errors.As(err, &missing) {
			t.Fatalf("%s: err = %v, want *MissingParamsError", tool, err)
		}
		if err.Error() != want {
			t.Errorf("%s: XML wording changed:\ngot  %q\nwant %q", tool, err.Error(), want)
		}
	}
}

// TestMissingParamsErrorNativeWording covers the native-channel text: no XML
// call syntax, and the "missing required parameter" prefix that the report
// repair hooks match on is kept.
func TestMissingParamsErrorNativeWording(t *testing.T) {
	r := registryWithRequiredParams()
	for _, tool := range []string{"one", "two", "report_vulnerability"} {
		_, err := r.Execute(tool, map[string]string{})
		var missing *MissingParamsError
		if !errors.As(err, &missing) {
			t.Fatalf("%s: err = %v, want *MissingParamsError", tool, err)
		}
		missing.Native = true
		msg := err.Error()
		if !strings.Contains(msg, "missing required parameter") {
			t.Errorf("%s: native wording lost the matched prefix: %q", tool, msg)
		}
		if !strings.Contains(msg, "JSON argument") {
			t.Errorf("%s: native wording does not describe JSON arguments: %q", tool, msg)
		}
		for _, xml := range []string{"<function=", "<parameter=", "</function>"} {
			if strings.Contains(msg, xml) {
				t.Errorf("%s: native wording still shows XML call syntax %q: %q", tool, xml, msg)
			}
		}
	}
}
