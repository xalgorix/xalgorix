package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/xalgord/xalgorix/v4/internal/methodology"
)

// gen-webui-phases regenerates webui/src/methodology-phases.json from the
// canonical methodology registry. Run from the repo root:
//
//	go run ./tools/gen-webui-phases > webui/src/methodology-phases.json
func main() {
	type webuiPhase struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}
	out := make([]webuiPhase, 0, methodology.PhaseCount)
	for _, p := range methodology.Phases {
		out = append(out, webuiPhase{ID: p.ID, Name: p.Name})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(buf.Bytes()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
