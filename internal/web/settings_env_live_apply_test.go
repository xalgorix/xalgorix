package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"testing"
)

// configFieldsByEnvKey maps every environment key that config's load() reads
// straight into a Config field (in the Config composite literal) to that
// field's name. It parses the config source, so a field added later is
// covered without touching this test.
func configFieldsByEnvKey(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("..", "config", "config.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse config.go: %v", err)
	}
	fields := map[string]string{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "load" || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if typ, ok := lit.Type.(*ast.Ident); !ok || typ.Name != "Config" {
				return true
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				field, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				ast.Inspect(kv.Value, func(v ast.Node) bool {
					if bl, ok := v.(*ast.BasicLit); ok && bl.Kind == token.STRING {
						if key, err := strconv.Unquote(bl.Value); err == nil && envSettingKeyRe.MatchString(key) {
							fields[key] = field.Name
						}
					}
					return true
				})
			}
			return false
		})
	}
	if len(fields) < 50 {
		t.Fatalf("found only %d env-backed Config fields in load(); the parser no longer matches config.go", len(fields))
	}
	return fields
}

// twoSettingValues returns two values that should leave a Config field of
// the given kind in different states.
func twoSettingValues(def envSettingDefinition, kind reflect.Kind) (string, string) {
	switch kind {
	case reflect.Bool:
		return "true", "false"
	case reflect.Int, reflect.Int64:
		return "20", "40"
	case reflect.Float64, reflect.Pointer:
		return "0.3", "0.6"
	}
	if len(def.Options) >= 2 {
		return def.Options[0], def.Options[1]
	}
	return "alpha", "bravo"
}

// A setting the dashboard does not flag RequiresRestart must reach new scans
// as soon as it is saved. New scans copy *s.cfg, which was filled from the
// environment at startup, so saving only calls os.Setenv and then
// applyEnvironmentToRuntimeConfig; a key missing from that switch silently
// waits for the next restart while the page says it is live.
func TestLiveSettingsReachRuntimeConfig(t *testing.T) {
	fields := configFieldsByEnvKey(t)
	defs := envDefinitionByKey()
	keys := make([]string, 0, len(defs))
	for key := range defs {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	checked := 0
	for _, key := range keys {
		def := defs[key]
		field, loaded := fields[key]
		if def.RequiresRestart || !loaded {
			continue
		}
		checked++
		t.Run(key, func(t *testing.T) {
			s := newTestServer(t, nil)
			fv := reflect.ValueOf(s.cfg).Elem().FieldByName(field)
			if !fv.IsValid() {
				t.Fatalf("Config has no field %s", field)
			}
			a, b := twoSettingValues(def, fv.Kind())
			s.applyEnvironmentToRuntimeConfig(map[string]string{key: a})
			afterA := reflect.ValueOf(s.cfg).Elem().FieldByName(field).Interface()
			s.applyEnvironmentToRuntimeConfig(map[string]string{key: b})
			afterB := reflect.ValueOf(s.cfg).Elem().FieldByName(field).Interface()
			if reflect.DeepEqual(afterA, afterB) {
				t.Fatalf("saving %s=%q and then %q left Config.%s at %v both times: the dashboard treats it as live, "+
					"but new scans only see it after a restart. Handle it in applyEnvironmentToRuntimeConfig or mark it RequiresRestart.",
					key, a, b, field, afterA)
			}
		})
	}
	if checked < 30 {
		t.Fatalf("checked only %d live settings; expected the bulk of the settings page", checked)
	}
}

// The specialist switch and the checklist choice are read from the scan's
// config copy, so they must update s.cfg when saved.
func TestSpecialistAndChecklistSettingsApplyLive(t *testing.T) {
	s := newTestServer(t, nil)

	s.applyEnvironmentToRuntimeConfig(map[string]string{"XALGORIX_DISABLE_AUTO_DELEGATE": "true"})
	if !s.cfg.DisableAutoDelegate {
		t.Fatal("XALGORIX_DISABLE_AUTO_DELEGATE=true did not disable specialists for new scans")
	}
	s.applyEnvironmentToRuntimeConfig(map[string]string{"XALGORIX_DISABLE_AUTO_DELEGATE": ""})
	if s.cfg.DisableAutoDelegate {
		t.Fatal("clearing XALGORIX_DISABLE_AUTO_DELEGATE did not fall back to the default (specialists on)")
	}

	for value, want := range map[string]string{
		"professional": "professional",
		"full":         "full",
		"":             "full",
		"unknown":      "full",
	} {
		s.applyEnvironmentToRuntimeConfig(map[string]string{"XALGORIX_CHECKLIST": value})
		if s.cfg.Checklist != want {
			t.Fatalf("XALGORIX_CHECKLIST=%q gave Checklist %q, want %q", value, s.cfg.Checklist, want)
		}
	}
}
