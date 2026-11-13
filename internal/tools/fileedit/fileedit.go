// Package fileedit provides file editing, listing, and searching tools.
package fileedit

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/sandbox"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// Register adds file editing tools to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "str_replace_editor",
		Description: "Edit a file by replacing text. Use command=view to view, command=create to create, command=str_replace to edit, command=insert to insert.",
		Parameters: []tools.Parameter{
			{Name: "command", Description: "One of: view, create, str_replace, insert", Required: true},
			{Name: "path", Description: "File path (relative to workspace or absolute)", Required: true},
			{Name: "old_str", Description: "Text to find (for str_replace)", Required: false},
			{Name: "new_str", Description: "Replacement text (for str_replace/insert)", Required: false},
			{Name: "insert_line", Description: "Line number to insert after (for insert)", Required: false},
			{Name: "view_range", Description: "Line range to view, e.g. '1-50' (for view)", Required: false},
			{Name: "file_text", Description: "Full file content (for create)", Required: false},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return strReplaceEditorForContext(r.GetScanContextID(), args)
		},
	})

	r.Register(&tools.Tool{
		Name:        "list_files",
		Description: "List files and directories at the given path.",
		Parameters: []tools.Parameter{
			{Name: "path", Description: "Directory path to list (relative to workspace or absolute)", Required: true},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return listFilesForContext(r.GetScanContextID(), args)
		},
	})

	r.Register(&tools.Tool{
		Name:        "search_files",
		Description: "Search for a pattern in files using ripgrep (rg).",
		Parameters: []tools.Parameter{
			{Name: "pattern", Description: "Search pattern (regex)", Required: true},
			{Name: "path", Description: "Directory to search in", Required: false},
			{Name: "include", Description: "File glob to include (e.g. *.go)", Required: false},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return searchFilesForContext(r.GetScanContextID(), args)
		},
	})
}

func resolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return config.Get().WorkspacePath(path)
}

func workspaceRootForContext(contextID string) string {
	if sc := scanctx.Get(strings.TrimSpace(contextID)); sc != nil {
		if sc.Terminal != nil {
			if wd := strings.TrimSpace(sc.Terminal.GetWorkDir()); wd != "" {
				return filepath.Clean(wd)
			}
		}
		if sc.ScanDir != "" {
			return filepath.Clean(sc.ScanDir)
		}
	}
	if cfg := config.Get(); cfg != nil && cfg.Workspace != "" {
		return filepath.Clean(cfg.Workspace)
	}
	return "."
}

func resolvePathForContext(contextID, rawPath string) (string, error) {
	root := workspaceRootForContext(contextID)
	path := strings.TrimSpace(rawPath)
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	if path == "~" {
		path = root
	} else if strings.HasPrefix(path, "~/") {
		path = filepath.Join(root, strings.TrimPrefix(path, "~/"))
	} else if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}

	resolved := filepath.Clean(path)
	if envAllowsAbsoluteFileEdit() {
		return resolved, nil
	}
	if !isWithinPath(root, resolved) {
		return "", fmt.Errorf("path %s is outside the active scan workspace %s", resolved, root)
	}
	return resolved, nil
}

func envAllowsAbsoluteFileEdit() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("XALGORIX_ALLOW_ABSOLUTE_FILEEDIT")))
	return v == "1" || v == "true" || v == "yes"
}

func isWithinPath(root, path string) bool {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		absRoot = filepath.Clean(root)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = filepath.Clean(path)
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func strReplaceEditor(args map[string]string) (tools.Result, error) {
	return runEditorWithPolicy(nil, args)
}

func strReplaceEditorForContext(contextID string, args map[string]string) (tools.Result, error) {
	sc := scanctx.Get(strings.TrimSpace(contextID))
	return runEditorWithPolicy(sc, args)
}

// runEditorWithPolicy dispatches the editor command and routes every
// write (create / str_replace / insert) through sandbox.Default().CheckResolve
// using the operation-specific tool name "fileedit.<op>" (R8.1, R5.3).
//
// The view command is read-only and intentionally bypasses the Path_Policy:
// Task 8.1 covers create/replace/insert/delete writes only.
//
// On Path_Policy reject we return the error to the agent loop via
// tools.Result{Error: err.Error()}, nil — never as a Go-level error —
// so the LLM can recover and try a path inside the Allow_List.
func runEditorWithPolicy(sc *scanctx.ScanContext, args map[string]string) (tools.Result, error) {
	command := args["command"]
	rawPath := args["path"]

	switch command {
	case "view":
		// Reads honor the deny-list but are otherwise permitted
		// anywhere — agents need access to system wordlists, payload
		// dirs, /etc/services, etc. CheckRead canonicalizes the path
		// and rejects only if it lands inside a deny-list root
		// (~/.ssh, ~/.aws, /etc/shadow, etc.).
		canonical, rerr := sandbox.Default().CheckRead(sc, "fileedit.view", rawPath)
		if rerr != nil {
			return tools.Result{Error: rerr.Error()}, nil
		}
		return viewFile(canonical, args["view_range"])
	case "create":
		canonical, rerr := sandbox.Default().CheckResolve(sc, "fileedit.create", rawPath)
		if rerr != nil {
			return tools.Result{Error: rerr.Error()}, nil
		}
		return createFile(canonical, args["file_text"])
	case "str_replace":
		canonical, rerr := sandbox.Default().CheckResolve(sc, "fileedit.replace", rawPath)
		if rerr != nil {
			return tools.Result{Error: rerr.Error()}, nil
		}
		return replaceInFile(canonical, args["old_str"], args["new_str"])
	case "insert":
		canonical, rerr := sandbox.Default().CheckResolve(sc, "fileedit.insert", rawPath)
		if rerr != nil {
			return tools.Result{Error: rerr.Error()}, nil
		}
		return insertInFile(canonical, args["new_str"], args["insert_line"])
	default:
		return tools.Result{}, fmt.Errorf("unknown command: %s (expected: view, create, str_replace, insert)", command)
	}
}

// runEditor is intentionally removed: the editor entry point now lives in
// runEditorWithPolicy, which inlines the dispatch so each write command can
// route its path through sandbox.Default().CheckResolve (writes) or
// sandbox.Default().CheckRead (the view read).

func viewFile(path, viewRange string) (tools.Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tools.Result{}, fmt.Errorf("cannot read file: %w", err)
	}

	lines := strings.Split(string(data), "\n")

	startLine, endLine := 1, len(lines)
	if viewRange != "" {
		parts := strings.SplitN(viewRange, "-", 2)
		if len(parts) == 2 {
			var err error
			startLine, err = strconv.Atoi(parts[0])
			if err != nil {
				return tools.Result{}, fmt.Errorf("invalid start line in view_range: %s", parts[0])
			}
			endLine, err = strconv.Atoi(parts[1])
			if err != nil {
				return tools.Result{}, fmt.Errorf("invalid end line in view_range: %s", parts[1])
			}
		}
	}

	if startLine < 1 {
		startLine = 1
	}
	if endLine > len(lines) {
		endLine = len(lines)
	}

	var b strings.Builder
	for i := startLine - 1; i < endLine; i++ {
		b.WriteString(fmt.Sprintf("%6d │ %s\n", i+1, lines[i]))
	}

	return tools.Result{Output: b.String()}, nil
}

func createFile(path, content string) (tools.Result, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tools.Result{}, fmt.Errorf("cannot create directory: %w", err)
	}

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return tools.Result{}, fmt.Errorf("cannot write file: %w", err)
	}

	return tools.Result{Output: fmt.Sprintf("File created: %s", path)}, nil
}

func replaceInFile(path, oldStr, newStr string) (tools.Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tools.Result{}, fmt.Errorf("cannot read file: %w", err)
	}

	content := string(data)

	count := strings.Count(content, oldStr)
	if count == 0 {
		return tools.Result{}, fmt.Errorf("old_str not found in file. Make sure it matches exactly, including whitespace")
	}
	if count > 1 {
		return tools.Result{}, fmt.Errorf("old_str found %d times in file. It must be unique. Add more context to make it unique", count)
	}

	newContent := strings.Replace(content, oldStr, newStr, 1)

	if err := os.WriteFile(path, []byte(newContent), 0o600); err != nil {
		return tools.Result{}, fmt.Errorf("cannot write file: %w", err)
	}

	return tools.Result{Output: fmt.Sprintf("Successfully replaced text in %s", path)}, nil
}

func insertInFile(path, newStr, insertLineStr string) (tools.Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tools.Result{}, fmt.Errorf("cannot read file: %w", err)
	}

	insertLine, err := strconv.Atoi(insertLineStr)
	if err != nil {
		return tools.Result{}, fmt.Errorf("invalid insert_line %q: %w", insertLineStr, err)
	}
	lines := strings.Split(string(data), "\n")

	if insertLine < 0 || insertLine > len(lines) {
		return tools.Result{}, fmt.Errorf("insert_line %d is out of range (file has %d lines)", insertLine, len(lines))
	}

	newLines := strings.Split(newStr, "\n")
	result := make([]string, 0, len(lines)+len(newLines))
	result = append(result, lines[:insertLine]...)
	result = append(result, newLines...)
	result = append(result, lines[insertLine:]...)

	if err := os.WriteFile(path, []byte(strings.Join(result, "\n")), 0o600); err != nil {
		return tools.Result{}, fmt.Errorf("cannot write file: %w", err)
	}

	return tools.Result{Output: fmt.Sprintf("Inserted %d lines after line %d in %s", len(newLines), insertLine, path)}, nil
}

func listFiles(args map[string]string) (tools.Result, error) {
	path := resolvePath(args["path"])
	return listFilesAtPath(path)
}

func listFilesForContext(contextID string, args map[string]string) (tools.Result, error) {
	path, err := resolvePathForContext(contextID, args["path"])
	if err != nil {
		return tools.Result{}, err
	}
	canonical, rerr := sandbox.Default().CheckRead(scanctx.Get(strings.TrimSpace(contextID)), "fileedit.list", path)
	if rerr != nil {
		return tools.Result{Error: rerr.Error()}, nil
	}
	return listFilesAtPath(canonical)
}

func listFilesAtPath(path string) (tools.Result, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return tools.Result{}, fmt.Errorf("cannot read directory: %w", err)
	}

	var b strings.Builder
	for _, e := range entries {
		info, _ := e.Info()
		if e.IsDir() {
			b.WriteString(fmt.Sprintf("  📁 %s/\n", e.Name()))
		} else if info != nil {
			b.WriteString(fmt.Sprintf("  📄 %s (%d bytes)\n", e.Name(), info.Size()))
		} else {
			b.WriteString(fmt.Sprintf("  📄 %s\n", e.Name()))
		}
	}

	if b.Len() == 0 {
		return tools.Result{Output: "(empty directory)"}, nil
	}
	return tools.Result{Output: b.String()}, nil
}

func searchFilesForContext(contextID string, args map[string]string) (tools.Result, error) {
	pattern := args["pattern"]
	path := args["path"]
	if path == "" {
		path = "."
	}
	resolved, err := resolvePathForContext(contextID, path)
	if err != nil {
		return tools.Result{}, err
	}
	return searchFilesWithPolicy(sandbox.Default(), scanctx.Get(strings.TrimSpace(contextID)), pattern, resolved, args["include"])
}

// searchFilesWithPolicy runs the recursive search under the read
// deny-list. A search reads file contents, so it is refused when its root
// resolves into a deny-list entry, to the filesystem root, or under /proc
// (process environment files), and deny-list entries
// below the root are skipped. Both the check and the search use the
// symlink-resolved root: grep and rg follow a symlink given as the root,
// so the original spelling could hide where the search really runs.
func searchFilesWithPolicy(policy *sandbox.Policy, sc *scanctx.ScanContext, pattern, root, include string) (tools.Result, error) {
	canonical, rerr := policy.CheckRead(sc, "fileedit.search", root)
	if rerr != nil {
		return tools.Result{Error: rerr.Error()}, nil
	}
	if canonical == "/" || canonical == "/proc" || strings.HasPrefix(canonical, "/proc/") {
		return tools.Result{Error: fmt.Sprintf("search_files: searching %s (resolves to %s) is not permitted", root, canonical)}, nil
	}
	return searchFilesAtPath(pattern, canonical, include, searchExclusions(policy.ReadDenyRoots(), canonical))
}

// searchExclusions returns exclusion globs for the deny-list entries
// located under root: the entry's base name (glob metacharacters escaped)
// plus "*", so the ".tmp" siblings the policy also denies are skipped too.
// Matching is by name, so a same-named file elsewhere under the root is
// skipped as well; the search fails closed rather than open.
func searchExclusions(denyRoots []string, root string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, deny := range denyRoots {
		if !isWithinPath(root, deny) {
			continue
		}
		name := filepath.Base(deny)
		if name == "." || name == string(filepath.Separator) {
			continue
		}
		glob := escapeGlob(name) + "*"
		if seen[glob] {
			continue
		}
		seen[glob] = true
		out = append(out, glob)
	}
	return out
}

// escapeGlob backslash-escapes the glob metacharacters understood by
// ripgrep's --glob and grep's --exclude.
func escapeGlob(name string) string {
	var b strings.Builder
	for _, r := range name {
		if strings.ContainsRune(`\*?[]{}`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// searchCommandArgs builds the ripgrep and grep argument lists. Exclusions
// come after the caller's include glob (for both tools the last matching
// glob wins) and "--" keeps a pattern that starts with "-" from being read
// as a flag. ripgrep recurses by default (its -r flag is --replace);
// --hidden --no-ignore make it search the same files grep -r does.
func searchCommandArgs(pattern, path, include string, exclude []string) (rgArgs, grepArgs []string) {
	rgArgs = []string{"-n", "--color=never", "--hidden", "--no-ignore"}
	grepArgs = []string{"-rn", "--color=never"}
	if include != "" {
		rgArgs = append(rgArgs, "--glob", include)
		grepArgs = append(grepArgs, "--include", include)
	}
	for _, name := range exclude {
		rgArgs = append(rgArgs, "--glob", "!"+name)
		grepArgs = append(grepArgs, "--exclude", name, "--exclude-dir", name)
	}
	rgArgs = append(rgArgs, "--", pattern, path)
	grepArgs = append(grepArgs, "--", pattern, path)
	return rgArgs, grepArgs
}

func searchFilesAtPath(pattern, path, include string, exclude []string) (tools.Result, error) {
	// Use ripgrep if available, fallback to grep
	rgArgs, grepArgs := searchCommandArgs(pattern, path, include, exclude)

	result, err := tools.RunCommand("rg", rgArgs...)
	if err != nil {
		// Fallback to grep
		result, err = tools.RunCommand("grep", grepArgs...)
		if err != nil {
			return tools.Result{Output: "No matches found."}, nil
		}
	}

	// Truncate if too long
	lines := strings.Split(result, "\n")
	if len(lines) > 100 {
		output := strings.Join(lines[:100], "\n")
		output += fmt.Sprintf("\n\n... [%d more matches truncated]", len(lines)-100)
		return tools.Result{Output: output}, nil
	}

	return tools.Result{Output: result}, nil
}
