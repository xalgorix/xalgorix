//go:build !linux

package terminal

import "os/exec"

// isolateCommand is a no-op outside Linux: PID namespaces are a Linux feature,
// so commands run as they always have. See scan_namespace_linux.go.
func isolateCommand(string, *exec.Cmd, int64) bool { return false }

func releaseScanNamespace(string) {}

func processIsolationAvailable() bool { return false }
