//go:build !windows

package processenv

import "os/exec"

// HideConsole has no effect on platforms without Windows console windows.
func HideConsole(cmd *exec.Cmd) {}
