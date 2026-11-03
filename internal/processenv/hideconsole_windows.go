//go:build windows

package processenv

import (
	"os/exec"
	"syscall"
)

// HideConsole prevents console children from opening a window on Windows.
// It preserves any other process attributes configured by the caller.
func HideConsole(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= 0x08000000 // CREATE_NO_WINDOW
}
