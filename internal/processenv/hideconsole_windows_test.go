//go:build windows

package processenv

import (
	"context"
	"syscall"
	"testing"
)

func TestCommandContextHidesConsole(t *testing.T) {
	cmd := CommandContext(context.Background(), "powershell.exe", "-NoProfile")
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.HideWindow || cmd.SysProcAttr.CreationFlags&0x08000000 == 0 {
		t.Fatal("Windows subprocess must hide its window and use CREATE_NO_WINDOW")
	}
}

func TestHideConsolePreservesAttributes(t *testing.T) {
	cmd := CommandContext(context.Background(), "cmd.exe")
	attrs := &syscall.SysProcAttr{CreationFlags: 0x00000200, NoInheritHandles: true}
	cmd.SysProcAttr = attrs
	HideConsole(cmd)
	if cmd.SysProcAttr != attrs || !attrs.NoInheritHandles || attrs.CreationFlags != 0x08000200 || !attrs.HideWindow {
		t.Fatal("HideConsole must merge existing process attributes")
	}
}
