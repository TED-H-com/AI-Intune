package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"

	"golang.org/x/sys/windows"
)

func attachParentConsole() {
	// Preserve redirected pipes used by PowerShell/installer capture. Only replace
	// missing handles after attaching; never allocate a console for a daemon.
	attach := windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")
	saved := make(map[uint32]windows.Handle)
	for _, id := range []uint32{windows.STD_OUTPUT_HANDLE, windows.STD_ERROR_HANDLE} {
		h, err := windows.GetStdHandle(id)
		if err == nil && h != 0 && h != windows.InvalidHandle {
			if kind, err := windows.GetFileType(h); err == nil && (kind == windows.FILE_TYPE_PIPE || kind == windows.FILE_TYPE_DISK) {
				saved[id] = h
			}
		}
	}
	attach.Call(uintptr(0xffffffff)) // ATTACH_PARENT_PROCESS; failure is normal.
	for _, stream := range []struct {
		id   uint32
		name string
		file **os.File
	}{
		{windows.STD_OUTPUT_HANDLE, "CONOUT$", &os.Stdout},
		{windows.STD_ERROR_HANDLE, "CONOUT$", &os.Stderr},
	} {
		if h, ok := saved[stream.id]; ok {
			_ = windows.SetStdHandle(stream.id, h)
		}
		h, err := windows.GetStdHandle(stream.id)
		if err == nil && h != 0 && h != windows.InvalidHandle && (*stream.file).Fd() != uintptr(h) {
			*stream.file = os.NewFile(uintptr(h), stream.name)
		}
	}
}

func setupPlatformLogging(daemon, console bool) error {
	if !daemon || console {
		attachParentConsole()
		log.SetOutput(os.Stderr)
	}
	if !daemon {
		return nil
	}
	path, err := defaultAgentLogPath()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	// Keep the runtime's raw stderr/crash handle stable across agent.log rotation.
	crash, err := os.OpenFile(filepath.Join(filepath.Dir(path), "agent-crash.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = debug.SetCrashOutput(crash, debug.CrashOptions{}); err != nil {
		crash.Close()
		return err
	}
	consoleStderr := os.Stderr
	if err = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(crash.Fd())); err != nil {
		return err
	}
	os.Stderr = crash
	writer, err := openRotatingLog(path, 5*1024*1024, 5)
	if err != nil {
		return err
	}
	if console {
		log.SetOutput(io.MultiWriter(writer, consoleStderr))
	} else {
		log.SetOutput(writer)
	}
	return nil
}
