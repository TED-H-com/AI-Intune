package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestNotifyEnvironmentChild(t *testing.T) {
	if os.Getenv("CLAWCTL_TEST_NOTIFY_CHILD") != "1" {
		return
	}
	for _, key := range []string{"NOTIFY_SOCKET", "WATCHDOG_PID", "WATCHDOG_USEC", "MAINPID"} {
		if _, present := os.LookupEnv(key); present {
			t.Errorf("child inherited %s", key)
		}
	}
}

func TestCaptureNotifyEnvironment(t *testing.T) {
	saved := agentNotify
	t.Cleanup(func() { agentNotify = saved })
	socket := filepath.Join(t.TempDir(), "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	t.Setenv("NOTIFY_SOCKET", socket)
	t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("MAINPID", strconv.Itoa(os.Getpid()))
	t.Setenv("WATCHDOG_USEC", "90000000")
	t.Setenv("CLAWCTL_TEST_NOTIFY_CHILD", "1")
	captureNotifyEnvironment()
	child := exec.Command(os.Args[0], "-test.run=^TestNotifyEnvironmentChild$")
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, output)
	}
	if got := watchdogFromEnv(); got != 90*time.Second {
		t.Fatalf("watchdog deadline = %s", got)
	}
	for _, message := range []string{"READY=1", "WATCHDOG=1"} {
		sdNotify(message)
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 128)
		n, _, err := conn.ReadFromUnix(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if string(buffer[:n]) != message {
			t.Fatalf("notification = %q", buffer[:n])
		}
	}
	for _, field := range []*string{&agentNotify.watchdogPID, &agentNotify.mainPID} {
		original := *field
		*field = strconv.Itoa(os.Getpid() + 1)
		sdNotify("WATCHDOG=1")
		if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := conn.ReadFromUnix(make([]byte, 128)); err == nil {
			t.Fatal("notification sent despite mismatched PID")
		} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatal(err)
		}
		*field = original
	}
}
