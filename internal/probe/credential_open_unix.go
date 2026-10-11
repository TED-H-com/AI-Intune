//go:build unix

package probe

import (
	"golang.org/x/sys/unix"
	"os"
)

func openPrivateCredential(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// Called only after the descriptor is proven to refer to a regular file.
func credentialBlockingRead(f *os.File) error {
	return unix.SetNonblock(int(f.Fd()), false)
}
