//go:build linux

package scriptcatalog

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"os"
	"syscall"
)

// DiskActionReadiness advertises this helper version and independently pinned
// local key. Missing/unsafe keys, root execution and missing Python fail closed.
func DiskActionReadiness() (string, bool) {
	if os.Geteuid() == 0 {
		return "", false
	}
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		return "", false
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return "", false
	}
	defer func() { syscall.Close(fd) }()
	for _, part := range []string{"etc", "clawctl"} {
		next, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			return "", false
		}
		syscall.Close(fd)
		fd = next
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			return "", false
		}
	}
	keyFD, err := syscall.Openat(fd, "disk-manifest-key.json", syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", false
	}
	file := os.NewFile(uintptr(keyFD), "public key")
	defer file.Close()
	var st syscall.Stat_t
	if syscall.Fstat(keyFD, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Size > 8192 {
		return "", false
	}
	var key struct {
		N string `json:"n"`
		E int    `json:"e"`
	}
	if json.NewDecoder(file).Decode(&key) != nil || key.E != 65537 {
		return "", false
	}
	n, ok := new(big.Int).SetString(key.N, 16)
	if !ok || n.BitLen() < 2048 || n.BitLen() > 4096 {
		return "", false
	}
	return Digest(x509.MarshalPKCS1PublicKey(&rsa.PublicKey{N: n, E: key.E})), true
}
