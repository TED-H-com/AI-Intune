//go:build !linux

package scriptcatalog

func DiskActionReadiness() (string, bool) { return "", false }
