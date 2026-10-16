package channels

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strconv"
	"time"
)

// VerifyTelegram compares fixed-size hashes, including when header lengths differ.
func VerifyTelegram(expected, supplied string) bool {
	a, b := sha256.Sum256([]byte(expected)), sha256.Sum256([]byte(supplied))
	return expected != "" && subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func VerifyDiscord(key, signature, timestamp string, body []byte, now time.Time, window time.Duration) bool {
	k, e := hex.DecodeString(key)
	if e != nil || len(k) != ed25519.PublicKeySize {
		return false
	}
	sig, e := hex.DecodeString(signature)
	if e != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	seconds, e := strconv.ParseInt(timestamp, 10, 64)
	if e != nil {
		return false
	}
	at := time.Unix(seconds, 0)
	if window <= 0 || at.Before(now.Add(-window)) || at.After(now.Add(window)) {
		return false
	}
	return ed25519.Verify(k, append([]byte(timestamp), body...), sig)
}
