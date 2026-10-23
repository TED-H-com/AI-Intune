package channels

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"testing"
	"time"
)

func TestInboundVerification(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	body := []byte(`{"type":1}`)
	sig := hex.EncodeToString(ed25519.Sign(priv, append([]byte(ts), body...)))
	key := hex.EncodeToString(pub)
	if !VerifyDiscord(key, sig, ts, body, now, 5*time.Minute) {
		t.Fatal("valid signature")
	}
	for _, c := range []struct {
		k, s, ts string
		b        []byte
		now      time.Time
	}{{key, sig, ts, []byte(`{"type":2}`), now}, {key, "ff", ts, body, now}, {"00", sig, ts, body, now}, {key, sig, ts, body, now.Add(6 * time.Minute)}, {key, sig, ts, body, now.Add(-6 * time.Minute)}} {
		if VerifyDiscord(c.k, c.s, c.ts, c.b, c.now, 5*time.Minute) {
			t.Fatal("accepted invalid signature or replay")
		}
	}
	if !VerifyTelegram("canary", "canary") || VerifyTelegram("canary", "wrong") || VerifyTelegram("", "") {
		t.Fatal("telegram verification")
	}
}
