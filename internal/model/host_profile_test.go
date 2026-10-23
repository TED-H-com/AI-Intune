package model

import "testing"

func TestHostProfileVocabularyAndDigest(t *testing.T) {
	for _, raw := range []string{`{"journald_max_mb":99}`, `{"journald_max_mb":4097}`, `{"power_profile":"fast"}`, `{"lid_ignore":1}`, `{"unknown":true}`, `null`, `{"lid_ignore":true,"lid_ignore":false}`, `{} {}`} {
		if _, err := ParseHostProfile([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	for _, raw := range []string{`{}`, `{"lid_ignore":false}`, `{"journald_max_mb":100}`, `{"journald_max_mb":4096}`, `{"power_profile":"power-saver"}`} {
		p, err := ParseHostProfile([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := p.Canonical()
		q, err := ParseHostProfile(b)
		if err != nil {
			t.Fatal(err)
		}
		d, _ := p.Digest()
		e, _ := q.Digest()
		if d != e {
			t.Fatal("unstable digest")
		}
	}
	a, _ := ParseHostProfile([]byte(`{"linger":true,"lid_ignore":true}`))
	b, _ := ParseHostProfile([]byte(`{"lid_ignore":true,"linger":true}`))
	da, _ := a.Digest()
	db, _ := b.Digest()
	if da != db {
		t.Fatal("key order affects digest")
	}
	d, _ := (HostProfile{}).Digest()
	if d != "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" {
		t.Fatal(d)
	}
}
