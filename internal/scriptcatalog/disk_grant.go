package scriptcatalog

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// DiskGrant contains exact canonical private bytes. It must never enter MCP,
// audit, verification excerpts, or human public projections.
type DiskGrant struct {
	Schema       string              `json:"schema"`
	Action       string              `json:"action"`
	ScriptSHA256 string              `json:"script_sha256"`
	ScriptID     string              `json:"script_id"`
	MachineID    string              `json:"machine_id"`
	JobID        string              `json:"job_id"`
	ArgsDigest   string              `json:"args_digest"`
	PolicyID     string              `json:"policy_id"`
	PolicyDigest string              `json:"policy_digest"`
	Policy       []byte              `json:"policy"`
	Manifests    [][]byte            `json:"manifests"`
	Selection    map[string][]string `json:"selection,omitempty"`
	ExpiresAt    time.Time           `json:"expires_at"`
}

type SignedDiskGrant struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// SignDiskGrant uses the standard RSA PKCS#1 v1.5/SHA256 encoding that the
// isolated Python helper verifies against its locally pinned public key.
func SignDiskGrant(key *rsa.PrivateKey, grant DiskGrant) (SignedDiskGrant, error) {
	var out SignedDiskGrant
	if key == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 4096 || key.E != 65537 {
		return out, fmt.Errorf("disk manifest signing key unavailable or unsupported")
	}
	raw, err := json.Marshal(grant)
	if err != nil {
		return out, err
	}
	hash := sha256.Sum256(raw)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return out, err
	}
	return SignedDiskGrant{Payload: raw, Signature: signature}, nil
}
