package scriptcatalog

import _ "embed"

// Generated scripts include the P2-02 protection/holder implementation. Pins
// cover every byte, including the local signature verifier and journal engine.
//
//go:embed disk-approved-quarantine-v1.py
var diskQuarantine []byte

//go:embed disk-approved-delete-v1.py
var diskDelete []byte

//go:embed disk-quarantine-expire-v1.py
var diskExpire []byte

//go:embed disk-quarantine-restore-v1.py
var diskRestore []byte

func IsDiskAction(id string) bool {
	switch id {
	case "disk-approved-quarantine-v1", "disk-approved-delete-v1", "disk-quarantine-expire-v1", "disk-quarantine-restore-v1":
		return true
	}
	return false
}

func DiskActionScript(action string) string {
	switch action {
	case "quarantine":
		return "disk-approved-quarantine-v1"
	case "delete":
		return "disk-approved-delete-v1"
	case "expire":
		return "disk-quarantine-expire-v1"
	case "restore":
		return "disk-quarantine-restore-v1"
	}
	return ""
}

func actionSchema() Schema {
	id := Property{Type: "string", Pattern: "^[a-zA-Z0-9_-]{1,128}$", MinLength: 1, MaxLength: 128}
	digest := Property{Type: "string", Pattern: "^sha256:[a-f0-9]{64}$", MinLength: 71, MaxLength: 71}
	return Schema{Type: "object", Required: []string{"manifest_id", "manifest_digest", "approval_id"}, Properties: map[string]Property{"manifest_id": id, "manifest_digest": digest, "approval_id": id}}
}
func expirySchema() Schema {
	schema := diskSchema()
	delete(schema.Properties, "scope")
	schema.Required = []string{"policy_id", "policy_digest"}
	return schema
}
