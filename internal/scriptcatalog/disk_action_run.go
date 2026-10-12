package scriptcatalog

import (
	"context"
	"encoding/json"
	"io"
)

// DiskActionRun supplies a signed grant, never a caller-supplied filesystem
// manifest or policy. Renew must fetch new authority from the Hub, with the
// assigned machine credential, at every helper mutation boundary.
// The credential itself is not passed into the child interpreter.
type DiskActionRun struct {
	Sink          io.Writer
	MachineID     string
	JobID         string
	Authorization json.RawMessage
	Renew         func(context.Context) (json.RawMessage, error)
}
