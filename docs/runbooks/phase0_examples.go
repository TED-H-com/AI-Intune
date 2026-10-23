// Package runbooks embeds the reviewed disabled schedule examples.
package runbooks

import _ "embed"

//go:embed retirement-phase0-schedules.example.json
var Phase0Schedules []byte
