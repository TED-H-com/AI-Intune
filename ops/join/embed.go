// Package join embeds the public, secret-free Linux bootstrap script.
package join

import _ "embed"

//go:embed join.sh
var Script string
