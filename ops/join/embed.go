// Package join embeds the public, secret-free bootstrap scripts.
package join

import _ "embed"

//go:embed join.sh
var Script string

//go:embed join.ps1
var PowerShell string
