// SPDX-License-Identifier: MIT

// Package version carries build-time metadata embedded via -ldflags.
package version

import "fmt"

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String returns "<Version> (<Commit> built <Date>)".
func String() string {
	return fmt.Sprintf("%s (%s built %s)", Version, Commit, Date)
}
