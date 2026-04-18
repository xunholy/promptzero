package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// Style carries ANSI colour escapes. When stderr is not a TTY, or NO_COLOR
// is set in the environment, all fields are empty strings so callers emit
// plain text without per-site branching.
type Style struct {
	reset, bold, dim, red, green, yellow, blue, magenta, cyan, white, gray string
}

// newStyles resolves the active palette once at process start, consulting
// NO_COLOR and the stderr TTY state so later call sites can concatenate
// escapes without re-checking.
func newStyles() Style {
	if os.Getenv("NO_COLOR") != "" || !term.IsTerminal(int(os.Stderr.Fd())) {
		return Style{}
	}
	return Style{
		reset:   "\033[0m",
		bold:    "\033[1m",
		dim:     "\033[2m",
		red:     "\033[31m",
		green:   "\033[32m",
		yellow:  "\033[33m",
		blue:    "\033[34m",
		magenta: "\033[35m",
		cyan:    "\033[36m",
		white:   "\033[37m",
		gray:    "\033[90m",
	}
}

var styles = newStyles()

// Package-level shortcuts for the active Style. Declared as vars (not
// consts) so they reflect the NO_COLOR / TTY decision made at process
// start. Consumed across the cmd/promptzero package.
var (
	reset   = styles.reset
	bold    = styles.bold
	dim     = styles.dim
	red     = styles.red
	green   = styles.green
	yellow  = styles.yellow
	blue    = styles.blue
	magenta = styles.magenta
	cyan    = styles.cyan
	white   = styles.white
	gray    = styles.gray
)

// hasColor reports whether ANSI colour escapes are active this run.
func hasColor() bool { return styles.red != "" }

// printBanner renders the promptzero splash on stderr. Falls back to a
// plain-text line when colour output is disabled.
func printBanner() {
	if !hasColor() {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  promptzero — AI operator for Flipper Zero")
		fmt.Fprintln(os.Stderr)
		return
	}
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "%s%s", bold, red)
	fmt.Fprintf(os.Stderr, "  ██████╗ ██████╗  ██████╗ ███╗   ███╗██████╗ ████████╗\n")
	fmt.Fprintf(os.Stderr, "  ██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗╚══██╔══╝\n")
	fmt.Fprintf(os.Stderr, "  ██████╔╝██████╔╝██║   ██║██╔████╔██║██████╔╝   ██║   \n")
	fmt.Fprintf(os.Stderr, "  ██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔═══╝    ██║   \n")
	fmt.Fprintf(os.Stderr, "  ██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║██║        ██║   \n")
	fmt.Fprintf(os.Stderr, "  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝        ╚═╝   \n")
	fmt.Fprintf(os.Stderr, "%s%s", reset, cyan)
	fmt.Fprintf(os.Stderr, "  ███████╗███████╗██████╗  ██████╗ \n")
	fmt.Fprintf(os.Stderr, "  ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗\n")
	fmt.Fprintf(os.Stderr, "    ███╔╝ █████╗  ██████╔╝██║   ██║\n")
	fmt.Fprintf(os.Stderr, "   ███╔╝  ██╔══╝  ██╔══██╗██║   ██║\n")
	fmt.Fprintf(os.Stderr, "  ███████╗███████╗██║  ██║╚██████╔╝\n")
	fmt.Fprintf(os.Stderr, "  ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ \n")
	fmt.Fprintf(os.Stderr, "%s\n", reset)
	fmt.Fprintf(os.Stderr, "  %s%sAI-Powered Flipper Zero Operator%s\n", dim, white, reset)
	fmt.Fprintf(os.Stderr, "  %s%sno limits // no filters%s\n\n", dim, gray, reset)
}

// status writes a coloured bullet followed by msg to stderr.
func status(icon string, msg string) {
	fmt.Fprintf(os.Stderr, "  %s %s\n", icon, msg)
}

// statusOK writes a green-bullet status line (operation succeeded).
func statusOK(msg string) { status(green+"●"+reset, msg) }

// statusWarn writes a yellow-bullet status line (non-fatal issue).
func statusWarn(msg string) { status(yellow+"●"+reset, msg) }

// statusErr writes a red-bullet status line (operation failed).
func statusErr(msg string) { status(red+"●"+reset, msg) }

// statusInfo writes a blue-bullet status line (in-flight work).
func statusInfo(msg string) { status(blue+"●"+reset, msg) }

// printSeparator draws a dim horizontal rule below the status block.
func printSeparator() {
	fmt.Fprintf(os.Stderr, "  %s%s%s\n", dim, strings.Repeat("─", 52), reset)
}
