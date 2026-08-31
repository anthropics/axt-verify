// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"io"
)

// newFlagSet is shared so the command may appear before or after its flags:
// `axt-verify checkpoint --org …` is how these invocations get written.
func newFlagSet(stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("axt-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parseCommandArgs also returns the positional arguments after the command —
// `events FILE` has one. Flags may sit on either side of the command, because
// that is how these invocations get written:
// `axt-verify checkpoint --from y.ckpt --save t.ckpt`.
func parseCommandArgs(fs *flag.FlagSet, args []string) (string, []string, int) {
	// Everything after a "--" is positional, once and for all: a filename
	// that looks like a flag (from a glob, say) must not be able to replace
	// the trust anchor this release ships.
	var literal []string
	for i, a := range args {
		if a == "--" {
			args, literal = args[:i], args[i+1:]
			break
		}
	}
	var positional []string
	for remaining := args; ; {
		if err := fs.Parse(remaining); err != nil {
			return "", nil, exitUsage
		}
		remaining = fs.Args()
		if len(remaining) == 0 {
			break
		}
		positional = append(positional, remaining[0])
		remaining = remaining[1:]
	}
	positional = append(positional, literal...)
	// An empty positional is a command this tool does not have — usually an
	// unset shell variable — and must never be mistaken for "no command
	// given" and land on exit 0 having verified nothing.
	if len(positional) == 0 || positional[0] == "" {
		fs.Usage()
		return "", nil, exitUsage
	}
	return positional[0], positional[1:], exitOK
}
