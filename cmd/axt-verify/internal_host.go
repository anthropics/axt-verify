// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

//go:build axtverify_internal

package main

import "os"

// internalBaseURL points the tool at a deployment that is not production.
// It exists only in builds made with -tags axtverify_internal, which is how
// the operators of this service run their own acceptance checks. No release
// build carries this file, so for a customer the override is not merely
// unset: it is absent from the binary.
var internalBaseURL = readInternalBaseURL()

func readInternalBaseURL() string { return os.Getenv("AXT_VERIFY_API_BASE_URL") }
