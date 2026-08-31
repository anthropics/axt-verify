// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

//go:build !axtverify_internal

package main

// internalBaseURL is empty in every release build: a customer's copy of
// axt-verify talks to the production API and has no way to be pointed
// anywhere else. The twin of this file, built only under
// -tags axtverify_internal, is what our own acceptance runs use.
var internalBaseURL = ""
