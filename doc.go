// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

// Package axtverify verifies that an organization's Access Transparency
// events are included in its transparency log, using only trust decided
// locally: the log key this release ships, or one the operator supplies. The
// cmd/axt-verify tool is a thin command line over it.
package axtverify
