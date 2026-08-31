// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package axtverify_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/anthropics/axt-verify"
)

const (
	orgUUID = "25f6429a-3293-49bf-afed-cb312911554b"
	origin  = "axt.anthropic.com/" + orgUUID
)

func requireVerification(t *testing.T, err error, substr string) {
	t.Helper()
	if !errors.Is(err, axtverify.ErrVerification) {
		t.Fatalf("err = %v, want ErrVerification", err)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("err = %q, want it to mention %q", err, substr)
	}
}
