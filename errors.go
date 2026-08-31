// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package axtverify

import "errors"

// ErrVerification marks a failed cryptographic check: a checkpoint,
// consistency or inclusion proof that does not stand up.
// Every one of these is a finding about the log, not about this tool, and
// callers separate them from transport trouble on that basis.
var ErrVerification = errors.New("verification failed")

type verificationError struct{ err error }

func (e *verificationError) Error() string { return e.err.Error() }
func (e *verificationError) Unwrap() []error {
	return []error{ErrVerification, e.err}
}

func verr(err error) error { return &verificationError{err} }
