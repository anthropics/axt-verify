# Third-party licenses

Output of `go-licenses report ./...` (github.com/google/go-licenses) run in this tree, with the module version from `go list -m all`.
The first row is this module itself; the other rows are every module compiled into the `axt-verify` binary.
The full license texts ship in `THIRD_PARTY_NOTICES/` (`go-licenses save ./cmd/axt-verify --save_path=THIRD_PARTY_NOTICES`).

| Module | Version | License | License URL |
|---|---|---|---|
| github.com/anthropics/axt-verify | (this release) | Apache-2.0 | https://github.com/anthropics/axt-verify/blob/HEAD/LICENSE |
| github.com/transparency-dev/formats | v0.0.0-20251017110053-404c0d5b696c | Apache-2.0 | https://github.com/transparency-dev/formats/blob/404c0d5b696c/LICENSE |
| github.com/transparency-dev/merkle | v0.0.2 | Apache-2.0 | https://github.com/transparency-dev/merkle/blob/v0.0.2/LICENSE |
| golang.org/x/mod (packages sumdb/note, sumdb/tlog) | v0.35.0 | BSD-3-Clause | https://cs.opensource.google/go/x/mod/+/v0.35.0:LICENSE |

`github.com/transparency-dev/formats/note` includes `note_cosigv1.go`, a file that carries a Go Authors BSD-style header inside the Apache-2.0 module; the BSD-3-Clause text it refers to is the one shipped under `THIRD_PARTY_NOTICES/golang.org/x/mod/sumdb/note/`.

The Go standard library and runtime (including the `vendor/golang.org/x/{crypto,net,sys,text}` packages bundled with the Go distribution) are BSD-3-Clause, Copyright The Go Authors.

Modules present in the module graph but not compiled into any package of this tree (test-only dependencies of the modules above; not reported by `go-licenses report ./...`): github.com/google/go-cmp v0.7.0 (BSD-3-Clause), golang.org/x/tools v0.43.0 (BSD-3-Clause).
