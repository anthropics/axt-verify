# Contributing to axt-verify

Thank you for your interest in contributing. This document explains the process and what to expect.

## Contributor License Agreement

Before we can accept your contribution, you must sign our Contributor License Agreement. The CLA bot will prompt you on your first pull request; sign by replying to the bot's comment. This is a one-time requirement per contributor.

If you are contributing on behalf of your employer and your employer may have rights in your contribution, your employer should sign our Corporate CLA. Contact opensource-cla@anthropic.com to arrange this.

## Getting started

### Prerequisites

Go 1.26 or later. There are no other dependencies beyond the Go toolchain; the module's dependencies are fetched by `go build`.

### Development setup

```
git clone https://github.com/anthropics/axt-verify.git
cd axt-verify
go build ./...
```

### Running tests

```
go test ./...
```

## How to contribute

### Reporting issues

Open an issue on GitHub. When reporting a bug, include steps to reproduce, expected behavior, actual behavior, environment details, and relevant logs or error messages. Do not include your Compliance API key, event contents, or other data from your organization's feed.

### Submitting pull requests

1. Fork the repository and create a branch from main.
2. Make your changes, following the code style guidelines below.
3. Add or update tests as appropriate.
4. Update documentation if your change affects public APIs or user-facing behavior.
5. Run the test suite and confirm all tests pass.
6. Open a pull request with a clear description of the change and its motivation.

Changes to what the verifier checks — the leaf canonicalization, the checkpoint and proof verification, the built-in key, the flags, exit codes, state file and `--json` report fields — are compatibility promises to every organization running the tool; please open an issue to discuss them before sending a pull request.

## Code style

Standard Go: run `gofmt` and `go vet ./...` before submitting.

## Review process

All pull requests require review from at least one maintainer before merging. We aim to provide initial feedback within one week.

## Questions

Open a discussion on GitHub.
