#!/usr/bin/env bash
# Go SDK checks: gofmt, go vet, staticcheck (if installed), go test -race,
# and a build of the e2e status app and the template differential.
set -euo pipefail
cd "$(dirname "$0")/.."
# The system `go` may be gccgo 1.18; prefer the pinned toolchain when present.
if [ -x "$HOME/.local/go-1.27.3/bin/go" ]; then
  export PATH="$HOME/.local/go-1.27.3/bin:$PATH"
fi
go version
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
  echo "gofmt needed:" "$unformatted" >&2
  exit 1
fi
go vet ./...
if command -v staticcheck >/dev/null; then
  staticcheck ./...
else
  echo "staticcheck not installed; skipping (go install honnef.co/go/tools/cmd/staticcheck@latest)"
fi
go test -race -count=1 ./...
DYNV_VECTOR_COUNTS=1 go test -count=1 -v -run 'TestPrimitives|TestSelfCases|TestTemplateVectors|TestBaseURLVectors' . | grep '^vectors '
go build ./...
go build -o "${TMPDIR:-/tmp}/dynv-go-e2e-app" ./e2e/app
echo "go sdk: ok"
