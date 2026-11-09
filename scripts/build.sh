#!/bin/sh
# Build and check the model. Used locally and in CI. Go standard library only.
#   scripts/build.sh test            gofmt, go vet, go test (a skipped test fails)
#   scripts/build.sh results [dir]   regenerate results/ (or dir) + SHA256SUMS
set -eu
export GOFLAGS=-mod=mod GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=0
mkdir -p build
case "${1:-}" in
  test)
    fmt=$(gofmt -l src tests)
    if [ -n "$fmt" ]; then echo "gofmt needed: $fmt" >&2; exit 1; fi
    go vet ./...
    status=0
    go test -count=1 -v ./... > build/test.log 2>&1 || status=$?
    cat build/test.log
    if [ "$status" -ne 0 ]; then exit "$status"; fi
    if grep -q -e '--- SKIP' build/test.log; then echo "skipped tests count as failures" >&2; exit 1; fi
    pass=$(grep -c -e '^--- PASS' build/test.log || true)
    echo "tests passed: $pass" ;;
  results)
    out=${2:-results}
    mkdir -p "$out"
    go build -trimpath -o build/rprmodel ./src/cmd/rprmodel
    ./build/rprmodel results fixtures/cases.tsv "$out"
    (cd "$out" && sha256sum cases.tsv sweep.csv > SHA256SUMS) ;;
  *) echo "usage: $0 test|results [dir]" >&2; exit 2 ;;
esac
