# AGENTS.md

Rules for anyone (people or AI agents) changing this repository.

## Go version: always the latest stable release

The code must always build and run on the **latest stable Go release**
(the first entry of <https://go.dev/dl/?mode=json>). There is no "supported
older version".

- `go.mod` has a `go 1.X.Y` line with the full latest patch version, and the
  Dockerfile builder is `FROM golang:1.X.Y-alpine AS build` with the same version.
  Always change both together.
- Builds use exactly that toolchain: `GOTOOLCHAIN=local` in the Dockerfile and
  in CI. Don't add a `toolchain` line to `go.mod`, and don't rely on toolchain
  auto-download.
- The CI job `go-version` (`.github/scripts/check-latest-go.sh`) fails when
  `go.mod` or the Dockerfile lags behind go.dev. It runs on every push, pull
  request and weekly (Monday), and the image is not built or published
  while it is red.
- When Go releases a new version (including a patch release), update in a
  dedicated PR:
  1. `go mod edit -go=1.X.Y` and update the `FROM golang:` tag in the Dockerfile.
  2. `go mod tidy`, then run the checks below with the new toolchain.
  3. If the new version flags new `go vet`/staticcheck warnings or deprecations,
     fix them in the same PR instead of pinning the old version.
- Pinned dev tools (`STATICCHECK_VERSION`, `GOVULNCHECK_VERSION` in
  `ci.yml`) must support the current Go; bump them when they don't.

## Checks before pushing

Run the same checks CI does:

```sh
go mod tidy && git diff --exit-code go.mod go.sum
gofmt -l .                       # must print nothing
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@2026.2.2 ./...
go test -race -count=1 -shuffle=on ./...
```

CI also fails if test coverage drops below `MIN_COVERAGE` in `ci.yml`. New
code needs tests; security checks (scopes, OAuth allowlists, rotation)
need tests for the success case and for every refusal.
