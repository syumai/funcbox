.PHONY: server funcbox test fmt vet

# Builds the dashboard (server/dashboard/ -> server/internal/dashboard/dist
# via pnpm + esbuild; tmp/09-dashboard.md §9.6) before the Go binary, so
# server/internal/dashboard's go:embed always has a real dist/server.js to
# embed -- release CI uses this exact same target, not a separate pipeline.
#
# The server binary lives in its own module (server/go.mod; see
# tmp/11-module-layout.md), so its build step uses `go -C server` rather
# than a plain `go build` from the repo root.
server:
	pnpm -C server/dashboard install --frozen-lockfile
	pnpm -C server/dashboard build
	go -C server build -o ../bin/funcbox-server ./cmd/funcbox-server

funcbox:
	go build -o bin/funcbox ./cmd/funcbox

test:
	go test ./...
	go -C server test ./...

fmt:
	gofmt -l .

vet:
	go vet ./...
	go -C server vet ./...
