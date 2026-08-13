.PHONY: server funcbox test fmt vet

# Builds the dashboard (server/dashboard/ -> server/internal/dashboard/dist
# server/internal/dashboard's go:embed always has a real dist/server.js to
# embed -- release CI uses this exact same target, not a separate pipeline.
#
# The server binary lives in its own module (server/go.mod; see
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
