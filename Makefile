.PHONY: server funcbox test fmt vet

# Builds the dashboard (dashboard/ -> internal/dashboard/dist via pnpm +
# esbuild; tmp/09-dashboard.md §9.6) before the Go binary, so
# internal/dashboard's go:embed always has a real dist/server.js to embed --
# release CI uses this exact same target, not a separate pipeline.
server:
	pnpm -C dashboard install --frozen-lockfile
	pnpm -C dashboard build
	go build -o bin/funcbox-server ./cmd/funcbox-server

funcbox:
	go build -o bin/funcbox ./cmd/funcbox

test:
	go test ./...

fmt:
	gofmt -l .

vet:
	go vet ./...
