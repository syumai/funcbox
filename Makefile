.PHONY: server funcbox test fmt vet

# TODO: pnpm -C dashboard build once dashboard exists
server:
	go build -o bin/funcbox-server ./cmd/funcbox-server

funcbox:
	go build -o bin/funcbox ./cmd/funcbox

test:
	go test ./...

fmt:
	gofmt -l .

vet:
	go vet ./...
