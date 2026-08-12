.PHONY: server test fmt vet

# TODO: pnpm -C dashboard build once dashboard exists
server:
	go build -o bin/funcbox-server ./cmd/funcbox-server

test:
	go test ./...

fmt:
	gofmt -l .

vet:
	go vet ./...
