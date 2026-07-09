.PHONY: build test cover lint fmt tidy clean

build:
	go build ./...

test:
	go test ./... -race -count=1

cover:
	go test ./tlsconf/ ./bearer/ -cover

lint:
	go vet ./...
	golangci-lint run ./...

fmt:
	gofmt -w .
	@which goimports >/dev/null 2>&1 && goimports -w -local github.com/yaop-labs/reef . || true

tidy:
	go mod tidy

clean:
	go clean -testcache
