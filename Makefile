.PHONY: build test cover lint vuln fmt fmt-check tidy tidy-check verify clean

# Keep the gate above the usual project baseline while lifecycle and edge
# integration tests continue to grow in the next milestone.
COVERAGE_MIN ?= 83.0

build:
	go build ./...

test:
	go test ./... -race -count=1

cover:
	go test ./... -coverpkg=./... -coverprofile=coverage.out
	@total="$$(go tool cover -func=coverage.out | awk '/^total:/ {gsub("%", "", $$3); print $$3}')"; \
	awk -v total="$$total" -v minimum="$(COVERAGE_MIN)" 'BEGIN { \
		printf "total coverage: %.1f%% (minimum %.1f%%)\n", total, minimum; \
		if (total + 0 < minimum + 0) exit 1 \
	}'

lint:
	go vet ./...
	golangci-lint run ./...

vuln:
	govulncheck ./...

fmt:
	gofmt -w .
	@which goimports >/dev/null 2>&1 && goimports -w -local github.com/yaop-labs/reef . || true

fmt-check:
	@files="$$(gofmt -l .)"; \
	if [ -n "$$files" ]; then \
		echo "files require gofmt:"; \
		echo "$$files"; \
		exit 1; \
	fi

tidy:
	go mod tidy

tidy-check:
	go mod tidy -diff

verify: fmt-check tidy-check build test cover lint vuln

clean:
	go clean -testcache
	rm -f coverage.out
