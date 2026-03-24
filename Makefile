.PHONY: build test lint clean scan-demo

build:
	go build -o bin/oxvault ./cmd/

test:
	go test ./...

lint:
	golangci-lint run

clean:
	rm -rf bin/

scan-demo:
	@echo "=== Scanning tool-poisoning example ==="
	./bin/oxvault scan ./examples/vulnerable-servers/tool-poisoning/ --skip-manifest || true
	@echo ""
	@echo "=== Scanning cmd-injection example ==="
	./bin/oxvault scan ./examples/vulnerable-servers/cmd-injection/ --skip-manifest || true
