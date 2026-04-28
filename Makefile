BIN := bin/oxvault
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo "dev")
LDFLAGS := -X github.com/oxvault/scanner/internal/version.Version=$(VERSION)

ifeq ($(OS),Windows_NT)
	BIN := bin/oxvault.exe
endif

.PHONY: all build run test lint clean scan-demo check

all: build test

build:
	@go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/

run:
	@go run ./cmd/

test:
	@go test ./... -v

lint:
	@golangci-lint run

# Run before pushing — build + test + lint
check: build test lint

clean:
	@rm -rf bin/ .oxvault/

scan-demo: build
	@echo "=== Scanning tool-poisoning example ==="
	@./$(BIN) scan ./examples/vulnerable-servers/tool-poisoning/ --skip-manifest || true
	@echo ""
	@echo "=== Scanning cmd-injection example ==="
	@./$(BIN) scan ./examples/vulnerable-servers/cmd-injection/ --skip-manifest || true
	@echo ""
	@echo "=== AIBOM v0.4 — pickle RCE ==="
	@./$(BIN) scan ./examples/vulnerable-models/pickle-rce/weights.pkl || true
	@echo ""
	@echo "=== AIBOM v0.4 — safetensors header overflow ==="
	@./$(BIN) scan ./examples/vulnerable-models/safetensors-overflow/model.safetensors || true
	@echo ""
	@echo "=== AIBOM v0.4 — ONNX malformed protobuf ==="
	@./$(BIN) scan ./examples/vulnerable-models/onnx-malformed/model.onnx || true
	@echo ""
	@echo "=== AIBOM v0.4 — model card prompt injection ==="
	@./$(BIN) scan ./examples/vulnerable-models/modelcard-poisoned/ || true
