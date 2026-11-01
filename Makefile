# Makefile — c2blue55 Go module (Wittgenstein AI Tournament)
.PHONY: test test-race bench build download-model clean

PKGS_RACE := . \
	./audit-evidence/probes \
	./cmd/c2blue-arena-web \
	./cmd/c2blue-mcp-guard \
	./cmd/c2cinetique \
	./cmd/c2dnslab-emit \
	./cmd/c2forge \
	./cmd/c2icmplab-emit \
	./cmd/c2icmplab-respond \
	./cmd/c2multiagent \
	./cmd/c2scanner \
	./cmd/dnslab-auth \
	./internal/dnslab \
	./internal/engine \
	./internal/goclassifier \
	./internal/icmplab \
	./internal/probes \
	./internal/projlearn \
	./socagent

PKGS_NORACE := ./internal/cinetique ./cmd/c2agent

test:
	GOEXPERIMENT=simd go test -race -count=3 $(PKGS_RACE)
	GOEXPERIMENT=simd go test -count=3 $(PKGS_NORACE)

test-race:
	GOEXPERIMENT=simd go test -race -count=3 $(PKGS_RACE)

bench:
	GOEXPERIMENT=simd go test -bench=. -benchmem -run=^$$ .

build:
	@mkdir -p bin
	CGO_ENABLED=0 GOAMD64=v3 GOEXPERIMENT=simd go build -ldflags="-s -w" -o bin/c2agent ./cmd/c2agent
	GOEXPERIMENT=simd go build -ldflags="-s -w" -o bin/c2blue-mcp-guard ./cmd/c2blue-mcp-guard
	GOEXPERIMENT=simd go build -ldflags="-s -w" -o bin/c2blue-arena-web ./cmd/c2blue-arena-web

download-model:
	@mkdir -p models
	@echo "Téléchargement de Qwen2.5-0.5B-Instruct Q4_K_M (468 Mo)..."
	curl -L -o models/qwen2.5-0.5b-instruct-q4_k_m.gguf \
		https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf

clean:
	rm -rf bin/
