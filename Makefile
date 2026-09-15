# Makefile — c2blue55 Go module (Wittgenstein AI Tournament)
.PHONY: test test-race bench build download-model clean

test:
	GOWORK=off go test -race -count=1 . ./socagent ./cmd/c2blue-mcp-guard ./cmd/c2blue-arena-web
	GOWORK=off CGO_ENABLED=0 GOAMD64=v3 go test -count=1 ./cmd/c2agent

test-race:
	GOWORK=off go test -race -count=1 . ./socagent ./cmd/c2blue-mcp-guard ./cmd/c2blue-arena-web

bench:
	GOWORK=off go test -bench=. -benchmem -run=^$$ .

build:
	@mkdir -p bin
	GOWORK=off CGO_ENABLED=0 GOAMD64=v3 go build -ldflags="-s -w" -o bin/c2agent ./cmd/c2agent
	GOWORK=off go build -ldflags="-s -w" -o bin/c2blue-mcp-guard ./cmd/c2blue-mcp-guard
	GOWORK=off go build -ldflags="-s -w" -o bin/c2blue-arena-web ./cmd/c2blue-arena-web

download-model:
	@mkdir -p models
	@echo "Téléchargement de Qwen2.5-0.5B-Instruct Q4_K_M (468 Mo)..."
	curl -L -o models/qwen2.5-0.5b-instruct-q4_k_m.gguf \
		https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf

clean:
	rm -rf bin/
