# Makefile — c2blue55 Go module
.PHONY: test bench test-race clean

test:
	go test -v ./...

test-race:
	GOEXPERIMENT=simd go test -race -v ./...

bench:
	go test -benchmem -bench=. ./...

clean:
	go clean
