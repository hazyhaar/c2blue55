#!/usr/bin/env bash
# verify-standalone.sh — Oracle mécanique d'autonomie et de reproductibilité pour c2blue55.
# Prouve qu'un clone isolé compile et passe ses tests sans monorepo ni accès réseau.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TMP_DIR="$(mktemp -d /tmp/c2blue-standalone-verify-XXXXXX)"
cleanup() {
    python3 -c "import shutil, sys; shutil.rmtree(sys.argv[1], ignore_errors=True)" "${TMP_DIR}" || true
}
trap cleanup EXIT

echo "==> Copie de l'arbre dans un répertoire isolé: ${TMP_DIR}"
cp -r "${REPO_DIR}/." "${TMP_DIR}/"

cd "${TMP_DIR}"

echo "==> 1. Compilation autonome pure Go (GOWORK=off, GOPROXY=off)..."
GOWORK=off GOPROXY=off go build -buildvcs=false ./...

echo "==> 2. Analyse statique (go vet)..."
GOWORK=off GOPROXY=off go vet ./...

echo "==> 3. Tests unitaires goclassifier..."
GOWORK=off GOPROXY=off go test -race -count=1 ./internal/goclassifier

echo "==> 4. Tests unitaires internal/engine..."
GOWORK=off GOPROXY=off go test -race -count=1 ./internal/engine

echo "==> 5. Banc et tests d'intégration du paquet racine..."
GOWORK=off GOPROXY=off go test -race -count=1 .

echo "==> 6. Tests forgerie c2forge..."
GOWORK=off GOPROXY=off go test -race -count=1 ./cmd/c2forge

echo "==> 7. Tests outils annexes (guard, web, socagent)..."
GOWORK=off GOPROXY=off go test -race -count=1 ./cmd/c2blue-mcp-guard ./cmd/c2blue-arena-web ./socagent

echo "==> 8. Tests démon c2agent (pure Go, CGO_ENABLED=0)..."
GOWORK=off GOPROXY=off CGO_ENABLED=0 GOAMD64=v3 go test -count=1 ./cmd/c2agent

echo "==> [SUCCÈS] c2blue55 est 100% autonome et reproductible."
