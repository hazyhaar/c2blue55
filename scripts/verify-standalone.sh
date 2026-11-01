#!/usr/bin/env bash
# verify-standalone.sh — Oracle mécanique d'autonomie et de reproductibilité pour c2blue55.
# Prouve qu'une copie isolée matérialisant vendor/ et purgée de toute directive replace
# compile et passe ses suites autonomes sans accès réseau ni résolution sur l'hôte.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TMP_DIR="$(mktemp -d /tmp/c2blue-standalone-verify-XXXXXX)"
cleanup() {
    python3 -c "import shutil, sys; shutil.rmtree(sys.argv[1], ignore_errors=True)" "${TMP_DIR}" || true
}
trap cleanup EXIT

echo "==> Copie de l'arbre dans un répertoire isolé: ${TMP_DIR}"
python3 - "${REPO_DIR}" "${TMP_DIR}" <<'PY'
import os, shutil, sys
src, dst = sys.argv[1], sys.argv[2]
for name in os.listdir(src):
    if name == ".git":
        continue
    s = os.path.join(src, name)
    d = os.path.join(dst, name)
    if os.path.isdir(s) and not os.path.islink(s):
        shutil.copytree(s, d, symlinks=True)
    else:
        shutil.copy2(s, d, follow_symlinks=False)
PY

cd "${TMP_DIR}"
git init -q

if [ ! -d vendor ]; then
    echo "==> 0. Matérialisation de vendor/ dans la copie isolée..."
    GOEXPERIMENT=simd go mod vendor
fi

echo "==> 0b. Retrait des directives replace de go.mod et normalisation de vendor/modules.txt..."
python3 - <<'PY'
import json, pathlib, subprocess

meta = json.loads(subprocess.check_output(["go", "mod", "edit", "-json"]).decode("utf-8"))
for rep in meta.get("Replace") or []:
    old = rep["Old"]["Path"]
    ver = rep["Old"].get("Version", "")
    spec = f"{old}@{ver}" if ver else old
    subprocess.check_call(["go", "mod", "edit", f"-dropreplace={spec}"])

meta_after = json.loads(subprocess.check_output(["go", "mod", "edit", "-json"]).decode("utf-8"))
if meta_after.get("Replace"):
    raise SystemExit(f"directives replace résiduelles dans go.mod: {meta_after['Replace']}")

mod_txt = pathlib.Path("vendor/modules.txt")
cleaned_lines = []
for line in mod_txt.read_text(encoding="utf-8").splitlines():
    if line.startswith("# ") and " => " in line:
        left = line.split(" => ", 1)[0]
        parts = left.split()
        if len(parts) == 2:
            continue
        line = left
    cleaned_lines.append(line)
mod_txt.write_text("\n".join(cleaned_lines) + "\n", encoding="utf-8")
PY

echo "==> 1. Compilation autonome hors ligne (GOPROXY=off, GOSUMDB=off, -mod=vendor)..."
GOPROXY=off GOSUMDB=off GOEXPERIMENT=simd go build -mod=vendor -buildvcs=false ./...

echo "==> 2. Analyse statique hors ligne (go vet -mod=vendor)..."
GOPROXY=off GOSUMDB=off GOEXPERIMENT=simd go vet -mod=vendor ./...

echo "==> 3. Tests unitaires autonomes sans corpus externe..."
SUITES=(
    ./internal/goclassifier
    ./internal/icmplab
    ./internal/probes
    ./cmd/c2blue-mcp-guard
    ./cmd/c2blue-arena-web
    ./cmd/c2scanner
    ./cmd/c2multiagent
    ./socagent
)
if [ -d "wittgenstein/redhost_lab" ]; then
    SUITES+=(./internal/dnslab)
fi
GOPROXY=off GOSUMDB=off GOEXPERIMENT=simd go test -mod=vendor -race -count=1 "${SUITES[@]}"

echo "==> [SUCCÈS] c2blue55 compile et passe ses suites autonomes hors ligne en mode vendor sans replace."
