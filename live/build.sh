#!/usr/bin/env bash
# Construit l'image live bootable de projetCyber via Debian live-build.
# Prérequis : Debian/Ubuntu + `live-build` + `golang` (voir README.md).
# NON booté-testé : recette d'après la doc live-build, à valider au banc.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="$HERE/config/includes.chroot/opt/projetcyber"

echo "[1/3] Compilation des binaires statiques (CGO_ENABLED=0)…"
mkdir -p "$BIN"
( cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o "$BIN/orchestrator" ./cmd/orchestrator )
( cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o "$BIN/questionnaire" ./cmd/questionnaire )
# On embarque les échantillons pour une démo hors ligne ; à retirer en prod.
rm -rf "$BIN/sample" && cp -r "$ROOT/sample" "$BIN/sample"

echo "[2/3] Configuration live-build…"
cd "$HERE"
# boot=live components : chaîne live standard ; toram : charge tout en RAM
# (stateless, clé retirable) ; noeject : n'éjecte pas au shutdown.
lb config \
  --distribution bookworm \
  --architectures amd64 \
  --binary-images iso-hybrid \
  --debian-installer none \
  --bootappend-live "boot=live components toram noeject hostname=projetcyber"

echo "[3/3] Construction de l'ISO (sudo requis)…"
sudo lb build

echo
echo "OK — ISO : $HERE/live-image-amd64.hybrid.iso"
echo "Écrire sur clé : sudo dd if=$HERE/live-image-amd64.hybrid.iso of=/dev/sdX bs=4M status=progress && sync"
