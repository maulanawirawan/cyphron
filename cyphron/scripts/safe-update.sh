#!/usr/bin/env bash
# safe-update Cyphron (U10) — update repo dengan gerbang suite hijau.
#
# Alur: suite HARI INI dijalankan dulu (baseline harus hijau) -> fetch ->
# pastikan fast-forward -> pull --ff-only -> suite ULANG -> bila gagal,
# rollback otomatis ke HEAD lama. Scratch/ & kb/data/ tak pernah tersentuh.
#
# Pemakaian:  bash scripts/safe-update.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
OLD_HEAD="$(git rev-parse HEAD)"
echo "[safe-update] repo : $REPO_ROOT"
echo "[safe-update] branch: $BRANCH (HEAD $OLD_HEAD)"

run_suite() {
  echo "[safe-update] menjalankan suite..."
  ( cd cyphron && python -m unittest discover -s tests 2>&1 | tail -2 )
}

echo "[safe-update] gerbang 1: suite pada HEAD sekarang wajib hijau"
run_suite

git fetch origin "$BRANCH"

if ! git merge-base --is-ancestor HEAD "origin/$BRANCH"; then
  echo "[safe-update] local HEAD terdivergensi dari origin/$BRANCH — " \
       "safe-update menolak merge otomatis. Ratakan manual (rebase) dulu."
  exit 1
fi

if [ "$(git rev-parse HEAD)" = "$(git rev-parse "origin/$BRANCH")" ]; then
  echo "[safe-update] sudah versi terbaru — tidak ada yang di-update"
  exit 0
fi

git pull --ff-only origin "$BRANCH"

echo "[safe-update] gerbang 2: suite pada HEAD baru"
if run_suite; then
  echo "[safe-update] BERHASIL: $(git rev-parse HEAD)"
  exit 0
fi

echo "[safe-update] suite GAGAL pada HEAD baru — ROLLBACK otomatis"
git reset --hard "$OLD_HEAD"
run_suite || true
echo "[safe-update] dikembalikan ke $OLD_HEAD — laporkan ke pemilik repo"
exit 1
