#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  Tool GetContact — Instalasi Universal & Jalankan (v1.2)
#  ✅ Semua otomatis terinstal: python, git, pip, requests, cryptography
#  ✅ Mendukung Termux / Linux (apt, dnf, pacman) / macOS
#  ✅ Perbaikan khusus Termux:
#     • Lewati upgrade pip (Dilarang di Termux)
#     • cryptography → pkg install python-cryptography
#     • apt/pkg lock sibuk → tunggu + coba ulang (tutup sesi lain)
#  ✅ Setelah setup, tool akan otomatis berjalan
#
#  Penggunaan:
#    bash setup.sh            → instalasi semua + jalankan tool
#    bash setup.sh --no-run   → hanya instalasi, jangan jalankan tool
# ═══════════════════════════════════════════════════════════════
set -e

RUN_TOOL=1
if [ "$1" = "--no-run" ]; then RUN_TOOL=0; fi

CYAN='\033[96m'; GREEN='\033[92m'; YELLOW='\033[93m'; RED='\033[91m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}  ✅ $1${RESET}"; }
info() { echo -e "${YELLOW}  ℹ️  $1${RESET}"; }
err()  { echo -e "${RED}  ❌ $1${RESET}"; }

echo -e "${CYAN}══════════════════════════════════════════════${RESET}"
echo -e "${CYAN}${BOLD}  📞 Tool GetContact — Setup & Jalankan${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════${RESET}"

# Pindah ke direktori skrip (bisa dijalankan dari mana saja)
cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")"

# Deteksi Lingkungan Sistem
if [ -n "$PREFIX" ] && echo "$PREFIX" | grep -q "com.termux"; then
  ENV="termux"
elif [ -f /etc/os-release ] && grep -qiE "ubuntu|debian|kali|pop|linuxmint" /etc/os-release 2>/dev/null; then
  ENV="debian"
elif command -v dnf >/dev/null 2>&1; then
  ENV="fedora"
elif command -v pacman >/dev/null 2>&1; then
  ENV="arch"
elif [ "$(uname)" = "Darwin" ]; then
  ENV="macos"
else
  ENV="unknown"
fi

echo -e "  ${DIM}Lingkungan: ${RESET}${BOLD}$ENV${RESET}"
echo ""

has_py()  { command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; }
has_git() { command -v git >/dev/null 2>&1; }

# Helper untuk retry jika apt/pkg sedang terkunci (lock)
pkg_run() {
  local n=0
  while [ $n -lt 10 ]; do
    if "$@" 2>&1; then
      return 0
    fi
    n=$((n+1))
    if [ $n -lt 10 ]; then
      echo -e "${YELLOW}  ⏳ apt/pkg sedang sibuk (mungkin sesi lain sedang berjalan) — mencoba ulang $n/10...${RESET}"
      sleep 3
    fi
  done
  return 1
}

# ── Langkah 1: Periksa/Instal Python + Git ─────────────────────
echo -e "${YELLOW}[1/4] Memeriksa & Menginstal Python + Git...${RESET}"

case "$ENV" in
  termux)
    if ! has_py || ! has_git; then
      pkg_run pkg update -y || { err "pkg update gagal — tutup sesi Termux lainnya lalu coba lagi"; exit 1; }
      has_py  || pkg_run pkg install -y python || { err "Gagal menginstal python"; exit 1; }
      has_git || pkg_run pkg install -y git || { err "Gagal menginstal git"; exit 1; }
    fi
    ;;
  debian)
    if ! has_py || ! has_git; then
      pkg_run sudo apt update -y || true
      has_py  || sudo apt install -y python3 python3-pip
      has_git || sudo apt install -y git
    fi
    ;;
  fedora)
    has_py  || sudo dnf install -y python3 python3-pip || true
    has_git || sudo dnf install -y git || true
    ;;
  arch)
    has_py  || sudo pacman -Sy --noconfirm python python-pip || true
    has_git || sudo pacman -Sy --noconfirm git || true
    ;;
  macos)
    command -v brew >/dev/null 2>&1 || { info "Menginstal Homebrew..."; /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; }
    has_py  || brew install python
    has_git || brew install git
    ;;
  *)
    err "Sistem operasi tidak dikenal — silakan instal python3 dan git secara manual."
    exit 1
    ;;
esac
ok "Python & Git siap"

# ── Langkah 2: Pengecekan pip ─────────────────────────────────
echo -e "${YELLOW}[2/4] Memeriksa pip...${RESET}"
if [ "$ENV" = "termux" ]; then
  info "Termux terdeteksi — Upgrade pip DILEWATI (pip upgrade dilarang di Termux, dikelola oleh paket python-pip)"
else
  if command -v pip3 >/dev/null 2>&1; then
    pip3 install --upgrade pip || true
  elif command -v python3 >/dev/null 2>&1; then
    python3 -m pip install --upgrade pip || true
  fi
fi
ok "pip siap"

# ── Langkah 3: Menginstal Pustaka Python (requests, cryptography) ─
echo -e "${YELLOW}[3/4] Menginstal pustaka Python (requests, cryptography)...${RESET}"

PIP=""
command -v pip3 >/dev/null 2>&1 && PIP="pip3"
[ -z "$PIP" ] && command -v pip >/dev/null 2>&1 && PIP="pip"
[ -z "$PIP" ] && command -v python3 >/dev/null 2>&1 && PIP="python3 -m pip"
[ -z "$PIP" ] && command -v python >/dev/null 2>&1 && PIP="python -m pip"

if [ -z "$PIP" ]; then
  err "pip tidak ditemukan!"; exit 1
fi

if [ "$ENV" = "termux" ]; then
  if $PIP install -r requirements.txt >/dev/null 2>&1; then
    ok "Pustaka terinstal via pip"
  else
    info "Gagal menginstal cryptography via pip (Termux) — menginstal via pkg..."
    pkg_run pkg install -y python-cryptography || { err "Gagal menginstal python-cryptography"; exit 1; }
    $PIP install requests || true
    ok "Pustaka terinstal via pkg + pip"
  fi
else
  $PIP install -r requirements.txt
  ok "Pustaka siap"
fi

# ── Langkah 4: Periksa File Tool & Jalankan ────────────────────
echo -e "${YELLOW}[4/4] Memeriksa file tool...${RESET}"
if [ ! -f gtc.py ]; then
  err "File Xtools.py tidak ditemukan!"; exit 1
fi
ok "Xtools.py siap"

echo ""
echo -e "${GREEN}${BOLD}═══ Instalasi Selesai! ═══${RESET}"
echo ""

if [ "$RUN_TOOL" = "1" ]; then
  echo -e "${CYAN}Tool sedang dimulai... (Tekan angka 0 di menu untuk keluar)${RESET}"
  echo ""
  if command -v python3 >/dev/null 2>&1; then
    python3 Xtools.py
  else
    python Xtools.py
  fi
else
  echo -e "${CYAN}Cara menjalankan tool secara manual:${RESET}"
  echo "  python3 Xtools.py"
fi
