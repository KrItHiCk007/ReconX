#!/usr/bin/env bash
# ReconX installer — Python deps + subfinder + assetfinder + findomain
set -euo pipefail

# ── colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
info() { echo -e "${CYAN}[*]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
fail() { echo -e "${RED}[-]${RESET} $*"; }

banner() {
  echo -e "${CYAN}${BOLD}"
  echo '  ____                     __  __'
  echo ' |  _ \ ___  ___ ___  _ __ \ \/ /'
  echo ' | |_) / _ \/ __/ _ \| '"'"'_ \ \  / '
  echo ' |  _ <  __/ (_| (_) | | | | /  \'
  echo ' |_| \_\___|\___\___/|_| |_|/_/\_\'
  echo -e "${RESET}"
  echo -e "${BOLD}  ReconX — Installer${RESET}"
  echo "  ──────────────────────────────────"
  echo
}

# ── helpers ───────────────────────────────────────────────────────────────────
need_cmd() {
  if ! command -v "$1" &>/dev/null; then
    fail "Required: '$1' not found. Install it and retry."
    exit 1
  fi
}

has_cmd() { command -v "$1" &>/dev/null; }

# detect OS / arch
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH_ALIAS="amd64" ;;
  aarch64|arm64) ARCH_ALIAS="arm64" ;;
  *)        ARCH_ALIAS="$ARCH" ;;
esac

# ── start ─────────────────────────────────────────────────────────────────────
banner

# ── 1. Python ─────────────────────────────────────────────────────────────────
info "Checking Python..."
need_cmd python3

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
  fail "Python 3.10+ required — found $PY_VER"
  exit 1
fi
ok "Python $PY_VER"

# ── 2. pip deps ───────────────────────────────────────────────────────────────
info "Installing Python dependencies..."
if has_cmd pip3; then
  pip3 install -q -r requirements.txt
elif has_cmd pip; then
  pip install -q -r requirements.txt
else
  fail "pip not found. Install pip and retry."
  exit 1
fi
ok "Python deps installed (httpx, dnspython, rich)"

# ── 3. Go tools (subfinder + assetfinder) ────────────────────────────────────
if has_cmd go; then
  GOBIN_DIR="$(go env GOPATH)/bin"

  info "Installing subfinder..."
  if go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null; then
    ok "subfinder installed → $GOBIN_DIR/subfinder"
  else
    warn "subfinder install failed (check Go proxy / network)"
  fi

  info "Installing assetfinder..."
  if go install github.com/tomnomnom/assetfinder@latest 2>/dev/null; then
    ok "assetfinder installed → $GOBIN_DIR/assetfinder"
  else
    warn "assetfinder install failed"
  fi

  # make sure GOPATH/bin is in PATH for this session
  export PATH="$PATH:$GOBIN_DIR"
else
  warn "Go not found — subfinder and assetfinder skipped."
  warn "Install Go from https://go.dev/dl/ then re-run this script."
fi

# ── 4. findomain (binary release) ────────────────────────────────────────────
info "Installing findomain..."

FINDOMAIN_URL=""
if [ "$OS" = "linux" ]; then
  case "$ARCH_ALIAS" in
    amd64)  FINDOMAIN_URL="https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux-musl.zip" ;;
    arm64)  FINDOMAIN_URL="https://github.com/Findomain/Findomain/releases/latest/download/findomain-aarch64-unknown-linux-musl.zip" ;;
  esac
elif [ "$OS" = "darwin" ]; then
  FINDOMAIN_URL="https://github.com/Findomain/Findomain/releases/latest/download/findomain-osx.zip"
fi

if [ -z "$FINDOMAIN_URL" ]; then
  warn "findomain: unsupported OS/arch ($OS/$ARCH_ALIAS) — skipped"
else
  TMP_DIR="$(mktemp -d)"
  DEST="/usr/local/bin/findomain"

  if has_cmd curl; then
    DL_CMD="curl -fsSL"
  elif has_cmd wget; then
    DL_CMD="wget -qO-"
  else
    warn "Neither curl nor wget found — findomain skipped"
    FINDOMAIN_URL=""
  fi

  if [ -n "$FINDOMAIN_URL" ]; then
    if $DL_CMD "$FINDOMAIN_URL" -o "$TMP_DIR/findomain.zip" 2>/dev/null; then
      need_cmd unzip
      unzip -q "$TMP_DIR/findomain.zip" -d "$TMP_DIR"
      BINARY=$(find "$TMP_DIR" -maxdepth 1 -type f -name "findomain*" | head -1)
      chmod +x "$BINARY"

      if [ -w "/usr/local/bin" ]; then
        mv "$BINARY" "$DEST"
        ok "findomain installed → $DEST"
      elif has_cmd sudo; then
        sudo mv "$BINARY" "$DEST"
        ok "findomain installed → $DEST (sudo)"
      else
        LOCAL_BIN="$HOME/.local/bin"
        mkdir -p "$LOCAL_BIN"
        mv "$BINARY" "$LOCAL_BIN/findomain"
        ok "findomain installed → $LOCAL_BIN/findomain"
        warn "Add $LOCAL_BIN to PATH if not already present"
      fi
    else
      warn "findomain download failed — skipped"
    fi
    rm -rf "$TMP_DIR"
  fi
fi

# ── 5. PATH hint ──────────────────────────────────────────────────────────────
if has_cmd go; then
  GOPATH_BIN="$(go env GOPATH)/bin"
  if [[ ":$PATH:" != *":$GOPATH_BIN:"* ]]; then
    echo
    warn "Add Go binaries to your PATH permanently:"
    echo -e "    ${BOLD}echo 'export PATH=\$PATH:$GOPATH_BIN' >> ~/.bashrc && source ~/.bashrc${RESET}"
  fi
fi

# ── 6. Summary ────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}  Tool availability:${RESET}"
for tool in subfinder assetfinder findomain; do
  if has_cmd "$tool"; then
    echo -e "  ${GREEN}✔${RESET}  $tool → $(command -v $tool)"
  else
    echo -e "  ${YELLOW}✘${RESET}  $tool — not in PATH"
  fi
done

echo
ok "Setup complete. Run:"
echo -e "    ${BOLD}python3 main.py --target example.com${RESET}"
echo
