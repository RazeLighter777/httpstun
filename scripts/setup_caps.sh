#!/usr/bin/env bash
set -euo pipefail

# Assign CAP_NET_ADMIN to httpstun binaries so they can create TUN/TAP interfaces without sudo.
# Usage:
#   scripts/setup_caps.sh [--release] [--dry-run]
# Options:
#   --release   Build and set capabilities on release binaries (default is debug)
#   --dry-run   Show actions without executing setcap
# Requires:
#   cargo, setcap (from libcap2-bin on Debian/Ubuntu)
#
# On systems where setcap is unavailable or filesystem doesn't support xattrs (e.g. some Docker
# volumes), you must run binaries with sudo instead.

BUILD_MODE=debug
DRY_RUN=0

for arg in "$@"; do
  case "$arg" in
    --release) BUILD_MODE=release ;;
    --dry-run) DRY_RUN=1 ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

if ! command -v setcap >/dev/null 2>&1; then
  echo "[ERROR] setcap not found. Install with: sudo apt-get update && sudo apt-get install -y libcap2-bin" >&2
  exit 1
fi

echo "[INFO] Building binaries (mode=$BUILD_MODE)..."
if [ "$BUILD_MODE" = "release" ]; then
  cargo build --release -p httpstun_server -p httpstun_client
  BIN_DIR=target/release
else
  cargo build -p httpstun_server -p httpstun_client
  BIN_DIR=target/debug
fi

BINS=(httpstun_server httpstun_client)

for bin in "${BINS[@]}"; do
  PATH_BIN="$BIN_DIR/$bin"
  if [ ! -f "$PATH_BIN" ]; then
    echo "[WARN] Binary not found: $PATH_BIN (skipping)" >&2
    continue
  fi
  echo "[INFO] Setting CAP_NET_ADMIN on $PATH_BIN"
  CMD=(setcap cap_net_admin+ep "$PATH_BIN")
  if [ $DRY_RUN -eq 1 ]; then
    echo "DRY-RUN: ${CMD[*]}"
  else
    if ! sudo "${CMD[@]}"; then
      echo "[ERROR] Failed to set capabilities on $PATH_BIN. You may need to run as root or use sudo to run the binary." >&2
    fi
  fi
  echo "[INFO] Verifying capabilities:"
  getcap "$PATH_BIN" || true
done

echo "[DONE] Capability setup complete. You can now run binaries without sudo for TUN creation (if filesystem honors caps)."
