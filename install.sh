#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Detect whether we are running locally (bash install.sh from the repo)
# or being piped from curl. When run as a file, BASH_SOURCE[0] is the
# script path; when piped into bash it is empty or "bash".
# ---------------------------------------------------------------------------
SCRIPT_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != "bash" && -f "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fi

LOCAL_MODE=false
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/Makefile" && -f "$SCRIPT_DIR/main.go" ]]; then
    LOCAL_MODE=true
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [[ "$LOCAL_MODE" == true ]]; then
    echo "Local mode: building bitswan with 'make build'..."
    make -C "$SCRIPT_DIR" build
    cp "$SCRIPT_DIR/bitswan" "$TMP/bitswan"
    chmod +x "$TMP/bitswan"
else
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$OS" in
        linux|darwin) ;;
        *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
    esac

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)        ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac

    echo "Downloading bitswan for ${OS}/${ARCH}..."
    curl -fsSL -o "$TMP/bitswan" \
        "https://deployment-management-backend.bitswan-devops-1.bswn.io/public/automation/latest?os=${OS}&arch=${ARCH}"
    chmod +x "$TMP/bitswan"
fi

# Install binary — prefer /usr/local/bin, fall back to ~/.local/bin
if [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
    mv "$TMP/bitswan" "$INSTALL_DIR/bitswan"
elif command -v sudo >/dev/null 2>&1; then
    INSTALL_DIR="/usr/local/bin"
    echo "Installing to $INSTALL_DIR (sudo required)..."
    sudo mv "$TMP/bitswan" "$INSTALL_DIR/bitswan"
else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
    mv "$TMP/bitswan" "$INSTALL_DIR/bitswan"
    echo "Note: ensure $INSTALL_DIR is in your PATH"
fi

echo "Installed bitswan to $INSTALL_DIR/bitswan"

"$INSTALL_DIR/bitswan" completion install

echo ""
echo "bitswan installed successfully! Run 'bitswan --help' to get started."
