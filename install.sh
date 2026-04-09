#!/usr/bin/env bash
set -euo pipefail

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
    linux|darwin) ;;
    *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)        ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

DOWNLOAD_URL="https://deployment-management-backend.bitswan-devops-1.bswn.io/public/automation/latest?os=${OS}&arch=${ARCH}"

echo "Downloading bitswan for ${OS}/${ARCH}..."

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL -o "$TMP/bitswan" "$DOWNLOAD_URL"
chmod +x "$TMP/bitswan"

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

BITSWAN="$INSTALL_DIR/bitswan"
echo "Installed bitswan to $BITSWAN"

# Install shell completions
install_bash_completion() {
    local dir="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions"
    mkdir -p "$dir"
    "$BITSWAN" completion bash > "$dir/bitswan"
    echo "Bash completions installed to $dir/bitswan"
    echo "  Restart your shell or run: source \"$dir/bitswan\""
}

install_zsh_completion() {
    local dir="${HOME}/.zsh/completions"
    mkdir -p "$dir"
    "$BITSWAN" completion zsh > "$dir/_bitswan"
    echo "Zsh completions installed to $dir/_bitswan"
    echo "  Ensure the following is in your ~/.zshrc (add if missing):"
    echo "    fpath=(~/.zsh/completions \$fpath)"
    echo "    autoload -Uz compinit && compinit"
}

install_fish_completion() {
    local dir="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions"
    mkdir -p "$dir"
    "$BITSWAN" completion fish > "$dir/bitswan.fish"
    echo "Fish completions installed to $dir/bitswan.fish"
}

SHELL_NAME=$(basename "${SHELL:-bash}")
case "$SHELL_NAME" in
    bash) install_bash_completion ;;
    zsh)  install_zsh_completion ;;
    fish) install_fish_completion ;;
    *)
        echo "Shell '$SHELL_NAME' not recognised; skipping completions."
        echo "Install manually with: bitswan completion --help"
        ;;
esac

echo ""
echo "bitswan installed successfully! Run 'bitswan --help' to get started."
