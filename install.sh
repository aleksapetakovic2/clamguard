#!/usr/bin/env bash
#
# Installs ClamGuard into your own account. No root, nothing outside your home
# directory, and it does not copy the code — it points at this checkout, so
# `git pull` is all an update takes.
#
#   ./install.sh              install
#   ./install.sh --uninstall  remove
#
# This does NOT install the privileged helper. That is a separate, deliberate
# step: sudo ./packaging/install-helper.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER="$HERE/clamguard"

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
BIN_DIR="$HOME/.local/bin"
DESKTOP_DIR="$DATA_HOME/applications"
ICON_DIR="$DATA_HOME/icons/hicolor/scalable/apps"

DESKTOP_FILE="$DESKTOP_DIR/clamguard.desktop"
ICON_FILE="$ICON_DIR/clamguard.svg"
SYMLINK="$BIN_DIR/clamguard"

if [[ "${1:-}" == "--uninstall" ]]; then
    rm -f "$DESKTOP_FILE" "$ICON_FILE" "$SYMLINK"
    rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/autostart/clamguard.desktop"
    command -v update-desktop-database >/dev/null && \
        update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
    echo "ClamGuard removed from your menu."
    echo
    echo "Your settings, scan history and quarantine were left alone. Remove them with:"
    echo "    rm -rf ~/.config/clamguard ~/.local/share/clamguard ~/.cache/clamguard"
    echo
    echo "If you installed the privileged helper, remove it with:"
    echo "    sudo $HERE/packaging/install-helper.sh --uninstall"
    exit 0
fi

echo "Installing ClamGuard for $USER (no root needed)."

# The menu entry quotes this folder's path in its Exec line, where these
# characters would need escaping the desktop-entry spec makes easy to get wrong.
case "$LAUNCHER" in
    *[\"\`\$\\%\|\&]* | *$'\n'*)
        echo "This folder's path has a character a menu entry cannot carry safely:" >&2
        echo "    $LAUNCHER" >&2
        echo "Move ClamGuard somewhere with a plainer path and run this again." >&2
        exit 1 ;;
esac

# A menu entry for an app that cannot start is worse than none. The launcher
# explains what is missing and how to install it.
if ! "$LAUNCHER" --version >/dev/null; then
    echo >&2
    echo "Nothing was installed. Once ./clamguard starts, run this again." >&2
    exit 1
fi

# 1. The launcher, on PATH.
mkdir -p "$BIN_DIR"
ln -sf "$LAUNCHER" "$SYMLINK"
echo "  command  -> $SYMLINK"

# 2. The icon, generated from the same source the app draws with.
mkdir -p "$ICON_DIR"
"$LAUNCHER" --write-icon "$ICON_FILE"
echo "  icon     -> $ICON_FILE"

# 3. The menu entry, pointed at this checkout.
mkdir -p "$DESKTOP_DIR"
sed "s|@LAUNCHER@|$LAUNCHER|g" "$HERE/packaging/clamguard.desktop" > "$DESKTOP_FILE"
chmod 644 "$DESKTOP_FILE"
echo "  menu     -> $DESKTOP_FILE"

command -v update-desktop-database >/dev/null && \
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
command -v gtk-update-icon-cache >/dev/null && \
    gtk-update-icon-cache -f -t "$DATA_HOME/icons/hicolor" 2>/dev/null || true

cat <<NOTE

Done. ClamGuard is in your application menu, and 'clamguard' works in a
terminal if ~/.local/bin is on your PATH.

Two things are deliberately NOT installed:

  * The privileged helper. Without it ClamGuard cannot edit /etc/clamav,
    control ClamAV's services, or run signature updates. Read it first, then:
        sudo $HERE/packaging/install-helper.sh

  * Anything outside your home directory. Uninstall with ./install.sh --uninstall
NOTE
