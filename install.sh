#!/usr/bin/env bash
set -euo pipefail

echo "==> Compiling ssh-watch-gnome..."
make build

echo "==> Installing to ~/.local/bin and setting up user systemd service..."
make install

echo "==> Done!"
