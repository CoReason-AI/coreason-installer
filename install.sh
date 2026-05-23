#!/bin/bash
# install.sh
# CoReason Platform Swarm-in-a-Box bootstrap installer script for Linux and macOS

set -euo pipefail

# 1. Determine script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 2. Check and install uv if not present
if ! command -v uv &> /dev/null; then
    echo "=== Installing uv package manager ==="
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # Add uv to the current path for the rest of this execution
    export PATH="$HOME/.local/bin:$PATH"
fi

# 3. Launch CLI or Web Installer using uv
LAUNCH_WEB=false
for arg in "$@"; do
    if [ "$arg" == "--web" ] || [ "$arg" == "--gui" ]; then
        LAUNCH_WEB=true
        break
    fi
done

cd "$SCRIPT_DIR"
if [ "$LAUNCH_WEB" = true ]; then
    echo "=== Bootstrapping CoReason Web Setup Dashboard ==="
    exec uv run src/web_gui.py
else
    echo "=== Bootstrapping CoReason CLI Installer ==="
    exec uv run src/cli.py "$@"
fi
