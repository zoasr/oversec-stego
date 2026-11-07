#!/usr/bin/env sh
# Start the Zero Width workbench on Linux/macOS using uv.
set -eu
cd "$(dirname "$0")"

if ! command -v uv >/dev/null 2>&1; then
    echo "uv is required. Install it from https://docs.astral.sh/uv/getting-started/installation/" >&2
    exit 1
fi

exec uv run --with-requirements requirements.txt -- python server.py --open "$@"
