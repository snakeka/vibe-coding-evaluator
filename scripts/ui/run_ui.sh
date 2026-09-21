#!/usr/bin/env bash
# scripts/ui/run_ui.sh — launch the Streamlit UI for vibe-coding-evaluator.
#
# Usage:
#   ./scripts/ui/run_ui.sh                    # default port 8501, no auto-open
#   ./scripts/ui/run_ui.sh --server.port 8502 # custom port
#   ./scripts/ui/run_ui.sh --browser.gatherUsageStats false
#
# The script activates the project venv (if present), then runs
# `streamlit run scripts/ui/app.py`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Activate venv if it exists
if [ -d ".venv" ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

# Sanity: streamlit must be importable
if ! python3 -c "import streamlit" 2>/dev/null; then
  echo "streamlit not installed. Run:" >&2
  echo "    pip install -e '.[ui]'" >&2
  exit 1
fi

exec streamlit run scripts/ui/app.py "$@"
