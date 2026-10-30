#!/bin/sh
# Merge the PathTrial stdio server into a project's .cursor/mcp.json.
# The server arguments stay ["mcp"]. This script does not add allow rules.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
template="$root/plugins/cursor/pathtrial/mcp.json"
project=${1:-.}
dest="$project/.cursor/mcp.json"

if [ ! -f "$template" ]; then
    printf 'error: missing %s\n' "$template" >&2
    exit 1
fi

python_bin=""
if command -v python3 >/dev/null 2>&1; then
    python_bin=python3
elif command -v python >/dev/null 2>&1; then
    python_bin=python
else
    printf 'error: python3 is required to merge .cursor/mcp.json\n' >&2
    exit 1
fi

mkdir -p "$project/.cursor"

PATHTRIAL_MCP_TEMPLATE="$template" PATHTRIAL_MCP_DEST="$dest" "$python_bin" - <<'PY'
import json
import os
from pathlib import Path

template = json.loads(Path(os.environ["PATHTRIAL_MCP_TEMPLATE"]).read_text(encoding="utf-8"))
server = template["mcpServers"]["pathtrial"]
if server.get("args") != ["mcp"]:
    raise SystemExit("refusing to install an MCP config that is not exactly [\"mcp\"]")
dest = Path(os.environ["PATHTRIAL_MCP_DEST"])
if dest.exists():
    current = json.loads(dest.read_text(encoding="utf-8"))
else:
    current = {"mcpServers": {}}
servers = current.setdefault("mcpServers", {})
existing = servers.get("pathtrial")
if existing is not None and existing != server:
    raise SystemExit(
        f"{dest} already has a different pathtrial server; refusing to replace it"
    )
servers["pathtrial"] = server
dest.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
print(f"wrote {dest}")
PY
