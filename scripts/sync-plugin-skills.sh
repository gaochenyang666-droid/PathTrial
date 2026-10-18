#!/bin/sh
# Copy the authoritative shared skills into both plugin packages.
# Use --check to fail when a generated copy differs.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
shared="$root/plugins/shared/skills"
codex="$root/plugins/codex/pathtrial/skills"
claude="$root/plugins/claude-code/pathtrial/skills"

check=0
if [ "${1:-}" = "--check" ]; then
    check=1
fi

if [ "$check" -eq 1 ]; then
    diff -ru "$shared" "$codex"
    diff -ru "$shared" "$claude"
    exit 0
fi

mkdir -p "$codex" "$claude"
cp -R "$shared/." "$codex/"
cp -R "$shared/." "$claude/"
printf 'Synced shared skills to Codex and Claude Code plugins.\n'
