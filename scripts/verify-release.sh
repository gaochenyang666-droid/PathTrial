#!/usr/bin/env bash
# Verify a public PathTrial release without Rust, Cargo, or a source build.

set -euo pipefail

REPO="gaochenyang666-droid/PathTrial"
VERSION="${PATHTRIAL_VERSION:-v1.4.0-rc.1}"
EXPECTED_VERSION="${VERSION#v}"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

say() {
    printf '%s\n' "$*"
}

sha256_file() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        say "shasum or sha256sum is required" >&2
        exit 1
    fi
}

os=$(uname -s)
arch=$(uname -m)
case "${os}:${arch}" in
    Darwin:arm64) target="aarch64-apple-darwin" ;;
    Darwin:x86_64) target="x86_64-apple-darwin" ;;
    Linux:x86_64 | Linux:amd64) target="x86_64-unknown-linux-gnu" ;;
    *)
        say "unsupported platform ${os}/${arch}" >&2
        exit 1
        ;;
esac

asset="pathtrial-${target}.tar.gz"
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/pathtrial-release-check.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM
mkdir -p "$tmpdir/home" "$tmpdir/install"

say "Platform: ${os}/${arch} (${target})"
say "Release: ${VERSION}"

curl -fsSL "${BASE_URL}/install.sh" -o "$tmpdir/install.sh"
curl -fsSL "${BASE_URL}/install.sh.sha256" -o "$tmpdir/install.sh.sha256"
expected_script=$(awk '{print $1}' "$tmpdir/install.sh.sha256")
actual_script=$(sha256_file "$tmpdir/install.sh")
test -n "$expected_script"
test "$expected_script" = "$actual_script"
sh -n "$tmpdir/install.sh"

curl -fsSL "${BASE_URL}/${asset}" -o "$tmpdir/${asset}"
curl -fsSL "${BASE_URL}/${asset}.sha256" -o "$tmpdir/${asset}.sha256"
expected=$(awk '{print $1}' "$tmpdir/${asset}.sha256")
actual=$(sha256_file "$tmpdir/${asset}")
test -n "$expected"
test "$expected" = "$actual"

size=$(wc -c < "$tmpdir/${asset}" | tr -d ' ')
test "$size" -gt 0
tar -tzf "$tmpdir/${asset}" >/dev/null

HOME="$tmpdir/home" \
    PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    PATHTRIAL_VERSION="$VERSION" \
    PATHTRIAL_BASE_URL="$BASE_URL" \
    PATHTRIAL_INSTALL_DIR="$tmpdir/install" \
    sh "$tmpdir/install.sh"

binary="$tmpdir/install/pathtrial"
test -x "$binary"
version_output=$("$binary" --version)
test "$version_output" = "pathtrial ${EXPECTED_VERSION}"

for command in scan http quic http3 proxy mcp; do
    "$binary" "$command" --help >/dev/null
done
"$binary" --help >/dev/null

BINARY="$binary" python3 - <<'PY'
import json
import os
import socketserver
import subprocess
import threading


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(1)
        try:
            self.request.recv(1024)
        except TimeoutError:
            pass


server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
server.daemon_threads = True
port = server.server_address[1]
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()

try:
    def request(identifier, method, params):
        return {
            "jsonrpc": "2.0",
            "id": identifier,
            "method": method,
            "params": params,
        }

    proc = subprocess.Popen(
        [os.environ["BINARY"], "mcp", "--allow-target", f"127.0.0.1:{port}"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    def call(identifier, method, params):
        assert proc.stdin is not None
        assert proc.stdout is not None
        proc.stdin.write(json.dumps(request(identifier, method, params)) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        assert line, proc.stderr.read() if proc.stderr else ""
        return json.loads(line)

    initialized = call(1, "initialize", {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "release-smoke", "version": "1"},
    })
    listed = call(2, "tools/list", {})
    capabilities_result = call(3, "tools/call", {
        "name": "pathtrial_capabilities",
        "arguments": {},
    })
    denied_result = call(4, "tools/call", {
        "name": "pathtrial_http",
        "arguments": {"url": "http://127.0.0.1:9/", "timeout_ms": 500},
    })
    scan_result_message = call(5, "tools/call", {
        "name": "pathtrial_scan",
        "arguments": {
            "target": "127.0.0.1",
            "port": port,
            "profile": "tcp",
            "rounds": 1,
            "timeout_ms": 1000,
            "max_seconds": 5,
        },
    })
    assert initialized["result"]["protocolVersion"] == "2025-06-18"
    tools = listed["result"]["tools"]
    assert len(tools) == 9
    capabilities = capabilities_result["result"]["structuredContent"]
    assert capabilities["core_version"] == "1.4.0-rc.1"
    denied = denied_result["result"]["structuredContent"]
    assert denied["error"]["code"] == "target_not_allowed"
    scan_result = scan_result_message["result"]["structuredContent"]
    assert "report" in scan_result, scan_result
    report = scan_result["report"]
    assert report["probes"], report
    evidence_id = report["probes"][0]["id"]

    explained_result = call(6, "tools/call", {
        "name": "pathtrial_explain_report",
        "arguments": {"report": report},
    })
    explained = explained_result["result"]["structuredContent"]
    assert explained["probe_counts"]["tcp"] >= 1
    assert evidence_id in json.dumps(explained)
    call(7, "shutdown", {})
    assert proc.stdin is not None
    proc.stdin.close()
    assert proc.wait(timeout=10) == 0
    print(f"MCP: core={capabilities['core_version']} tools={len(tools)} evidence={evidence_id}")
finally:
    server.shutdown()
    server.server_close()
PY

say "Asset: ${asset}"
say "Asset bytes: ${size}"
say "Asset SHA-256: ${actual}"
say "Installed version: ${version_output}"
say "CLI and MCP release verification passed"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        printf '### %s / %s\n\n' "$os" "$arch"
        printf -- '- Release: `%s`\n' "$VERSION"
        printf -- '- Asset: `%s`\n' "$asset"
        printf -- '- Size: `%s` bytes\n' "$size"
        printf -- '- SHA-256: `%s`\n' "$actual"
        printf -- '- Installed: `%s`\n' "$version_output"
        printf -- '- CLI help, MCP initialize, tools/list, default deny, authorized scan and report explanation passed\n'
    } >> "$GITHUB_STEP_SUMMARY"
fi
