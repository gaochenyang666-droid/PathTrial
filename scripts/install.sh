#!/bin/sh
# PathTrial installer for macOS and x86_64 Linux.
# Downloads a release tarball, verifies its SHA-256, and installs without sudo.

set -eu

REPO="gaochenyang666-droid/PathTrial"
VERSION="${PATHTRIAL_VERSION:-v1.5.0-rc.1}"
BASE_URL="${PATHTRIAL_BASE_URL:-https://github.com/${REPO}/releases/download/${VERSION}}"
INSTALL_DIR="${PATHTRIAL_INSTALL_DIR:-${HOME}/.local/bin}"

say() {
    printf '%s\n' "$*"
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

download() {
    url=$1
    dest=$2
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$dest"
    else
        fail "curl or wget is required"
    fi
}

sha256_file() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        fail "shasum or sha256sum is required to verify the download"
    fi
}

os=$(uname -s)
arch=$(uname -m)

case "${os}:${arch}" in
    Darwin:arm64)
        target="aarch64-apple-darwin"
        ;;
    Darwin:x86_64)
        target="x86_64-apple-darwin"
        ;;
    Linux:x86_64 | Linux:amd64)
        target="x86_64-unknown-linux-gnu"
        ;;
    MINGW*:x86_64 | MSYS*:x86_64 | CYGWIN*:x86_64)
        fail "Windows x86_64 uses install.ps1 from the same release. This shell script does not install the Windows archive."
        ;;
    *)
        fail "unsupported platform ${os}/${arch}; supported targets are macOS arm64, macOS x86_64, Linux x86_64, and Windows x86_64 via install.ps1"
        ;;
esac

asset="pathtrial-${target}.tar.gz"
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/pathtrial-install.XXXXXX")
cleanup() {
    rm -rf "$tmpdir"
}
trap cleanup EXIT HUP INT TERM

say "Downloading PathTrial ${VERSION} for ${target}..."
download "${BASE_URL}/${asset}" "${tmpdir}/${asset}"
download "${BASE_URL}/${asset}.sha256" "${tmpdir}/${asset}.sha256"

expected=$(awk '{print $1}' "${tmpdir}/${asset}.sha256")
actual=$(sha256_file "${tmpdir}/${asset}")
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    fail "SHA-256 verification failed for ${asset}"
fi

tar -xzf "${tmpdir}/${asset}" -C "$tmpdir"
binary=$(find "$tmpdir" -type f -name pathtrial -perm -u+x | head -n 1)
if [ -z "$binary" ]; then
    fail "the release archive did not contain a pathtrial executable"
fi

mkdir -p "$INSTALL_DIR"
install -m 0755 "$binary" "${INSTALL_DIR}/pathtrial"

say "Installed ${INSTALL_DIR}/pathtrial"
case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        say "Add this directory to PATH if needed:"
        say "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        ;;
esac
"${INSTALL_DIR}/pathtrial" --version
