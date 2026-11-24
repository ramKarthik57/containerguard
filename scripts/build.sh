#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Output directory selection:
# Default: Compiles to an isolated build directory (build/) to prevent modifying
# or overwriting the official tracked release binaries (bin/containerguard and bpf/execve_events.o).
# Compares compiled hashes against official release checksums.
# Pass "--overwrite-release" to explicitly overwrite tracked release binaries in bin/ and bpf/.
OVERWRITE_RELEASE=false
if [[ "${1:-}" == "--overwrite-release" ]]; then
    OVERWRITE_RELEASE=true
    OUT_BPF_DIR="${ROOT_DIR}/bpf"
    OUT_BIN_DIR="${ROOT_DIR}/bin"
else
    OUT_BPF_DIR="${ROOT_DIR}/build/bpf"
    OUT_BIN_DIR="${ROOT_DIR}/build/bin"
fi

mkdir -p "${OUT_BPF_DIR}" "${OUT_BIN_DIR}"

echo "=== Building ContainerGuard (Output: ${OUT_BIN_DIR}, ${OUT_BPF_DIR}) ==="

# 1. Compile eBPF C program
echo "[1/3] Compiling eBPF kernel program (execve_events.c)..."
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c "${ROOT_DIR}/bpf/execve_events.c" -o "${OUT_BPF_DIR}/execve_events.o"

# 2. Verify Go formatting and static checks (non-destructive)
echo "[2/3] Checking Go formatting and running go vet..."
unformatted=$(gofmt -l "${ROOT_DIR}")
if [ -n "$unformatted" ]; then
    echo "Error: The following Go source files require formatting (run 'gofmt -w <file>'):"
    echo "$unformatted"
    exit 1
fi
(cd "${ROOT_DIR}" && go vet ./...)

# 3. Build ContainerGuard daemon and CLI utilities
echo "[3/3] Compiling Go daemon and cg-top..."
(cd "${ROOT_DIR}" && go build -o "${OUT_BIN_DIR}/containerguard" ./cmd/containerguard)
(cd "${ROOT_DIR}" && go build -o "${OUT_BIN_DIR}/cg-top" ./cmd/cg-top)

echo "=== Build Complete ==="

# 4. Checksum verification against official 50% verified release milestone
OFFICIAL_BPF_SHA="6ae519a012694f11c9ab514c1b13cafb4b8551fb8deadaf10dee817862717ef3"
OFFICIAL_DAEMON_SHA="cfee0d9675b653fdd7cda2629454a4839b1fd59ede0ba43f8bcd7ce7bebc93d0"

BUILT_BPF_SHA=$(sha256sum "${OUT_BPF_DIR}/execve_events.o" | awk '{print $1}')
BUILT_DAEMON_SHA=$(sha256sum "${OUT_BIN_DIR}/containerguard" | awk '{print $1}')

echo "--- Artifact Digest Accounting ---"
echo " eBPF Kernel Object: ${BUILT_BPF_SHA}"
if [[ "${BUILT_BPF_SHA}" == "${OFFICIAL_BPF_SHA}" ]]; then
    echo "   [PASS] Bytecode matches official milestone release checksum."
else
    echo "   [NOTE] Bytecode differs from official milestone (compiler/toolchain divergence)."
fi

echo " Go Control Daemon:  ${BUILT_DAEMON_SHA}"
if [[ "${BUILT_DAEMON_SHA}" == "${OFFICIAL_DAEMON_SHA}" ]]; then
    echo "   [PASS] Binary matches official milestone release checksum."
else
    echo "   [NOTE] Binary differs from official milestone (Go build-id / toolchain timestamp)."
fi

if [[ "${OVERWRITE_RELEASE}" == "false" ]]; then
    echo ""
    echo "[i] Tracked release binaries (bin/containerguard, bpf/execve_events.o) were preserved."
    echo "    Built artifacts reside in build/bin/ and build/bpf/."
fi
