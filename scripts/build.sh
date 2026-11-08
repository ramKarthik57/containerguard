#!/usr/bin/env bash
set -euo pipefail

echo "=== Building ContainerGuard ==="

# 1. Compile eBPF C program
echo "[1/3] Compiling eBPF kernel program (execve_events.c)..."
mkdir -p bpf bin
clang -g -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c bpf/execve_events.c -o bpf/execve_events.o

# 2. Verify Go formatting and static checks (non-destructive)
echo "[2/3] Checking Go formatting and running go vet..."
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
    echo "Error: The following Go source files require formatting (run 'gofmt -w <file>'):"
    echo "$unformatted"
    exit 1
fi
go vet ./...

# 3. Build ContainerGuard daemon
echo "[3/3] Compiling Go daemon (bin/containerguard)..."
go build -o bin/containerguard ./cmd/containerguard

echo "=== Build Complete: bin/containerguard and bpf/execve_events.o ready ==="
