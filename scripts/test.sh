#!/usr/bin/env bash
set -euo pipefail

echo "=== Running ContainerGuard Test Suite ==="
go test -v -count=1 ./...
echo "=== All Tests Passed Successfully ==="
