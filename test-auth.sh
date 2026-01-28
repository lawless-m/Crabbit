#!/bin/bash
# Test script for Crabbit auth server

set -e

# Kill any existing auth server
pkill -f "run-auth-server" 2>/dev/null || true

# Build
cargo build --release

# Start auth server on port 567 (Plan 9 ticket service)
RUST_LOG=debug cargo run --release --example run-auth-server -- --port 567 --authdom nawin > /tmp/crabbit.log 2>&1 &
SERVER_PID=$!
sleep 2

# Run the expect test
echo "=== Running auth/debug test ==="
timeout 45 expect /home/matt/Git/Crabbit/auth_test.exp || true

# Show server log
echo ""
echo "=== Server log ==="
grep -v "^warning:" /tmp/crabbit.log | grep -v "^  -->" | grep -v "^   |" | tail -50

# Kill server
kill $SERVER_PID 2>/dev/null || true
