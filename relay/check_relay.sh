#!/bin/bash
# Check relay messages from laptop (run from MainPC)
KEY="C:\Users\YOUR_USER\.ssh\id_your_key"
HOST="YOUR_SSH_USER@YOUR_HOST_IP"

echo "=== Messages from Laptop ==="
ssh -i "$KEY" $HOST "ls -lt ~/claude-relay/laptop-to-mainpc/ 2>/dev/null; echo '---'; cat ~/claude-relay/laptop-to-mainpc/*.json 2>/dev/null || echo 'No messages yet'"

echo ""
echo "=== Shared Artifacts ==="
ssh -i "$KEY" $HOST "ls -la ~/claude-relay/shared/ 2>/dev/null"
