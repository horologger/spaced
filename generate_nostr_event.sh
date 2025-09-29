#!/bin/bash

# Get current timestamp (Unix epoch)
timestamp=$(date +%s)

# Create JSON file
cat > nostr_event.json << EOF
{
  "created_at": $timestamp,
  "kind": 1,
  "tags": [],
  "content": "What is my pubkey?"
}
EOF

echo "Generated nostr_event.json with timestamp: $timestamp" >&2
cat nostr_event.json

