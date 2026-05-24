#!/bin/bash
# Progressive Server load test
# Usage: bash contrib/benchmark.sh

SERVER="${1:-http://localhost:8008}"
CONCURRENCY="${2:-10}"
DURATION="${3:-30s}"

echo "=== Progressive Server Benchmark ==="
echo "Server: $SERVER"
echo "Concurrency: $CONCURRENCY"
echo "Duration: $DURATION"
echo ""

# Register user + get token
echo "--- Register ---"
REG=$(curl -sf -X POST "$SERVER/_matrix/client/v3/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"benchuser","password":"benchpass"}')
TOK=$(echo "$REG" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

if [ -z "$TOK" ]; then
  REG=$(curl -sf -X POST "$SERVER/_matrix/client/v3/login" \
    -H "Content-Type: application/json" \
    -d '{"type":"m.login.password","user":"@benchuser:localhost","password":"benchpass"}')
  TOK=$(echo "$REG" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
fi

# Create room
ROOM=$(curl -sf -X POST "$SERVER/_matrix/client/v3/createRoom" \
  -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  -d '{"name":"bench-room"}' | python3 -c "import sys,json;print(json.load(sys.stdin).get('room_id',''))")

echo "Token: ${TOK:0:12}..."
echo "Room: $ROOM"
echo ""

# Benchmark /sync
echo "--- Sync Benchmark ---"
for i in $(seq 1 50); do
  time curl -sf "$SERVER/_matrix/client/v3/sync?timeout=0" -H "Authorization: Bearer $TOK" >/dev/null
done 2>&1 | grep real | awk '{print $2}' | sed 's/0m//;s/s//' | sort -n | awk '{sum+=$1;cnt++} END {printf "sync avg: %.3fs\n", sum/cnt}'

# Benchmark send events
echo ""
echo "--- Send Benchmark ---"
for i in $(seq 1 20); do
  time curl -sf -X PUT "$SERVER/_matrix/client/v3/rooms/$ROOM/send/m.room.message/$i" \
    -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
    -d "{\"msgtype\":\"m.text\",\"body\":\"bench message $i\"}" >/dev/null
done 2>&1 | grep real | awk '{print $2}' | sed 's/0m//;s/s//' | sort -n | awk '{sum+=$1;cnt++} END {printf "send avg: %.3fs\n", sum/cnt}'

echo ""
echo "=== Done ==="
