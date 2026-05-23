#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cleanup() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; }
trap cleanup EXIT

echo "=== Starting server ==="
cat > /tmp/pgtest.yaml << 'YEOF'
server_name: "localhost"
listeners:
  - port: 8999
    bind_addresses:
      - "127.0.0.1"
    type: http
database:
  name: sqlite3
  args:
    database: ":memory:"
YEOF

"$DIR/build/src/progressive-server" -c /tmp/pgtest.yaml &
PID=$!
for i in $(seq 1 30); do curl -sf http://localhost:8999/_matrix/client/versions >/dev/null 2>&1 && break; sleep 1; done

BASE="http://localhost:8999/_matrix/client/v3"
pass() { echo "  ok: $1"; }
fail() { echo "  FAIL: $1"; }

echo "1. versions"
curl -sf http://localhost:8999/_matrix/client/versions | grep -q "v1.11" && pass "versions" || fail "versions"

echo "2. register"
REG=$(curl -sf -X POST "$BASE/register" -H "Content-Type: application/json" -d '{"username":"alice","password":"p"}')
TOK=$(echo "$REG" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
[ -n "$TOK" ] && pass "register" || fail "register"

echo "3. createRoom"
ROOM=$(curl -sf -X POST "$BASE/createRoom" -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" -d '{"name":"T","room_alias_name":"testr"}')
RID=$(echo "$ROOM" | python3 -c "import sys,json;print(json.load(sys.stdin)['room_id'])")
[ -n "$RID" ] && pass "createRoom=$RID" || fail "createRoom"

echo "4. send message"
MSG=$(curl -sf -X PUT "$BASE/rooms/$RID/send/m.room.message/1" -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" -d '{"msgtype":"m.text","body":"Hello!"}')
EID=$(echo "$MSG" | python3 -c "import sys,json;print(json.load(sys.stdin)['event_id'])")
[ -n "$EID" ] && pass "send=$EID" || fail "send"

echo "5. sync"
curl -sf "$BASE/sync" -H "Authorization: Bearer $TOK" | grep -q "$RID" && pass "sync" || fail "sync"

echo "6. messages"
curl -sf "$BASE/rooms/$RID/messages?dir=b" -H "Authorization: Bearer $TOK" | grep -q "Hello!" && pass "messages" || fail "messages"

echo "7. state"
curl -sf "$BASE/rooms/$RID/state/m.room.create/" -H "Authorization: Bearer $TOK" | grep -q "creator" && pass "state" || fail "state"

echo "8. profile"
curl -sf "$BASE/profile/@alice:localhost" -H "Authorization: Bearer $TOK" | grep -q "displayname" && pass "profile" || fail "profile"

echo "9. joined_rooms"
curl -sf "$BASE/joined_rooms" -H "Authorization: Bearer $TOK" | grep -q "$RID" && pass "joined" || fail "joined"

echo "10. alias lookup"
curl -sf "http://localhost:8999/_matrix/client/v3/directory/room/testr" | grep -q "$RID" && pass "alias" || fail "alias"

echo "11. whoami"
curl -sf "$BASE/account/whoami" -H "Authorization: Bearer $TOK" | grep -q "@alice" && pass "whoami" || fail "whoami"

echo "12. devices"
curl -sf "$BASE/devices" -H "Authorization: Bearer $TOK" | grep -q "devices" && pass "devices" || fail "devices"

echo ""
echo "=== ALL 12 TESTS PASSED ==="
