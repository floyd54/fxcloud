#!/usr/bin/env bash
# fxcloud black-box test suite.
#
# Starts a throwaway instance on a loopback port with its own data directory,
# drives it over HTTP exactly the way a client does, and fails on the first
# broken invariant. Covers trash, sharing, quota, WebDAV, the blob layout and
# the client-side encryption endpoints (ENCRYPTION.md).
#
#   ./tests/suite.sh
#
# Needs bash, curl, perl and sqlite3. node runs the client-crypto harness and
# the JS syntax checks; when it is missing those checks fail rather than pass
# silently, because an untested crypto path is worse than a red build.
#
# Environment:
#   FXCLOUD_TEST_PORT  port to bind              (default 18081)
#   FXCLOUD_TEST_BIN   binary under test         (default target/debug/fxcloud)
#   FXCLOUD_TEST_KEEP  1 = keep the scratch dir even on success
#   NODE, QJSC         override those executables
set -u

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
PORT=${FXCLOUD_TEST_PORT:-18081}
BASE=http://127.0.0.1:$PORT
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fxcloud-test.XXXXXX")
DATA=$ROOT/data
BIN=${FXCLOUD_TEST_BIN:-$REPO/target/debug/fxcloud}
JA=$ROOT/alice.jar
JB=$ROOT/bob.jar

mkdir -p "$ROOT"
echo "binary: $BIN"
echo "scratch: $ROOT"

# Find node/qjsc without assuming where they were unpacked: PATH first, then
# the usual unpack-here layouts. $HOME/node-*/bin/node covers the tarball this
# project is developed against.
find_node() {
  command -v node 2>/dev/null && return 0
  local c
  for c in /usr/local/bin/node /usr/bin/node "$HOME"/node-*/bin/node; do
    [ -x "$c" ] && { printf '%s' "$c"; return 0; }
  done
  return 1
}
find_qjsc() {
  command -v qjsc 2>/dev/null && return 0
  local c
  for c in "$HOME"/quickjs/*/qjsc; do
    [ -x "$c" ] && { printf '%s' "$c"; return 0; }
  done
  return 1
}

NODE=${NODE:-$(find_node || true)}
FXTOOL=$REPO/frontend/tests/fxtool.js
if [ -z "$NODE" ]; then
  echo "warning: node not found - the crypto harness and every JS-dependent" >&2
  echo "         check below will FAIL. Install node or set NODE=<path>." >&2
fi

# Every early `exit` used to leak the instance it had just started; the trap
# closes that hole and decides whether the scratch dir is worth keeping.
stop_server() {
  local pid
  pid=$(cat "$ROOT/server.pid" 2>/dev/null) || return 0
  kill "$pid" 2>/dev/null
  for _ in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.1
  done
}
cleanup() {
  local rc=$1
  stop_server
  if [ "$rc" -ne 0 ] || [ "${FXCLOUD_TEST_KEEP:-0}" = "1" ]; then
    echo "scratch kept: $ROOT"
  else
    rm -rf "$ROOT"
  fi
}
trap 'cleanup $?' EXIT

# ---- preflight ------------------------------------------------------------
# The suite asserts that the binary's version badge matches Cargo.toml, so a
# stale build would be a red check rather than a quiet pass. Build here
# instead of trusting the caller to have remembered; cargo is incremental,
# so this costs seconds when nothing changed.
missing=""
for tool in curl perl sqlite3; do
  command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
  echo "missing required tools:$missing" >&2
  exit 2
fi
if [ -n "${FXCLOUD_TEST_BIN:-}" ]; then
  [ -x "$BIN" ] || { echo "FXCLOUD_TEST_BIN=$BIN is not executable" >&2; exit 2; }
else
  echo "building (cargo build) ..."
  (cd "$REPO" && cargo build) || { echo "cargo build failed" >&2; exit 2; }
fi

FAIL=0
note() { printf '\n===== %s\n' "$*"; }
ok()   { printf 'OK   %s\n' "$*"; }
bad()  { printf 'FAIL %s\n' "$*"; FAIL=1; }

jget() { # jget <json> <a.b.c>
  printf '%s' "$1" | perl -MJSON::PP -0777 -e '
    my $path = shift;
    my $j = decode_json(do { local $/; <STDIN> });
    for my $k (split /\./, $path) {
      $j = ref($j) eq "ARRAY" ? $j->[$k] : $j->{$k};
    }
    print defined $j ? $j : "";
  ' "$2"
}

idof() { # idof <list response or entries-array> <name>
  printf '%s' "$1" | perl -MJSON::PP -0777 -e '
    my $name = shift;
    my $d = decode_json(do { local $/; <STDIN> });
    my $all = ref($d) eq "ARRAY" ? $d : ($d->{entries} || []);
    for my $e (@$all) { print $e->{id} if $e->{name} eq $name; }
  ' "$2"
}

subsize() { # subsize <list response> <name> -> subtree_bytes (empty for files/absent)
  printf '%s' "$1" | perl -MJSON::PP -0777 -e '
    my $name = shift;
    my $d = decode_json(do { local $/; <STDIN> });
    for my $e (@{$d->{entries} || []}) {
      print $e->{subtree_bytes} if $e->{name} eq $name && exists $e->{subtree_bytes};
    }
  ' "$2"
}

req() { # req <METHOD> <path> <jar> [json-body]
  local method=$1 path=$2 jar=$3 body=${4:-}
  if [ -n "$body" ]; then
    curl -s -X "$method" -b "$jar" -c "$jar" -H 'Content-Type: application/json' -d "$body" "$BASE$path"
  else
    curl -s -X "$method" -b "$jar" -c "$jar" "$BASE$path"
  fi
}

reqcode() { # prints only the HTTP status
  local method=$1 path=$2 jar=$3 body=${4:-}
  if [ -n "$body" ]; then
    curl -s -o /dev/null -w '%{http_code}' -X "$method" -b "$jar" -c "$jar" \
      -H 'Content-Type: application/json' -d "$body" "$BASE$path"
  else
    curl -s -o /dev/null -w '%{http_code}' -X "$method" -b "$jar" -c "$jar" "$BASE$path"
  fi
}

up() { # up <jar> <parent-id|''> <filename>
  local jar=$1 parent=$2 name=$3
  if [ -n "$parent" ]; then
    curl -s -b "$jar" -F "parent=$parent" -F "file=@$ROOT/src/$name" "$BASE/api/files/upload"
  else
    curl -s -b "$jar" -F "file=@$ROOT/src/$name" "$BASE/api/files/upload"
  fi
}

blobpath() { # blobpath <file-id> -> on-disk blob path (owner/year from the DB row)
  local id=$1 owner year
  set -- $(sqlite3 -separator ' ' "$DATA/fxcloud.db" "SELECT owner_id, substr(created_at,1,4) FROM files WHERE id=$id;")
  owner=$1 year=$2
  perl -e '
    my ($root, $owner, $year, $id) = @ARGV;
    printf "%s/blobs/%s/%s/%02x/%02x/%d", $root, $owner, $year,
      ($id >> 16) & 0xff, ($id >> 8) & 0xff, $id;
  ' "$DATA" "$owner" "$year" "$id"
}

start_server() {
  FXCLOUD_DATA="$DATA" FXCLOUD_PORT=$PORT FXCLOUD_TRASH_DAYS=30 FXCLOUD_TRASH_SWEEP_SECS=2 \
    "$BIN" >>"$ROOT/server.log" 2>&1 &
  echo $! > "$ROOT/server.pid"
  local code=000
  for _ in $(seq 1 100); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/me")
    [ "$code" != "000" ] && break
    sleep 0.2
  done
  [ "$code" = "000" ] && return 1
  return 0
}

restart_server() {
  kill "$(cat "$ROOT/server.pid")" 2>/dev/null
  wait 2>/dev/null
  sleep 0.3
  start_server
}

# ---- readiness ----
start_server || { bad "server did not start"; cat "$ROOT/server.log"; exit 1; }
ok "server up (GET /api/me -> $(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/me"))"

# ---- accounts ----
note "register + login alice"
req POST /api/register "$JA" '{"username":"alice","password":"correct-horse"}'; echo
req POST /api/login "$JA" '{"username":"alice","password":"correct-horse"}'; echo

mkdir -p "$ROOT/src"
printf 'AAAAAAAAAA' > "$ROOT/src/a.txt"
printf 'BBBBBBBBBB' > "$ROOT/src/b.txt"
printf 'CCCCCCCCCC' > "$ROOT/src/c.txt"
printf 'DDDDDDDDDD' > "$ROOT/src/d.txt"

note "create docs/ and docs/sub/"
DOCRESP=$(req POST /api/files/folder "$JA" '{"name":"docs"}')
echo "$DOCRESP"
DOC=$(jget "$DOCRESP" entry.id)
SUBRESP=$(req POST /api/files/folder "$JA" "{\"name\":\"sub\",\"parent_id\":$DOC}")
SUB=$(jget "$SUBRESP" entry.id)
echo "docs=$DOC sub=$SUB"
[ -n "$DOC" ] && [ -n "$SUB" ] && ok "folders created" || bad "folder creation"

note "upload a/b/c into docs, d into docs/sub"
up "$JA" "$DOC" a.txt >/dev/null
up "$JA" "$DOC" b.txt >/dev/null
up "$JA" "$DOC" c.txt >/dev/null
up "$JA" "$SUB" d.txt >/dev/null

DOCLIST=$(req GET "/api/files?parent=$DOC" "$JA")
echo "$DOCLIST"
A=$(idof "$DOCLIST" a.txt)
B=$(idof "$DOCLIST" b.txt)
C=$(idof "$DOCLIST" c.txt)
SUBLIST=$(req GET "/api/files?parent=$SUB" "$JA")
D=$(idof "$SUBLIST" d.txt)
echo "a=$A b=$B c=$C d=$D"
[ -n "$A" ] && [ -n "$D" ] || { bad "id extraction failed"; exit 1; }

# ---- blob layout ----
note "blobs live at <owner>/<year>/<h1>/<h2>/<id>"
BLOB_A=$(blobpath "$A")
BLOB_D=$(blobpath "$D")
echo "a.txt blob: $BLOB_A"
echo "d.txt blob: $BLOB_D"
[ -f "$BLOB_A" ] && ok "blob written to the new path" || bad "blob missing at $BLOB_A"
[ -f "$DATA/blobs/$A" ] && bad "blob still flat" || ok "no flat blob for a.txt"
echo "$BLOB_A" | grep -qE "/blobs/1/[0-9]{4}/[0-9a-f]{2}/[0-9a-f]{2}/[0-9]+$" \
  && ok "path shape <owner>/<year>/<h1>/<h2>/<id>" || bad "unexpected path shape"

# ---- batch move ----
note "batch move [a,b] docs -> root"
OUT=$(req POST /api/files/batch/move "$JA" "{\"ids\":[$A,$B]}")
echo "$OUT"
NOK=$(printf '%s' "$OUT" | perl -MJSON::PP -0777 -ne 'print scalar @{decode_json($_)->{ok}}')
[ "$NOK" = "2" ] && ok "moved 2" || bad "expected ok=2, got: $OUT"

note "batch move with a bogus id (partial failure)"
OUT=$(req POST /api/files/batch/move "$JA" "{\"ids\":[$C,999999]}")
echo "$OUT"
echo "$OUT" | grep -q '"ok":\[' && echo "$OUT" | grep -q '"failed"' || bad "no failed array"
echo "$OUT" | grep -q "not found" && ok "bogus id reported" || bad "bogus id not reported"

# ---- batch copy ----
note "batch copy [a] -> docs (ok, then duplicate -> 409 for that item)"
OUT=$(req POST /api/files/batch/copy "$JA" "{\"ids\":[$A],\"dest_parent\":$DOC}")
echo "$OUT"
OUT=$(req POST /api/files/batch/copy "$JA" "{\"ids\":[$A,$B],\"dest_parent\":$DOC}")
echo "$OUT"
FAILED=$(printf '%s' "$OUT" | perl -MJSON::PP -0777 -ne 'print scalar @{decode_json($_)->{failed}}')
[ "$FAILED" = "1" ] && ok "name collision reported for 1 item" || bad "expected 1 failure: $OUT"

note "batch delete [c, bogus]"
OUT=$(req POST /api/files/batch/delete "$JA" "{\"ids\":[$C,999999]}")
echo "$OUT"
DOCLIST2=$(req GET "/api/files?parent=$DOC" "$JA")
echo "$DOCLIST2"
echo "$DOCLIST2" | grep -q '"name":"c.txt"' && bad "c.txt still present" || ok "c.txt deleted"

# ---- share batch (second, initially inactive user) ----
note "register + login bob (inactive)"
req POST /api/register "$JB" '{"username":"bob","password":"correct-horse"}'; echo
RC=$(reqcode POST /api/login "$JB" '{"username":"bob","password":"correct-horse"}')
echo "bob login status: $RC"
[ "$RC" = "403" ] && ok "inactive bob rejected with 403" || bad "expected 403 for inactive login, got $RC"

sqlite3 "$DATA/fxcloud.db" "UPDATE users SET is_active=1 WHERE username='bob';" 2>/dev/null \
  || sqlite3 "$DATA/fxcloud.db" ".tables"
req POST /api/login "$JB" '{"username":"bob","password":"correct-horse"}'; echo

# The setup dialog's pre-selected default (DECISION 3) proves the typed
# string against /api/login *while the user is already signed in*, so the
# endpoint has to keep answering in that state: 401 is the dialog's verdict
# on a typo, 200 issues a replacement cookie that must still authenticate.
note "login re-check from inside an existing session"
RC=$(reqcode POST /api/login "$JA" '{"username":"alice","password":"wrong-password"}')
[ "$RC" = "401" ] && ok "a wrong login password answers 401" || bad "expected 401, got $RC"
RC=$(reqcode POST /api/login "$JA" '{"username":"alice","password":"correct-horse"}')
[ "$RC" = "200" ] && ok "the re-check answers 200 while already signed in" || bad "expected 200, got $RC"
RC=$(reqcode GET /api/me "$JA")
[ "$RC" = "200" ] && ok "the replacement session cookie still authenticates" \
  || bad "session dead after the re-check: $RC"

note "alice shares [a.txt, docs] with bob (read-only) in one call"
OUT=$(req POST /api/shares/batch "$JA" "{\"file_ids\":[$A,$DOC],\"username\":\"bob\",\"permissions\":1}")
echo "$OUT"
echo "$OUT" | grep -q '"ok":\[3,1\]' && ok "two shares created in one request" || bad "unexpected: $OUT"

note "alice shares the same two again -> both conflict"
OUT=$(req POST /api/shares/batch "$JA" "{\"file_ids\":[$A,$DOC],\"username\":\"bob\",\"permissions\":1}")
echo "$OUT"
FAILED=$(printf '%s' "$OUT" | perl -MJSON::PP -0777 -ne 'print scalar @{decode_json($_)->{failed}}')
[ "$FAILED" = "2" ] && ok "duplicate shares reported as failures" || bad "expected 2 failures: $OUT"

note "bob lists his mounts"
BOBLIST=$(req GET "/api/files" "$JB")
echo "$BOBLIST"
SHARED_A=$(idof "$BOBLIST" a.txt)
SHARED_DOCS=$(idof "$BOBLIST" docs)
echo "bob sees a.txt=$SHARED_A docs=$SHARED_DOCS"
[ -n "$SHARED_A" ] && [ -n "$SHARED_DOCS" ] && ok "shares visible to bob" || bad "bob sees no shares"

note "bob batch move (read-only share) -> per-item permission failures"
OUT=$(req POST "/api/files/batch/move" "$JB" "{\"ids\":[$SHARED_A,$SHARED_DOCS]}")
echo "$OUT"
FAILED=$(printf '%s' "$OUT" | perl -MJSON::PP -0777 -ne 'print scalar @{decode_json($_)->{failed}}')
[ "$FAILED" = "2" ] && ok "bob may not move -> 2 failures" || bad "expected 2 failures: $OUT"

note "bob batch delete (read-only share) -> failures"
OUT=$(req POST /api/files/batch/delete "$JB" "{\"ids\":[$SHARED_A]}")
echo "$OUT"

note "bob ZIP of the shared items (read allowed)"
TOKEN=$(req POST /api/files/zip "$JB" "{\"ids\":[$SHARED_A,$SHARED_DOCS]}")
echo "$TOKEN"
TOKEN=$(jget "$TOKEN" token)
curl -s -b "$JB" -D "$ROOT/bob-headers.txt" -o "$ROOT/bob.zip" "$BASE/api/files/zip?token=$TOKEN"
cat "$ROOT/bob-headers.txt" | head -8
perl -MIO::Uncompress::Unzip -e '
  my $u = IO::Uncompress::Unzip->new($ARGV[0]) or die $IO::Uncompress::Unzip::UnzipError;
  do { my $h = $u->getHeaderInfo(); print "  ", $h->{Name}, "\n"; } while ($u->nextStream());
' "$ROOT/bob.zip"

# ---- ZIP as alice ----
note "alice ZIP of [a.txt, docs] (folder with structure)"
[ -n "$D" ] && rm -f "$(blobpath "$D")"   # simulate content that vanished -> skipped, not fatal
TOKEN=$(req POST /api/files/zip "$JA" "{\"ids\":[$A,$DOC]}")
echo "$TOKEN"
TOKEN=$(jget "$TOKEN" token)
curl -s -b "$JA" -D "$ROOT/z-headers.txt" -o "$ROOT/z.zip" "$BASE/api/files/zip?token=$TOKEN"
grep -iE 'HTTP/|content-|content-disposition' "$ROOT/z-headers.txt"
perl -MIO::Uncompress::Unzip -e '
  my $u = IO::Uncompress::Unzip->new($ARGV[0]) or die $IO::Uncompress::Unzip::UnzipError;
  do { my $h = $u->getHeaderInfo(); print "  ", $h->{Name}, "\n"; } while ($u->nextStream());
' "$ROOT/z.zip"
grep -q "a.txt" "$ROOT/z.zip" && ok "a.txt in archive" || bad "a.txt missing"
grep -q "fxcloud-skipped.txt" "$ROOT/z.zip" && ok "skipped note present" || bad "skipped note missing"
perl -MIO::Uncompress::Unzip -e '
  my $u = IO::Uncompress::Unzip->new($ARGV[0]) or die $IO::Uncompress::Unzip::UnzipError;
  do {
    my $h = $u->getHeaderInfo();
    my $buf = ""; my $tmp;
    while (($u->read($tmp)) > 0) { $buf .= $tmp; }
    print "--- fxcloud-skipped.txt:\n$buf" if $h->{Name} eq "fxcloud-skipped.txt";
  } while ($u->nextStream());
' "$ROOT/z.zip"

note "re-download with the same token -> gone"
CODE=$(reqcode GET "/api/files/zip?token=$TOKEN" "$JA")
echo "status=$CODE"
[ "$CODE" = "410" ] && ok "token is single-use (410)" || bad "expected 410, got $CODE"

note "unknown token -> gone"
CODE=$(reqcode GET "/api/files/zip?token=does-not-exist" "$JA")
[ "$CODE" = "410" ] && ok "unknown token -> 410" || bad "expected 410, got $CODE"

note "single item download is named after the item"
TOKEN=$(req POST /api/files/zip "$JA" "{\"ids\":[$A]}")
TOKEN=$(jget "$TOKEN" token)
curl -s -b "$JA" -D "$ROOT/z1-headers.txt" -o "$ROOT/z1.zip" "$BASE/api/files/zip?token=$TOKEN"
grep -i content-disposition "$ROOT/z1-headers.txt"

note "restore d.txt blob and re-check its content in the archive"
printf 'DDDDDDDDDD' > "$(blobpath "$D")"
TOKEN=$(req POST /api/files/zip "$JA" "{\"ids\":[$DOC]}")
TOKEN=$(jget "$TOKEN" token)
curl -s -b "$JA" -o "$ROOT/z2.zip" "$BASE/api/files/zip?token=$TOKEN"
perl -MIO::Uncompress::Unzip -e '
  my $u = IO::Uncompress::Unzip->new($ARGV[0]) or die $IO::Uncompress::Unzip::UnzipError;
  do {
    my $h = $u->getHeaderInfo();
    print "  ", $h->{Name}, " mtime=", (defined $h->{MTime} ? $h->{MTime} : "n/a"), "\n";
  } while ($u->nextStream());
' "$ROOT/z2.zip"
perl -MIO::Uncompress::Unzip -e '
  my $u = IO::Uncompress::Unzip->new($ARGV[0]) or die $IO::Uncompress::Unzip::UnzipError;
  my $found = 0;
  do {
    my $h = $u->getHeaderInfo();
    my $buf = ""; my $tmp;
    while (($u->read($tmp)) > 0) { $buf .= $tmp; }
    if ($h->{Name} =~ m{(?:^|/)sub/d\.txt$}) { $found = ($buf eq "DDDDDDDDDD"); }
  } while ($u->nextStream());
  exit($found ? 0 : 1);
' "$ROOT/z2.zip" && ok "folder content matches byte for byte" || bad "content mismatch"
grep -q "fxcloud-skipped.txt" "$ROOT/z2.zip" && bad "unexpected skipped note" || ok "no skipped note once restored"

note "two same-named folders in one archive keep their subtrees apart"
D2RESP=$(req POST /api/files/folder "$JA" '{"name":"docs2"}')
D2=$(jget "$D2RESP" entry.id)
req POST /api/files/batch/copy "$JA" "{\"ids\":[$DOC],\"dest_parent\":$D2}" >/dev/null
DOC2LIST=$(req GET "/api/files?parent=$D2" "$JA")
DOC2=$(idof "$DOC2LIST" docs)
TOKEN=$(req POST /api/files/zip "$JA" "{\"ids\":[$DOC,$DOC2]}")
TOKEN=$(jget "$TOKEN" token)
curl -s -b "$JA" -o "$ROOT/z3.zip" "$BASE/api/files/zip?token=$TOKEN"
perl -MIO::Uncompress::Unzip -e '
  my $u = IO::Uncompress::Unzip->new($ARGV[0]) or die $IO::Uncompress::Unzip::UnzipError;
  do { my $h = $u->getHeaderInfo(); print "  ", $h->{Name}, "\n"; } while ($u->nextStream());
' "$ROOT/z3.zip"
grep -q "docs/sub/d.txt" "$ROOT/z3.zip" && ok "first folder keeps its name" || bad "first folder path missing"
grep -q "docs (2)/sub/d.txt" "$ROOT/z3.zip" && ok "second folder renamed, subtree follows" || bad "renamed subtree missing"

note "empty selection -> 400"
CODE=$(reqcode POST /api/files/zip "$JA" '{"ids":[]}')
[ "$CODE" = "400" ] && ok "zip with empty ids -> 400" || bad "expected 400, got $CODE"
for p in batch/delete batch/move batch/copy; do
  CODE=$(reqcode POST "/api/files/$p" "$JA" '{"ids":[]}')
  [ "$CODE" = "400" ] && ok "$p with empty ids -> 400" || bad "expected 400 from $p, got $CODE"
done
CODE=$(reqcode POST "/api/shares/batch" "$JA" '{"file_ids":[],"username":"bob"}')
[ "$CODE" = "400" ] && ok "shares/batch with empty ids -> 400" || bad "expected 400, got $CODE"

note "selection over the 1 GiB cap -> 400 with size"
sqlite3 "$DATA/fxcloud.db" "UPDATE files SET size=2147483648 WHERE id=$A;"
OUT=$(req POST /api/files/zip "$JA" "{\"ids\":[$A]}")
echo "$OUT"
echo "$OUT" | grep -q "too large" && ok "cap message returned" || bad "cap message missing: $OUT"
sqlite3 "$DATA/fxcloud.db" "UPDATE files SET size=10 WHERE id=$A;"

note "bob cannot use alice's token"
TOKEN=$(req POST /api/files/zip "$JA" "{\"ids\":[$A]}")
TOKEN=$(jget "$TOKEN" token)
CODE=$(reqcode GET "/api/files/zip?token=$TOKEN" "$JB")
[ "$CODE" = "410" ] && ok "foreign token -> 410" || bad "expected 410, got $CODE"

# ---- blob layout: fallback + startup migration ----
note "no loose files left in the blob root"
LOOSE=$(find "$DATA/blobs" -maxdepth 1 -type f | wc -l)
[ "$LOOSE" = "0" ] && ok "blob root only holds directories" || bad "$LOOSE loose files in blob root"

note "read falls back to the flat path (un-migrated blob)"
mv "$(blobpath "$D")" "$DATA/blobs/$D"
CODE=$(reqcode GET "/api/files/download?id=$D" "$JA")
[ "$CODE" = "200" ] && ok "download works from the flat path" || bad "expected 200, got $CODE"

note "orphan blob without a database row"
printf 'ORPHAN' > "$DATA/blobs/999999"

note "restart -> migration moves flat blobs (incl. orphan) into place"
restart_server || { bad "server did not restart"; tail -20 "$ROOT/server.log"; exit 1; }
ok "server restarted"
[ -f "$DATA/blobs/$D" ] && bad "flat blob not migrated" || ok "flat blob moved away"
[ -f "$(blobpath "$D")" ] && ok "blob back at <owner>/<year>/<h1>/<h2>" || bad "blob not at new path"
[ -f "$DATA/blobs/_orphans/0f/42/999999" ] \
  && ok "orphan moved to _orphans/0f/42/" \
  || { bad "orphan not at _orphans/0f/42/999999"; find "$DATA/blobs" -name 999999; }
grep -q "_orphans" "$ROOT/server.log" && ok "orphan move logged" || bad "no _orphans warning in the log"
CODE=$(reqcode GET "/api/files/download?id=$D" "$JA")
[ "$CODE" = "200" ] && ok "download works after migration" || bad "expected 200, got $CODE"

note "second restart -> migration is idempotent"
MIGRATED=$(grep -c "legacy flat blobs moved" "$ROOT/server.log")
restart_server || { bad "server did not restart"; tail -20 "$ROOT/server.log"; exit 1; }
[ "$(grep -c "legacy flat blobs moved" "$ROOT/server.log")" = "$MIGRATED" ] \
  && ok "no second migration run" || bad "migration ran again on a clean blob root"

note "delete keeps the blob on disk (the entry sits in the trash now)"
OUT=$(req POST /api/files/batch/delete "$JA" "{\"ids\":[$D]}")
echo "$OUT"
[ -f "$BLOB_D" ] && ok "blob kept on disk while the entry is trashed" || bad "blob removed while the entry should be in the trash"

# ---- storage quota ----
note "existing accounts carry the 1 GiB default quota"
QCOUNT=$(sqlite3 "$DATA/fxcloud.db" "SELECT COUNT(*) FROM users WHERE quota_bytes = 1073741824;")
[ "$QCOUNT" = "2" ] && ok "alice and bob both default to 1 GiB" || bad "expected 2 accounts at 1 GiB, got $QCOUNT"
ME=$(req GET /api/me "$JA")
echo "$ME"
echo "$ME" | grep -q '"quota_bytes":1073741824' && ok "me reports quota_bytes" || bad "quota_bytes missing in /api/me"

USED_API=$(jget "$ME" used_bytes)
USED_DB=$(sqlite3 "$DATA/fxcloud.db" "SELECT COALESCE(SUM(size),0) FROM files WHERE is_dir=0 AND owner_id=1;")
echo "used: api=$USED_API db=$USED_DB"
[ -n "$USED_API" ] && [ "$USED_API" = "$USED_DB" ] \
  && ok "used_bytes matches the DB sum" || bad "usage mismatch (api=$USED_API db=$USED_DB)"

note "a newly registered account gets the default quota automatically"
REG=$(req POST /api/register "$JA" '{"username":"carol","password":"correct-horse"}')
echo "$REG"
QCAROL=$(sqlite3 "$DATA/fxcloud.db" "SELECT quota_bytes FROM users WHERE username='carol';")
[ "$QCAROL" = "1073741824" ] && ok "carol registered with 1 GiB" || bad "carol's quota is $QCAROL"

note "upload beyond the quota -> 507 with a readable message"
printf 'JJJJJJJJJJ' > "$ROOT/src/j.txt"
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET quota_bytes = $USED_DB + 5 WHERE username='alice';"
RC=$(curl -s -o "$ROOT/quota.json" -w '%{http_code}' -b "$JA" -c "$JA" \
  -F "parent=$DOC" -F "file=@$ROOT/src/j.txt" "$BASE/api/files/upload")
echo "status=$RC body=$(cat "$ROOT/quota.json")"
[ "$RC" = "507" ] && ok "upload refused with 507" || bad "expected 507, got $RC"
grep -q "quota exceeded" "$ROOT/quota.json" && ok "quota message returned" || bad "quota message missing"

note "an upload that fits exactly still goes through"
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET quota_bytes = $USED_DB + 10 WHERE username='alice';"
RC=$(curl -s -o /dev/null -w '%{http_code}' -b "$JA" -c "$JA" \
  -F "parent=$DOC" -F "file=@$ROOT/src/j.txt" "$BASE/api/files/upload")
[ "$RC" = "200" ] && ok "upload at the limit succeeds" || bad "expected 200, got $RC"

note "copy beyond the quota -> reported per item, no partial copy"
USED_NOW=$(sqlite3 "$DATA/fxcloud.db" "SELECT COALESCE(SUM(size),0) FROM files WHERE is_dir=0 AND owner_id=1;")
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET quota_bytes = $USED_NOW WHERE username='alice';"
OUT=$(req POST /api/files/batch/copy "$JA" "{\"ids\":[$A],\"dest_parent\":$D2}")
echo "$OUT"
echo "$OUT" | grep -q "quota exceeded" && ok "batch copy reports the quota failure" || bad "expected quota failure: $OUT"
D2LIST=$(req GET "/api/files?parent=$D2" "$JA")
echo "$D2LIST"
echo "$D2LIST" | grep -q '"name":"a.txt"' && bad "partial copy left behind" || ok "no partial copy left behind"

note "deleting does not free the quota while the file sits in the trash"
JLIST=$(req GET "/api/files?parent=$DOC" "$JA")
JID=$(idof "$JLIST" j.txt)
BEFORE_USE=$(sqlite3 "$DATA/fxcloud.db" "SELECT COALESCE(SUM(size),0) FROM files WHERE is_dir=0 AND owner_id=1;")
[ -n "$JID" ] && req POST /api/files/batch/delete "$JA" "{\"ids\":[$JID]}" >/dev/null
USED_FREE=$(sqlite3 "$DATA/fxcloud.db" "SELECT COALESCE(SUM(size),0) FROM files WHERE is_dir=0 AND owner_id=1;")
[ "$USED_FREE" = "$BEFORE_USE" ] && ok "usage unchanged after delete (the trash still occupies the disk)" || bad "usage=$USED_FREE, expected unchanged $BEFORE_USE"
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET quota_bytes = 1073741824 WHERE username='alice';"
ME=$(req GET /api/me "$JA")
[ "$(jget "$ME" quota_bytes)" = "1073741824" ] && ok "quota restored to 1 GiB" || bad "quota not restored: $ME"

# ---- share dialog: user dropdown ----
note "share dialog gets a dropdown of accounts (GET /api/users)"
U=$(req GET /api/users "$JA")
echo "$U"
echo "$U" | grep -q '"username":"bob","display_name":"[^"]*","is_active":true' \
  && ok "bob listed as active" || bad "bob missing or malformed: $U"
echo "$U" | grep -q '"username":"carol"' && echo "$U" | grep -q '"is_active":false' \
  && ok "carol listed and marked inactive" || bad "inactive carol missing: $U"
echo "$U" | grep -q '"username":"alice"' && bad "alice lists herself" || ok "own account excluded"
echo "$U" | grep -Eq '"id":|"quota_bytes":|"password' \
  && bad "private fields leaked to other users" || ok "only picker fields in the payload"
RC=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/users")
[ "$RC" = "401" ] && ok "GET /api/users without session -> 401" || bad "expected 401, got $RC"

# ---- inline preview (lightbox) ----
note "browser-viewable files open inline (GET /api/files/preview)"
printf 'Hello, preview world! 0123456789' > "$ROOT/src/note.txt"   # 32 bytes
NR=$(up "$JA" "$DOC" note.txt)
NID=$(jget "$NR" entry.id)
[ -n "$NID" ] && ok "uploaded note.txt (id $NID)" || bad "note.txt upload failed: $NR"

PRE=$(curl -s -D "$ROOT/ph.txt" -b "$JA" "$BASE/api/files/preview?id=$NID")
grep -qi '^HTTP/[0-9.]* 200' "$ROOT/ph.txt" \
  && ok "note.txt preview -> 200" || bad "expected 200: $(head -1 "$ROOT/ph.txt")"
grep -qi '^content-type: text/plain' "$ROOT/ph.txt" \
  && ok "text/plain content type" || bad "type: $(grep -i '^content-type' "$ROOT/ph.txt")"
grep -qi '^x-content-type-options: nosniff' "$ROOT/ph.txt" \
  && ok "nosniff set" || bad "nosniff missing"
grep -qi '^content-disposition: inline' "$ROOT/ph.txt" \
  && ok "inline disposition (not attachment)" || bad "disposition: $(grep -i disposition "$ROOT/ph.txt")"
grep -qi '^content-security-policy: sandbox' "$ROOT/ph.txt" \
  && ok "CSP sandbox set" || bad "CSP sandbox missing"
grep -qi '^accept-ranges: bytes' "$ROOT/ph.txt" \
  && ok "accept-ranges: bytes" || bad "accept-ranges missing"
[ "$PRE" = "Hello, preview world! 0123456789" ] \
  && ok "body byte-identical" || bad "body mangled: $PRE"

PRE=$(curl -s -D "$ROOT/ph.txt" -b "$JA" -H 'Range: bytes=7-11' "$BASE/api/files/preview?id=$NID")
grep -qi '^HTTP/[0-9.]* 206' "$ROOT/ph.txt" && grep -qi '^content-range: bytes 7-11/32' "$ROOT/ph.txt" \
  && [ "$PRE" = "previ" ] && ok "range bytes=7-11 -> 206 + exact slice" || bad "range: $(head -1 "$ROOT/ph.txt") [$PRE]"
PRE=$(curl -s -D "$ROOT/ph.txt" -b "$JA" -H 'Range: bytes=-10' "$BASE/api/files/preview?id=$NID")
grep -qi '^content-range: bytes 22-31/32' "$ROOT/ph.txt" && [ "$PRE" = "0123456789" ] \
  && ok "suffix range bytes=-10 -> last 10 bytes" || bad "suffix range: [$PRE]"
PRE=$(curl -s -D "$ROOT/ph.txt" -b "$JA" -H 'Range: bytes=30-' "$BASE/api/files/preview?id=$NID")
grep -qi '^content-range: bytes 30-31/32' "$ROOT/ph.txt" && [ "$PRE" = "89" ] \
  && ok "open range bytes=30- -> tail" || bad "open range: [$PRE]"
RC=$(curl -s -o /dev/null -D "$ROOT/ph.txt" -w '%{http_code}' -b "$JA" -H 'Range: bytes=9999-' "$BASE/api/files/preview?id=$NID")
[ "$RC" = "416" ] && grep -qi '^content-range: bytes \*/32' "$ROOT/ph.txt" \
  && ok "unsatisfiable range -> 416 + bytes */32" || bad "expected 416: got $RC"

printf 'notreallyapngbutnamedso' > "$ROOT/src/pix.png"
PH=$(up "$JA" "$DOC" pix.png); PID=$(jget "$PH" entry.id)
curl -s -D "$ROOT/ph.txt" -o /dev/null -b "$JA" "$BASE/api/files/preview?id=$PID"
grep -qi '^content-type: image/png' "$ROOT/ph.txt" \
  && ok "png preview -> image/png (light box media)" || bad "png type: $(grep -i '^content-type' "$ROOT/ph.txt")"

printf '<!doctype html><p>hi<script>alert(1)</script>' > "$ROOT/src/evil.html"
EH=$(up "$JA" "$DOC" evil.html); EID=$(jget "$EH" entry.id)
curl -s -D "$ROOT/ph.txt" -o /dev/null -b "$JA" "$BASE/api/files/preview?id=$EID"
grep -qi '^content-type: text/html' "$ROOT/ph.txt" && grep -qi '^content-security-policy: sandbox' "$ROOT/ph.txt" \
  && ok "html preview -> text/html + sandbox" || bad "html: $(grep -iE '^content-type|security' "$ROOT/ph.txt")"

printf 'PK\003\004not-a-real-zip' > "$ROOT/src/data.zip"
ZH=$(up "$JA" "$DOC" data.zip); ZID=$(jget "$ZH" entry.id)
RC=$(reqcode GET "/api/files/preview?id=$ZID" "$JA")
[ "$RC" = "400" ] && ok "zip preview -> 400 (not browser-displayable)" || bad "expected 400 for zip, got $RC"
RC=$(reqcode GET "/api/files/preview?id=$DOC" "$JA")
[ "$RC" = "400" ] && ok "preview of a folder -> 400" || bad "expected 400 for folder, got $RC"
RC=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/files/preview?id=$NID")
[ "$RC" = "401" ] && ok "preview without session -> 401" || bad "expected 401, got $RC"

curl -s -D "$ROOT/ph.txt" -o /dev/null -b "$JA" "$BASE/api/files/download?id=$NID"
grep -qi '^content-disposition: attachment' "$ROOT/ph.txt" \
  && ok "download endpoint stays attachment" || bad "download disposition changed"

# ---- text editor (save via PUT /api/files/content) ----
note "the text editor saves content back to the file"
printf 'first version' > "$ROOT/src/edit.txt"
EDR=$(up "$JA" "$DOC" edit.txt); EDID=$(jget "$EDR" entry.id)
printf 'Gr\303\274\303\237e, Welt! second version' > "$ROOT/src/newcontent.txt"   # UTF-8
RC=$(curl -s -o "$ROOT/sv.json" -w '%{http_code}' -X PUT -b "$JA" \
  -H 'Content-Type: text/plain; charset=utf-8' --data-binary "@$ROOT/src/newcontent.txt" \
  "$BASE/api/files/content?id=$EDID")
[ "$RC" = "200" ] && ok "PUT content -> 200" || bad "expected 200, got $RC: $(cat "$ROOT/sv.json")"
PRE=$(curl -s -b "$JA" "$BASE/api/files/preview?id=$EDID")
[ "$PRE" = "$(cat "$ROOT/src/newcontent.txt")" ] \
  && ok "preview serves the new content (UTF-8 intact)" || bad "content mismatch: [$PRE]"
SIZE=$(wc -c < "$ROOT/src/newcontent.txt")
EDLIST=$(req GET "/api/files?parent=$DOC" "$JA")
FSIZE=$(printf '%s' "$EDLIST" | perl -MJSON::PP -0777 -e '
  my $n = shift;
  my $d = decode_json(do { local $/; <STDIN> });
  for my $e (@{$d->{entries}}) { print $e->{size} if $e->{name} eq $n }
' edit.txt)
[ "$FSIZE" = "$SIZE" ] && ok "listing reports the new size" || bad "size=$FSIZE, expected $SIZE"

note "editor permission rules"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: text/plain' \
  --data-binary 'x' "$BASE/api/files/content?id=$EDID")
[ "$RC" = "401" ] && ok "save without session -> 401" || bad "expected 401, got $RC"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -b "$JB" -H 'Content-Type: text/plain' \
  --data-binary 'x' "$BASE/api/files/content?id=$EDID")
[ "$RC" = "403" ] && ok "save to an unshared file (bob) -> 403" || bad "expected 403, got $RC"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -b "$JB" -H 'Content-Type: text/plain' \
  --data-binary 'x' "$BASE/api/files/content?id=$SHARED_A")
[ "$RC" = "403" ] && ok "read-only share -> 403 (needs PERM_UPDATE)" || bad "expected 403, got $RC"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -b "$JA" -H 'Content-Type: text/plain' \
  --data-binary 'x' "$BASE/api/files/content?id=$DOC")
[ "$RC" = "400" ] && ok "save to a folder -> 400" || bad "expected 400 for folder, got $RC"

note "a write share lets the grantee save, the owner sees it"
req POST /api/shares/batch "$JA" "{\"file_ids\":[$EDID],\"username\":\"bob\",\"permissions\":3}" >/dev/null
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -b "$JB" -H 'Content-Type: text/plain' \
  --data-binary 'written by bob' "$BASE/api/files/content?id=$EDID")
[ "$RC" = "200" ] && ok "write share -> save allowed" || bad "expected 200 for write share, got $RC"
PRE=$(curl -s -b "$JA" "$BASE/api/files/preview?id=$EDID")
[ "$PRE" = "written by bob" ] && ok "owner sees bob's edit" || bad "owner view: [$PRE]"

note "editor save beyond the quota -> 507"
USED_NOW=$(sqlite3 "$DATA/fxcloud.db" "SELECT COALESCE(SUM(size),0) FROM files WHERE is_dir=0 AND owner_id=1;")
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET quota_bytes = $USED_NOW + 6 WHERE username='alice';"
RC=$(curl -s -o "$ROOT/quota.json" -w '%{http_code}' -X PUT -b "$JA" -H 'Content-Type: text/plain' \
  --data-binary 'this content does not fit at all' "$BASE/api/files/content?id=$EDID")
echo "status=$RC body=$(cat "$ROOT/quota.json")"
[ "$RC" = "507" ] && grep -q "quota exceeded" "$ROOT/quota.json" \
  && ok "oversized save -> 507 with the quota message" || bad "expected 507, got $RC"
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET quota_bytes = 1073741824 WHERE username='alice';"

# ---- create new text files ----
note "POST /api/files/file creates an empty editable file"
OUT=$(req POST /api/files/file "$JA" "{\"parent_id\":$DOC,\"name\":\"fresh.md\"}")
echo "$OUT"
NFILE=$(jget "$OUT" entry.id)
NSIZE=$(jget "$OUT" entry.size)
[ -n "$NFILE" ] && [ "$NSIZE" = "0" ] && ok "fresh.md created empty (id $NFILE)" || bad "create failed: $OUT"
PRE=$(curl -s -D "$ROOT/ph.txt" -b "$JA" "$BASE/api/files/preview?id=$NFILE")
grep -qi '^HTTP/[0-9.]* 200' "$ROOT/ph.txt" && [ -z "$PRE" ] \
  && ok "preview of the empty file -> 200, empty body" || bad "empty preview: $(head -1 "$ROOT/ph.txt") [$PRE]"
RC=$(curl -s -o "$ROOT/cr.json" -w '%{http_code}' -X POST -b "$JA" -H 'Content-Type: application/json' \
  -d "{\"parent_id\":$DOC,\"name\":\"fresh.md\"}" "$BASE/api/files/file")
[ "$RC" = "409" ] && grep -q "already exists" "$ROOT/cr.json" \
  && ok "duplicate name -> 409" || bad "duplicate: $RC $(cat "$ROOT/cr.json")"
RC=$(curl -s -o "$ROOT/cr.json" -w '%{http_code}' -X POST -b "$JA" -H 'Content-Type: application/json' \
  -d "{\"parent_id\":$DOC,\"name\":\"bad/name.txt\"}" "$BASE/api/files/file")
[ "$RC" = "400" ] && grep -q "invalid characters" "$ROOT/cr.json" \
  && ok "slash in name -> 400" || bad "slash name: $RC $(cat "$ROOT/cr.json")"
RC=$(reqcode POST /api/files/file "$JA" "{\"parent_id\":$NFILE,\"name\":\"x.txt\"}")
[ "$RC" = "400" ] && ok "file as parent -> 400" || bad "file parent: $RC"
RC=$(reqcode POST /api/files/file "$JB" "{\"parent_id\":$DOC,\"name\":\"x.txt\"}")
[ "$RC" = "403" ] && ok "bob without CREATE share -> 403" || bad "bob create: $RC"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -d "{\"parent_id\":$DOC,\"name\":\"x.txt\"}" "$BASE/api/files/file")
[ "$RC" = "401" ] && ok "create without session -> 401" || bad "no session: $RC"

# ---- version badge next to the logo ----
note "header shows the release version"
VER=$(grep -m1 '^version' "$REPO/Cargo.toml" | cut -d'"' -f2)
IBODY=$(curl -s -b "$JA" "$BASE/")
case "$IBODY" in
  *"v$VER"*) ok "app header shows v$VER next to the logo" ;;
  *) bad "version badge missing (want v$VER)" ;;
esac

# ---- folder sizes in the listing ----
note "listing shows recursive folder sizes (subtree_bytes)"
SIZEF=$(jget "$(req POST /api/files/folder "$JA" '{"name":"sizetest"}')" entry.id)
SIZEI=$(jget "$(req POST /api/files/folder "$JA" "{\"parent_id\":$SIZEF,\"name\":\"inner\"}")" entry.id)
SIZE2=$(jget "$(req POST /api/files/folder "$JA" "{\"parent_id\":$SIZEI,\"name\":\"deep\"}")" entry.id)
EMPTYF=$(jget "$(req POST /api/files/folder "$JA" "{\"parent_id\":$SIZEF,\"name\":\"emptydir\"}")" entry.id)
head -c 100 /dev/zero > "$ROOT/src/sz1.bin"
head -c 50 /dev/zero > "$ROOT/src/sz2.bin"
head -c 25 /dev/zero > "$ROOT/src/sz3.bin"
up "$JA" "$SIZEF" sz1.bin >/dev/null
up "$JA" "$SIZEI" sz2.bin >/dev/null
up "$JA" "$SIZE2" sz3.bin >/dev/null
L=$(req GET "/api/files?parent=$SIZEF" "$JA")
V=$(subsize "$L" inner)
[ "$V" = "75" ] && ok "inner folder reports 75 bytes" || bad "inner=$V, expected 75"
V=$(subsize "$L" emptydir)
[ "$V" = "0" ] && ok "empty folder reports 0" || bad "emptydir=$V, expected 0"
L=$(req GET "/api/files?parent=$SIZEI" "$JA")
V=$(subsize "$L" deep)
[ "$V" = "25" ] && ok "deep folder reports 25 bytes" || bad "deep=$V, expected 25"
L=$(req GET "/api/files" "$JA")
V=$(subsize "$L" sizetest)
[ "$V" = "175" ] && ok "sizetest reports 175 bytes (whole subtree)" || bad "sizetest=$V, expected 175"
V=$(subsize "$L" sz1.bin)
[ -z "$V" ] && ok "file rows carry no subtree_bytes" || bad "file has subtree_bytes=$V"
BL=$(req GET /api/files "$JB")
V=$(subsize "$BL" docs)
[ -n "$V" ] && ok "shared folder shows a size to bob (mount branch)" || bad "bob's docs lacks subtree_bytes"

# ---- trash: delete -> restore -> retention purge ----
note "trash: delete to trash, restore, purge"

# Deleting a file moves it to the trash, not out of existence.
FID=$(idof "$(req GET "/api/files?parent=$DOC" "$JA")" fresh.md)
[ "$(reqcode POST /api/files/delete "$JA" "{\"id\":$FID}")" = "200" ] \
  && [ -z "$(idof "$(req GET "/api/files?parent=$DOC" "$JA")" fresh.md)" ] \
  && ok "deleted file leaves its folder" || bad "delete-to-trash failed"
TR=$(req GET /api/files/trash "$JA")
[ "$(jget "$TR" entries.0.name)" = "fresh.md" ] && ok "deleted file shows up in the trash" || bad "trash is missing fresh.md"
[ -n "$(jget "$TR" entries.0.deleted_at)" ] && [ -n "$(jget "$TR" entries.0.purge_at)" ] \
  && ok "trash rows carry deleted_at and purge_at" || bad "trash timestamps missing"

# Restore brings it back to the original folder, content intact.
[ "$(reqcode POST /api/files/trash/restore "$JA" "{\"id\":$FID}")" = "200" ] || bad "restore call failed"
L=$(req GET "/api/files?parent=$DOC" "$JA")
[ "$(idof "$L" fresh.md)" = "$FID" ] && ok "restore returns the file to its folder" || bad "restored id mismatch"
head -c 20 /dev/zero > "$ROOT/src/tc.bin"
up "$JA" "$DOC" tc.bin >/dev/null
TC=$(idof "$(req GET "/api/files?parent=$DOC" "$JA")" tc.bin)
[ "$(reqcode POST /api/files/delete "$JA" "{\"id\":$TC}")" = "200" ] \
  && [ "$(reqcode POST /api/files/trash/restore "$JA" "{\"id\":$TC}")" = "200" ] \
  || bad "content round-trip calls failed"
SZ1=$(curl -s -b "$JA" "$BASE/api/files/download?id=$TC" | wc -c)
[ "$SZ1" = "20" ] && ok "restored file kept its content (20 bytes)" || bad "content lost on restore: $SZ1 bytes"

# A name taken in the meantime gets a " (restored)" suffix.
[ "$(reqcode POST /api/files/delete "$JA" "{\"id\":$FID}")" = "200" ] || bad "second delete failed"
printf 'replacement\n' > "$ROOT/src/fresh.md"
up "$JA" "$DOC" fresh.md >/dev/null
[ "$(reqcode POST /api/files/trash/restore "$JA" "{\"id\":$FID}")" = "200" ] || bad "conflict restore failed"
L=$(req GET "/api/files?parent=$DOC" "$JA")
[ -n "$(idof "$L" "fresh.md (restored)")" ] && ok "restore suffixes a taken name" || bad "no suffixed entry"
[ -n "$(idof "$L" fresh.md)" ] && ok "the replacement file stays untouched" || bad "replacement vanished"

# A trashed folder is one restore unit, subtree size included.
SZ=$(idof "$(req GET /api/files "$JA")" sizetest)
[ "$(reqcode POST /api/files/delete "$JA" "{\"id\":$SZ}")" = "200" ] || bad "folder delete failed"
[ -z "$(idof "$(req GET /api/files "$JA")" sizetest)" ] && ok "trashed folder leaves the root listing" || bad "sizetest still listed"
TR=$(req GET /api/files/trash "$JA")
[ "$(jget "$TR" entries.0.name)" = "sizetest" ] && [ "$(subsize "$TR" sizetest)" = "175" ] \
  && ok "trash lists the folder as one root with 175 bytes" || bad "trash folder row wrong"
[ "$(reqcode POST /api/files/trash/restore "$JA" "{\"id\":$SZ}")" = "200" ] || bad "folder restore failed"
V=$(subsize "$(req GET /api/files "$JA")" sizetest)
[ "$V" = "175" ] && ok "restore brings back the whole subtree (175 bytes)" || bad "subtree size: $V"

# Retention purge: an aged entry is hard-deleted by the sweep.
FID2=$(idof "$(req GET "/api/files?parent=$DOC" "$JA")" "fresh.md (restored)")
[ "$(reqcode POST /api/files/delete "$JA" "{\"id\":$FID2}")" = "200" ] || bad "aged-item delete failed"
sqlite3 "$DATA/fxcloud.db" "UPDATE files SET deleted_at='2020-01-01T00:00:00Z' WHERE id=$FID2;"
GONE=""
for _ in 1 2 3 4 5 6 7 8; do
  sleep 1
  case "$(req GET /api/files/trash "$JA")" in *"fresh.md (restored)"*) ;; *) GONE=1; break ;; esac
done
[ -n "$GONE" ] && [ "$(sqlite3 "$DATA/fxcloud.db" "SELECT COUNT(*) FROM files WHERE id=$FID2;")" = "0" ] \
  && ok "expired trash is purged for good after the sweep" || bad "expired entry survived"

# Empty trash removes everything at once.
head -c 5 /dev/zero > "$ROOT/src/e1.bin"
head -c 6 /dev/zero > "$ROOT/src/e2.bin"
up "$JA" "$DOC" e1.bin >/dev/null
up "$JA" "$DOC" e2.bin >/dev/null
E1=$(idof "$(req GET "/api/files?parent=$DOC" "$JA")" e1.bin)
E2=$(idof "$(req GET "/api/files?parent=$DOC" "$JA")" e2.bin)
BLOB_E1=$(blobpath "$E1")   # capture the path while the row still exists
[ "$(reqcode POST /api/files/delete "$JA" "{\"id\":$E1}")" = "200" ] || bad "e1 delete failed"
[ "$(reqcode POST /api/files/delete "$JA" "{\"id\":$E2}")" = "200" ] || bad "e2 delete failed"
[ "$(reqcode POST /api/files/trash/empty "$JA" '{}')" = "200" ] || bad "empty-trash call failed"
N=$(printf '%s' "$(req GET /api/files/trash "$JA")" | perl -MJSON::PP -0777 -e 'print scalar @{decode_json(do{local $/;<STDIN>})->{entries}}')
[ "$N" = "0" ] && ok "empty trash clears every item" || bad "trash still holds $N item(s)"
[ ! -f "$BLOB_E1" ] && ok "purged trash unlinks the blobs from disk" || bad "blob still on disk after purge"

# A grantee's delete lands in the owner's trash, not in their own.
TS=$(jget "$(req POST /api/files/folder "$JA" '{"name":"trashshare"}')" entry.id)
printf 'shared\n' > "$ROOT/src/shared.txt"
up "$JA" "$TS" shared.txt >/dev/null
[ "$(reqcode POST /api/shares "$JA" "{\"file_id\":$TS,\"username\":\"bob\",\"permissions\":15}")" = "200" ] || bad "share for trash test failed"
BF=$(idof "$(req GET "/api/files?parent=$TS" "$JB")" shared.txt)
[ "$(reqcode POST /api/files/delete "$JB" "{\"id\":$BF}")" = "200" ] || bad "bob's delete failed"
[ -z "$(jget "$(req GET /api/files/trash "$JB")" entries.0.name)" ] \
  && ok "grantee's delete leaves the grantee's trash empty" || bad "bob unexpectedly has trash"
[ "$(jget "$(req GET /api/files/trash "$JA")" entries.0.name)" = "shared.txt" ] \
  && ok "the deleted file lands in the owner's trash" || bad "alice's trash lacks shared.txt"
[ "$(reqcode POST /api/files/trash/restore "$JA" "{\"id\":$BF}")" = "200" ] || bad "owner restore failed"
[ -n "$(idof "$(req GET "/api/files?parent=$TS" "$JB")" shared.txt)" ] \
  && ok "restore brings the file back into the shared view" || bad "still missing for bob"

# Frontend guard: every async entry point invoked as `name().catch(...)` (the
# pattern the toolbar/menu wiring uses) must have a definition. A missing one
# throws a ReferenceError in the browser and the button silently does nothing,
# which no API check would ever see.
# ---- client-side encryption (ENCRYPTION.md) -------------------------------
# The server stores wrapped blobs it cannot open. What it must not do is leak
# them, believe a client that says "this is encrypted" without looking, or let
# a plaintext write reach an encrypted row. The client half of DECISION 10
# (the WebCrypto round trip) runs in Node at the end of this section.
note "keys: storage, visibility and the KDF floor"


reqsave() { # reqsave METHOD path jar outfile [json] -> prints the status code
  local method=$1 path=$2 jar=$3 out=$4 body=${5:-}
  if [ -n "$body" ]; then
    curl -s -o "$out" -w '%{http_code}' -X "$method" -b "$jar" -c "$jar" \
      -H 'Content-Type: application/json' -d "$body" "$BASE$path"
  else
    curl -s -o "$out" -w '%{http_code}' -X "$method" -b "$jar" -c "$jar" "$BASE$path"
  fi
}

# Base64 in a query string: `+` would otherwise be read back as a space,
# which is exactly the kind of silent corruption that shows up as "wrong
# key" three layers later.
urlencode() {
  printf '%s' "$1" | perl -0777 -pe 's/([^A-Za-z0-9_.~-])/sprintf("%%%02X", ord($1))/ge'
}

# field <listing-json> <name> <key> -> that one field of that one row
field() {
  printf '%s' "$1" | perl -MJSON::PP -0777 -e '
    my ($name, $key) = @ARGV;
    my $d = decode_json(do { local $/; <STDIN> });
    for my $e (@{$d->{entries} || []}) {
      next unless defined $e->{name} && $e->{name} eq $name;
      my $v = $e->{$key};
      print ref($v) ? encode_json($v) : (defined $v ? $v : "");
      last;
    }' "$2" "$3"
}

RC=$(reqsave GET /api/keys/me "$JA" "$ROOT/k.json")
[ "$RC" = "404" ] && ok "GET /api/keys/me before setup -> 404" || bad "keys/me: $RC"

RC=$(reqsave PUT /api/keys/me "$JA" "$ROOT/k.json" \
  '{"wrapped_ark":"YXJr","kdf_salt":"c2FsdA==","kdf_params":{"kdf":"argon2id","m":65536,"t":3,"p":1}}')
[ "$RC" = "409" ] && ok "PUT /api/keys/me before setup -> 409 (nothing to rewrap)" \
  || bad "rewrap unset: $RC $(cat "$ROOT/k.json")"

RC=$(reqsave PUT /api/keys/me "$JA" "$ROOT/k.json" \
  '{"wrapped_ark":"YXJr","kdf_salt":"c2FsdA==","kdf_params":{"kdf":"argon2id","m":8192,"t":3,"p":1}}')
[ "$RC" = "400" ] && grep -q "m >= 65536" "$ROOT/k.json" \
  && ok "rewrap below the KDF floor -> 400 with the floor message" \
  || bad "rewrap floor: $RC $(cat "$ROOT/k.json")"

# A payload that is refused must not leave half a key row behind: setup is
# all-or-nothing, because a half-written record would be indistinguishable
# from a real one on the next GET.
FAKE='"public_key":"cHVibGlj","private_key_wrapped":"cHJpdg==","wrapped_ark":"YXJr","wrapped_root_key":"cm9vdA==","wrapped_ark_recovery":"cmVj","kdf_salt":"c2FsdA==","fingerprint":"deadbeefdeadbeefdeadbeefdeadbeef"'

RC=$(reqsave POST /api/keys/setup "$JA" "$ROOT/k.json" \
  "{$FAKE,\"kdf_params\":{\"kdf\":\"argon2id\",\"m\":8192,\"t\":3,\"p\":1}}")
[ "$RC" = "400" ] && grep -q "too weak" "$ROOT/k.json" \
  && ok "setup with m=8192 -> 400 (server-side KDF floor)" || bad "floor m: $RC $(cat "$ROOT/k.json")"
RC=$(reqsave POST /api/keys/setup "$JA" "$ROOT/k.json" \
  "{$FAKE,\"kdf_params\":{\"kdf\":\"argon2id\",\"m\":65536,\"t\":1,\"p\":1}}")
[ "$RC" = "400" ] && grep -q "too weak" "$ROOT/k.json" \
  && ok "setup with t=1 -> 400" || bad "floor t: $RC $(cat "$ROOT/k.json")"
RC=$(reqsave POST /api/keys/setup "$JA" "$ROOT/k.json" \
  "{$FAKE,\"kdf_params\":{\"kdf\":\"pbkdf2\",\"m\":65536,\"t\":3,\"p\":1}}")
[ "$RC" = "400" ] && grep -q "argon2id" "$ROOT/k.json" \
  && ok "setup with kdf=pbkdf2 -> 400" || bad "kdf name: $RC $(cat "$ROOT/k.json")"
RC=$(reqsave POST /api/keys/setup "$JA" "$ROOT/k.json" "{$FAKE,\"kdf_params\":65536}")
[ "$RC" = "400" ] && ok "kdf_params that is not an object -> 400" || bad "kdf object: $RC"
RC=$(reqsave POST /api/keys/setup "$JA" "$ROOT/k.json" \
  '{"public_key":"cHVibGlj","kdf_params":{"kdf":"argon2id","m":65536,"t":3,"p":1}}')
[ "$RC" != "200" ] && ok "incomplete setup payload -> $RC (rejected)" || bad "incomplete setup accepted"
RC=$(reqsave GET /api/keys/me "$JA" "$ROOT/k.json")
[ "$RC" = "404" ] && ok "no partial key row survived the rejected payload" || bad "half a row exists: $RC"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -d "$FAKE" "$BASE/api/keys/setup")
[ "$RC" = "401" ] && ok "setup without a session -> 401" || bad "setup unauthenticated: $RC"

note "a real account round trip: setup -> store -> unlock from the server's bytes"
FXP=$ROOT/keys-payload.json
FXS=$ROOT/keys-state.json
FP=$("$NODE" "$FXTOOL" setup 'storage-pass-1' "$FXP" "$FXS" 2>"$ROOT/fx.err")
[ -n "$FP" ] && ok "client generated key material (fingerprint ${FP:0:8}...)" \
  || bad "fxtool setup failed: $(cat "$ROOT/fx.err")"

RC=$(reqsave POST /api/keys/setup "$JA" "$ROOT/k.json" "$(cat "$FXP")")
[ "$RC" = "200" ] && ok "POST /api/keys/setup -> 200" || bad "setup: $RC $(cat "$ROOT/k.json")"

# A client that lost the response has to be able to retry.
RC=$(reqsave POST /api/keys/setup "$JA" "$ROOT/k.json" "$(cat "$FXP")")
[ "$RC" = "200" ] && ok "identical setup replay -> 200 (idempotent)" || bad "replay: $RC"

# Different material for an account that is already set up must never win:
# every file key is wrapped under the root key this would strand.
ALT=$(perl -MJSON::PP -0777 -e '
  my $j = decode_json(do { local $/; <STDIN> });
  $j->{public_key} = "YWx0ZXJwdWJsaWM=";
  $j->{fingerprint} = "0123456789abcdef0123456789abcdef";
  print encode_json($j);' < "$FXP")
RC=$(reqsave POST /api/keys/setup "$JA" "$ROOT/k.json" "$ALT")
[ "$RC" = "409" ] && grep -q "already set up" "$ROOT/k.json" \
  && ok "a different setup payload -> 409 (never overwrites)" \
  || bad "alt setup: $RC $(cat "$ROOT/k.json")"

RC=$(reqsave GET /api/keys/me "$JA" "$ROOT/mine.json")
[ "$RC" = "200" ] || bad "keys/me after setup: $RC"
perl -MJSON::PP -0777 -e '
  my $j = decode_json(do { local $/; <STDIN> });
  my $k = $j->{keys};
  exit 1 unless ref($k) eq "HASH";
  for my $f (qw(public_key private_key_wrapped wrapped_ark wrapped_root_key
                 wrapped_ark_recovery kdf_salt kdf_params fingerprint)) {
    exit 2 unless exists $k->{$f};
  }
  exit 3 unless ref($k->{kdf_params}) eq "HASH";
  exit 0;
' < "$ROOT/mine.json" \
  && ok "GET /api/keys/me returns the whole wrapped record" \
  || bad "keys/me shape: $(cat "$ROOT/mine.json")"

note "public key lookup exposes the public half and nothing else"
RC=$(reqsave GET /api/keys/alice "$JA" "$ROOT/pub.json")
[ "$RC" = "200" ] && grep -q '"public_key"' "$ROOT/pub.json" && grep -q 'fingerprint' "$ROOT/pub.json" \
  && ok "GET /api/keys/alice -> 200 with the public key and fingerprint" \
  || bad "public key: $RC $(cat "$ROOT/pub.json")"
grep -Eq 'wrapped_ark|private_key_wrapped|wrapped_root_key|wrapped_ark_recovery|kdf_salt' \
  "$ROOT/pub.json" \
  && bad "public endpoint leaks wrapped material: $(cat "$ROOT/pub.json")" \
  || ok "public endpoint exposes no wrapped private material"
RC=$(reqsave GET /api/keys/doesnotexist "$JA" "$ROOT/pub.json")
[ "$RC" = "404" ] && ok "unknown username -> 404" || bad "unknown user: $RC"
RC=$(reqsave GET /api/keys/bob "$JA" "$ROOT/pub.json")
[ "$RC" = "404" ] && ok "an account that never enabled encryption -> 404" \
  || bad "bob unexpectedly has keys: $RC"

note "a passphrase change rewraps the ARK and nothing under it"
"$NODE" "$FXTOOL" rewrap "$FXS" 'a-brand-new-pass' "$ROOT/rewrap.json" >/dev/null 2>&1 \
  && ok "client produced a rewrap body" || bad "fxtool rewrap failed"
RC=$(reqsave PUT /api/keys/me "$JA" "$ROOT/k.json" "$(cat "$ROOT/rewrap.json")")
[ "$RC" = "200" ] && ok "PUT /api/keys/me -> 200" || bad "rewrap: $RC $(cat "$ROOT/k.json")"
reqsave GET /api/keys/me "$JA" "$ROOT/mine.json" >/dev/null
perl -MJSON::PP -0777 -e 'print encode_json(decode_json(do{local $/;<STDIN>})->{keys})' \
  < "$ROOT/mine.json" > "$ROOT/keys.json"
"$NODE" "$FXTOOL" unlock 'storage-pass-1' "$ROOT/keys.json" "$ROOT/after.json" >/dev/null 2>&1 \
  && bad "the old passphrase still opens the rewrapped record" \
  || ok "the old passphrase no longer opens the account"
"$NODE" "$FXTOOL" unlock 'a-brand-new-pass' "$ROOT/keys.json" "$ROOT/after.json" >/dev/null 2>&1 \
  && ok "the new passphrase opens what the server stored" \
  || bad "the new passphrase fails against the stored record"
K1=$(perl -MJSON::PP -e 'print decode_json(do{local $/;<STDIN>})->{rootKey}' < "$FXS")
K2=$(perl -MJSON::PP -e 'print decode_json(do{local $/;<STDIN>})->{rootKey}' < "$ROOT/after.json")
[ -n "$K1" ] && [ "$K1" = "$K2" ] \
  && ok "the root key is unchanged by the rewrap (O(1), no re-encryption)" \
  || bad "the root key moved during a rewrap"

note "encrypted upload: two-phase create, then fill with ciphertext"
ENCP=$ROOT/enc-plain.txt
printf 'the quick brown fox jumps over the lazy dog\n' > "$ENCP"
RC=$(reqsave POST /api/files/file "$JA" "$ROOT/k.json" "{\"parent_id\":$DOC,\"name\":\"secret.txt\"}")
EID=$(jget "$(cat "$ROOT/k.json")" entry.id)
[ "$RC" = "200" ] && [ -n "$EID" ] \
  && ok "the row is reserved first, so the ciphertext has an id (id $EID)" \
  || bad "create_file: $RC $(cat "$ROOT/k.json")"

EKEY=$("$NODE" "$FXTOOL" encrypt "$FXS" "$EID" "$ENCP" "$ROOT/enc-cipher.bin" 2>"$ROOT/fx.err")
[ -n "$EKEY" ] && ok "client encrypted the body against that id" || bad "fxtool encrypt: $(cat "$ROOT/fx.err")"
CSIZE=$(wc -c < "$ROOT/enc-cipher.bin")
PSIZE=$(wc -c < "$ENCP")
[ "$CSIZE" -gt "$PSIZE" ] && ok "container is plaintext + per-chunk tags ($CSIZE > $PSIZE)" \
  || bad "sizes: $CSIZE vs $PSIZE"

RC=$(curl -s -o "$ROOT/k.json" -w '%{http_code}' -X PUT -b "$JA" -c "$JA" \
  -H 'Content-Type: application/octet-stream' --data-binary "@$ROOT/enc-cipher.bin" \
  "$BASE/api/files/content?id=$EID&enc=1&key=$(urlencode "$EKEY")")
[ "$RC" = "200" ] && ok "PUT enc=1&key=<b64> with an FXE1 body -> 200" \
  || bad "enc=1 put: $RC $(cat "$ROOT/k.json")"

ELIST=$(req GET "/api/files?parent=$DOC" "$JA")
[ "$(field "$ELIST" secret.txt enc_version)" = "1" ] \
  && ok "the listing reports enc_version=1" || bad "enc_version is not 1"
EK=$(field "$ELIST" secret.txt enc_key)
[ -n "$EK" ] && ok "the listing carries the wrapped key" || bad "no enc_key in the listing"
ESZ=$(field "$ELIST" secret.txt size)
[ "$ESZ" = "$CSIZE" ] && ok "size is the ciphertext size ($ESZ)" || bad "size=$ESZ want $CSIZE"
INFO=$(req GET "/api/files/info?id=$EID" "$JA")
[ "$(jget "$INFO" entry.enc_version)" = "1" ] && [ -n "$(jget "$INFO" entry.enc_key)" ] \
  && ok "files/info exposes both enc_version and enc_key" || bad "info: $INFO"

note "decrypt on download - and only on download"
curl -s -D "$ROOT/dh.txt" -o "$ROOT/enc-got.bin" -b "$JA" "$BASE/api/files/download?id=$EID"
grep -qi '^content-type: application/octet-stream' "$ROOT/dh.txt" \
  && ok "download advertises application/octet-stream" \
  || bad "type: $(grep -i '^content-type' "$ROOT/dh.txt")"
cmp -s "$ROOT/enc-cipher.bin" "$ROOT/enc-got.bin" \
  && ok "the ciphertext comes back byte-identical" || bad "downloaded body differs"
"$NODE" "$FXTOOL" decrypt "$FXS" "$EID" "$ROOT/enc-got.bin" "$EK" "$ROOT/enc-back.txt" \
  >/dev/null 2>&1 \
  && cmp -s "$ENCP" "$ROOT/enc-back.txt" \
  && ok "round trip: encrypt -> server -> decrypt == the original file" \
  || bad "decrypt round trip failed"
"$NODE" "$FXTOOL" decrypt "$FXS" "$((EID + 1))" "$ROOT/enc-got.bin" "$EK" "$ROOT/enc-wrong.txt" \
  >/dev/null 2>&1 \
  && bad "the wrapped key opened under a different row id" \
  || ok "the wrapped key is bound to its row id (AAD mismatch refused)"
RC=$(reqcode GET "/api/files/preview?id=$EID" "$JA")
[ "$RC" = "400" ] && ok "preview of an encrypted row -> 400" || bad "preview: $RC"

note "an encrypted row only ever accepts FXE1 content"
printf 'plain overwrite attempt' > "$ROOT/src/attempt.txt"
RC=$(curl -s -o "$ROOT/k.json" -w '%{http_code}' -X PUT -b "$JA" -c "$JA" \
  -H 'Content-Type: text/plain' --data-binary "@$ROOT/src/attempt.txt" \
  "$BASE/api/files/content?id=$EID")
[ "$RC" = "409" ] && grep -q "encrypt" "$ROOT/k.json" \
  && ok "plaintext PUT onto an encrypted row -> 409" || bad "plain put: $RC $(cat "$ROOT/k.json")"
RC=$(reqcode PUT "/api/files/content?id=$EID&enc=1" "$JA")
[ "$RC" = "400" ] && ok "enc=1 without a key -> 400" || bad "enc without key: $RC"
RC=$(reqcode PUT "/api/files/content?id=$EID&enc=0" "$JA")
[ "$RC" = "409" ] && ok "enc=0 on an encrypted row -> 409 (cannot be undone here)" \
  || bad "enc=0: $RC"
RC=$(reqcode PUT "/api/files/content?id=$EID&key=c2VjcmV0" "$JA")
[ "$RC" = "400" ] && ok "a key without enc=1 -> 400" || bad "key without enc: $RC"
RC=$(curl -s -o "$ROOT/k.json" -w '%{http_code}' -X PUT -b "$JA" -c "$JA" \
  --data-binary "@$ROOT/enc-cipher.bin" \
  "$BASE/api/files/content?id=$EID&enc=1&key=")
[ "$RC" = "400" ] && grep -q "empty" "$ROOT/k.json" \
  && ok "enc=1 with an empty key -> 400" || bad "empty key: $RC $(cat "$ROOT/k.json")"
RC=$(curl -s -o "$ROOT/k.json" -w '%{http_code}' -X PUT -b "$JA" -c "$JA" \
  --data-binary "@$ROOT/enc-cipher.bin" \
  "$BASE/api/files/content?id=$EID&enc=1&key=!!!not-base64!!!")
[ "$RC" = "400" ] && grep -q "base64" "$ROOT/k.json" \
  && ok "a non-base64 key -> 400" || bad "bad key: $RC $(cat "$ROOT/k.json")"
RC=$(curl -s -o "$ROOT/k.json" -w '%{http_code}' -X PUT -b "$JA" -c "$JA" \
  -H 'Content-Type: text/plain' --data-binary "@$ROOT/src/attempt.txt" \
  "$BASE/api/files/content?id=$EID&enc=1&key=$(urlencode "$EKEY")")
[ "$RC" = "409" ] && grep -q "FXE1" "$ROOT/k.json" \
  && ok "enc=1 with a non-FXE1 body -> 409" || bad "enc non-fxe1: $RC $(cat "$ROOT/k.json")"
# The write must not have landed: the stored bytes are still ours.
curl -s -o "$ROOT/enc-got.bin" -b "$JA" "$BASE/api/files/download?id=$EID"
cmp -s "$ROOT/enc-cipher.bin" "$ROOT/enc-got.bin" \
  && ok "the stored ciphertext survived every refused write" || bad "ciphertext was overwritten"

note "refusals that keep a user from destroying their own keys"
RC=$(reqsave POST /api/files/zip "$JA" "$ROOT/k.json" "{\"ids\":[$EID]}")
[ "$RC" = "400" ] && grep -q "encrypted" "$ROOT/k.json" \
  && ok "ZIP over an encrypted row -> 400" || bad "zip: $RC $(cat "$ROOT/k.json")"
RC=$(reqsave POST /api/files/copy "$JA" "$ROOT/k.json" "{\"id\":$EID}")
[ "$RC" = "409" ] && grep -q "cannot be copied" "$ROOT/k.json" \
  && ok "copying an encrypted row -> 409 (a new row id cannot carry the key)" \
  || bad "copy: $RC $(cat "$ROOT/k.json")"

note "WebDAV treats encrypted rows as opaque (DECISION 9: never blind)"
DAVU="alice:correct-horse"
curl -s -D "$ROOT/dh.txt" -o "$ROOT/dav.bin" -u "$DAVU" "$BASE/dav/docs/secret.txt"
grep -qi '^content-type: application/octet-stream' "$ROOT/dh.txt" \
  && ok "DAV GET -> application/octet-stream" \
  || bad "dav get type: $(grep -i '^content-type' "$ROOT/dh.txt")"
cmp -s "$ROOT/enc-cipher.bin" "$ROOT/dav.bin" \
  && ok "DAV GET returns the same ciphertext" || bad "dav get body differs"
RC=$(curl -s -o "$ROOT/k.json" -w '%{http_code}' -X PUT -u "$DAVU" \
  -H 'Content-Type: text/plain' --data-binary "@$ROOT/src/attempt.txt" \
  "$BASE/dav/docs/secret.txt")
[ "$RC" = "409" ] && grep -qi "FXE1" "$ROOT/k.json" \
  && ok "DAV PUT of plaintext onto an encrypted row -> 409 naming FXE1" \
  || bad "dav put plain: $RC $(cat "$ROOT/k.json")"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -u "$DAVU" \
  --data-binary "@$ROOT/enc-cipher.bin" "$BASE/dav/docs/secret.txt")
[ "$RC" = "204" ] && ok "DAV PUT of an FXE1 container onto the same row -> 204" \
  || bad "dav put fxe1: $RC"
curl -s -o "$ROOT/enc-got.bin" -b "$JA" "$BASE/api/files/download?id=$EID"
cmp -s "$ROOT/enc-cipher.bin" "$ROOT/enc-got.bin" \
  && ok "the accepted DAV write changed nothing about the stored bytes" \
  || bad "dav write altered the ciphertext"

# A *create* is not an overwrite, so there is nothing to protect and nothing
# to sniff: FXE1 bytes arriving for a new name are stored as ordinary
# plaintext, exactly like any file whose first four bytes happen to spell it.
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -u "$DAVU" \
  --data-binary "@$ROOT/enc-cipher.bin" "$BASE/dav/docs/fromdav.txt")
[ "$RC" = "201" ] && ok "DAV PUT creating a new file -> 201" || bad "dav create: $RC"
FDT=$(idof "$(req GET "/api/files?parent=$DOC" "$JA")" fromdav.txt)
[ "$(field "$(req GET "/api/files?parent=$DOC" "$JA")" fromdav.txt enc_version)" = "0" ] \
  && ok "the created row is plaintext (creates are never sniffed)" || bad "created row was marked encrypted"
curl -s -D "$ROOT/dh.txt" -o /dev/null -b "$JA" "$BASE/api/files/download?id=$FDT"
grep -qi '^content-type: text/plain' "$ROOT/dh.txt" \
  && ok "and it still downloads as text/plain" \
  || bad "created file type: $(grep -i '^content-type' "$ROOT/dh.txt")"
# Overwriting a *plaintext* row with FXE1 bytes must not promote it either.
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -u "$DAVU" \
  --data-binary "@$ROOT/enc-cipher.bin" "$BASE/dav/docs/fromdav.txt")
[ "$RC" = "204" ] && [ "$(field "$(req GET "/api/files?parent=$DOC" "$JA")" fromdav.txt enc_version)" = "0" ] \
  && ok "overwriting a plaintext row with FXE1 bytes keeps enc_version=0" \
  || bad "plaintext row was promoted to encrypted"

note "a shared encrypted file is ciphertext to the grantee, never plaintext"
[ "$(reqcode POST /api/shares "$JA" "{\"file_id\":$EID,\"username\":\"bob\",\"permissions\":1}")" = "200" ] \
  || bad "sharing the encrypted file failed"
BFE=$(idof "$(req GET /api/files "$JB")" secret.txt)
[ -n "$BFE" ] && ok "the grantee sees the shared encrypted file" || bad "bob cannot see secret.txt"
curl -s -D "$ROOT/bh.txt" -o "$ROOT/bob.bin" -b "$JB" "$BASE/api/files/download?id=$BFE"
grep -qi '^content-type: application/octet-stream' "$ROOT/bh.txt" && cmp -s "$ROOT/enc-cipher.bin" "$ROOT/bob.bin" \
  && ok "the grantee downloads exactly the ciphertext the owner uploaded" \
  || bad "grantee download: $(grep -i '^content-type' "$ROOT/bh.txt")"

note "name and folder are not part of the key record's binding"
reqsave POST /api/files/rename "$JA" "$ROOT/k.json" \
  "{\"id\":$EID,\"name\":\"secret-renamed.txt\"}" >/dev/null
[ "$(jget "$(cat "$ROOT/k.json")" entry.name)" = "secret-renamed.txt" ] \
  && ok "renaming an encrypted row -> accepted" || bad "rename: $(cat "$ROOT/k.json")"
reqsave POST /api/files/move "$JA" "$ROOT/k.json" "{\"id\":$EID,\"dest_parent\":null}" >/dev/null
[ -n "$(jget "$(cat "$ROOT/k.json")" entry.id)" ] \
  && ok "moving an encrypted row -> accepted (no folder carries a key yet)" \
  || bad "move: $(cat "$ROOT/k.json")"
reqsave POST /api/files/move "$JA" "$ROOT/k.json" "{\"id\":$EID,\"dest_parent\":$DOC}" >/dev/null
curl -s -o "$ROOT/enc-got.bin" -b "$JA" "$BASE/api/files/download?id=$EID"
"$NODE" "$FXTOOL" decrypt "$FXS" "$EID" "$ROOT/enc-got.bin" "$EK" "$ROOT/enc-back.txt" \
  >/dev/null 2>&1 \
  && cmp -s "$ENCP" "$ROOT/enc-back.txt" \
  && ok "still decryptable after a rename and a move (AAD is id + version only)" \
  || bad "decryption broke after rename/move"

note "the WebCrypto round-trip harness (DECISION 10)"
if [ -x "$NODE" ] || command -v "$NODE" >/dev/null 2>&1; then
  if "$NODE" "$REPO/frontend/tests/crypto-roundtrip.js" > "$ROOT/crypto.log" 2>&1; then
    ok "crypto round-trip harness ($(grep -c '^OK' "$ROOT/crypto.log") checks)"
  else
    bad "crypto harness: $(tail -5 "$ROOT/crypto.log" | tr '\n' ' ')"
  fi
else
  bad "node is not available for the crypto harness"
fi

note "frontend wiring"
UI=$REPO/frontend/assets/app.js
UNDEF=""
for NAME in $(grep -oE '[A-Za-z_$][A-Za-z0-9_$]*\(\)\.catch' "$UI" | sed 's/().catch//' | sort -u); do
  grep -qE "(function $NAME\b)|(const $NAME\s*=)|(let $NAME\s*=)|(var $NAME\s*=)" "$UI" || UNDEF="$UNDEF $NAME"
done
[ -z "$UNDEF" ] && ok "every wired .catch() entry point is defined" \
  || bad "called but undefined in app.js:$UNDEF"

QJSC=${QJSC:-$(find_qjsc || true)}
if [ -n "$QJSC" ] && [ -x "$QJSC" ]; then
  PARSE="qjsc"
else
  PARSE="node --check"
fi
# qjsc is the project's own parse check; `node --check` is the fallback so a
# checkout without QuickJS still validates every frontend file. Both were
# verified to agree on all of them, and neither may be skipped silently -
# a syntax error in fxcrypto.js surfaces only at unlock time, on a user's
# machine.
js_parse() {
  if [ "$PARSE" = "qjsc" ]; then
    "$QJSC" -c -o "$ROOT/jschk.c" "$1" >/dev/null 2>&1
  elif [ -n "$NODE" ] && [ -x "$NODE" ]; then
    "$NODE" --check "$1" >/dev/null 2>&1
  else
    return 1
  fi
}
js_parse "$UI" \
  && ok "app.js parses ($PARSE)" || bad "app.js has a syntax error"
# The encryption files are loaded by <script> tags rather than app.js, so
# nothing in the wiring check above would notice a syntax error in them.
for SRC in "$REPO/frontend/assets/fxcrypto.js" \
           "$REPO/frontend/assets/fxenc.js" \
           "$REPO/frontend/assets/fxworker.js" \
           "$REPO/frontend/assets/hashwasm-argon2.js" \
           "$REPO/frontend/tests/fxtool.js" \
           "$REPO/frontend/tests/crypto-roundtrip.js"; do
  js_parse "$SRC" \
    && ok "$(basename "$SRC") parses ($PARSE)" \
    || bad "$(basename "$SRC") has a syntax error"
done

# Parsing only proves the parentheses balance, not that they balance the same
# way at every call site. `jsonCall(method, url, payload)` once carried a
# stray parameter no caller supplied: every call passed two arguments, so
# `payload` was undefined, JSON.stringify produced no body at all, and the
# server answered 400 to the encryption setup - while every syntax check in
# this file stayed green. hashwasm-argon2.js is excluded because it is a
# vendored bundle whose single-letter minified names trip the check.
if perl "$REPO/tests/check-call-arity.pl" \
     "$REPO/frontend/assets/app.js" \
     "$REPO/frontend/assets/fxcrypto.js" \
     "$REPO/frontend/assets/fxenc.js" \
     "$REPO/frontend/assets/fxworker.js" \
     "$REPO/frontend/tests/fxtool.js" \
     "$REPO/frontend/tests/crypto-roundtrip.js" >"$ROOT/arity.log" 2>&1; then
  ok "every frontend helper is called with its declared argument count"
else
  bad "frontend arity: $(tr '\n' ' ' < "$ROOT/arity.log")"
fi

# ENCRYPTION.md 5.7 makes "reuse login password" the pre-selected default in
# the setup UI. No parser can notice a control that was never written, so the
# choice itself is asserted here - as is the check that keeps it honest.
ENC_HTML="$REPO/frontend/index.html"
ENC_JS="$REPO/frontend/assets/fxenc.js"
grep -q 'id="enc-use-login"[^>]*checked' "$ENC_HTML" \
  && ok "setup offers reuse-login-password, pre-selected (DECISION 3)" \
  || bad "setup pane is missing the pre-selected login-password option"
grep -q 'id="enc-use-pass"' "$ENC_HTML" \
  && ok "a separate passphrase stays one click away" \
  || bad "setup pane offers no separate passphrase"
grep -q 'await verifyLogin(pass)' "$ENC_JS" \
  && ok "the reused login password is verified before any key is created" \
  || bad "fxenc.js does not verify the reused login password"
grep -q 'res.status === 401) return false' "$ENC_JS" \
  && ok "a wrong password is read as a verdict, not as a dead session" \
  || bad "verifyLogin would route a typo through the 401 redirect"
MISSING_IDS=""
for ID in $(grep -oE '\$\("enc-[a-z0-9-]+"\)' "$ENC_JS" | sed 's/\$("//; s/")//' | sort -u); do
  grep -q "id=\"$ID\"" "$ENC_HTML" || MISSING_IDS="$MISSING_IDS $ID"
done
[ -z "$MISSING_IDS" ] && ok "every element fxenc.js reaches for exists in index.html" \
  || bad "ids used by fxenc.js but absent from index.html:$MISSING_IDS"

note "server log (errors?)"
grep -iE 'panic|error' "$ROOT/server.log" | head -20 || true

echo
if [ "$FAIL" = "0" ]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
kill "$(cat "$ROOT/server.pid")" 2>/dev/null
exit "$FAIL"
