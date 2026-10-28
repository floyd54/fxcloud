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
JD=$ROOT/dave.jar   # the user-settings section changes this account's password

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

field() { # field <listing-json> <name> <key> -> that one field of that one row
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
OUT=$(req POST /api/shares/batch "$JA" "{\"items\":[{\"file_id\":$A},{\"file_id\":$DOC}],\"username\":\"bob\",\"permissions\":1}")
echo "$OUT"
echo "$OUT" | grep -q '"ok":\[3,1\]' && ok "two shares created in one request" || bad "unexpected: $OUT"

note "alice shares the same two again -> both conflict"
OUT=$(req POST /api/shares/batch "$JA" "{\"items\":[{\"file_id\":$A},{\"file_id\":$DOC}],\"username\":\"bob\",\"permissions\":1}")
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
CODE=$(reqcode POST "/api/shares/batch" "$JA" '{"items":[],"username":"bob"}')
[ "$CODE" = "400" ] && ok "shares/batch with nothing selected -> 400" || bad "expected 400, got $CODE"

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

# ---- user settings (topbar menu: name, theme, password) ----
note "user settings: display name and theme (PUT /api/me)"

# A fresh account starts on the light theme, in the DB and in the payload.
ME=$(req GET /api/me "$JA")
[ "$(jget "$ME" theme)" = "light" ] && ok "new account defaults to the light theme" || bad "default theme: $ME"
THEME_DB=$(sqlite3 "$DATA/fxcloud.db" "SELECT theme FROM users WHERE username='alice';")
[ "$THEME_DB" = "light" ] && ok "theme stored in the DB" || bad "users.theme is '$THEME_DB'"

RC=$(reqcode PUT /api/me "$JA" '{"theme":"dark"}')
ME=$(req GET /api/me "$JA")
[ "$RC" = "200" ] && [ "$(jget "$ME" theme)" = "dark" ] \
  && ok "PUT /api/me saves the dark theme" || bad "theme save failed (rc=$RC): $ME"
THEME_DB=$(sqlite3 "$DATA/fxcloud.db" "SELECT theme FROM users WHERE username='alice';")
[ "$THEME_DB" = "dark" ] && ok "dark theme persisted to the DB" || bad "users.theme is '$THEME_DB'"

RC=$(reqcode PUT /api/me "$JA" '{"theme":"neon"}')
[ "$RC" = "400" ] && ok "an unknown theme is refused (400)" || bad "expected 400 for theme=neon, got $RC"
ME=$(req GET /api/me "$JA")
[ "$(jget "$ME" theme)" = "dark" ] && ok "the refused theme changed nothing" || bad "theme clobbered: $ME"
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET theme='light' WHERE username='alice';" >/dev/null

RC=$(reqcode PUT /api/me "$JA" '{"display_name":"Alice Cooper"}')
ME=$(req GET /api/me "$JA")
[ "$RC" = "200" ] && [ "$(jget "$ME" display_name)" = "Alice Cooper" ] \
  && ok "PUT /api/me saves the display name" || bad "display name save failed (rc=$RC): $ME"
U=$(req GET /api/users "$JB")
echo "$U" | grep -q '"display_name":"Alice Cooper"' \
  && ok "the new display name shows up for others" || bad "share dialog still sees the old name: $U"

RC=$(reqcode PUT /api/me "$JA" '{"display_name":"   "}')
[ "$RC" = "400" ] && ok "an empty display name is refused (400)" || bad "expected 400 for a blank name, got $RC"
RC=$(reqcode PUT /api/me "$JA" '{}')
[ "$RC" = "400" ] && ok "an empty settings body is refused (400)" || bad "expected 400 for {}, got $RC"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' \
  -d '{"theme":"dark"}' "$BASE/api/me")
[ "$RC" = "401" ] && ok "PUT /api/me without session -> 401" || bad "expected 401, got $RC"
req PUT /api/me "$JA" '{"display_name":"alice"}' >/dev/null   # back to the plain name

note "user settings: password change (PUT /api/me/password)"
# A fresh, activated account so the checks cannot disturb alice's or bob's
# password - the rest of the suite signs in with those.
req POST /api/register "$JD" '{"username":"dave","password":"correct-horse"}' >/dev/null
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET is_active=1 WHERE username='dave';" >/dev/null
RC=$(reqcode POST /api/login "$JD" '{"username":"dave","password":"correct-horse"}')
[ "$RC" = "200" ] && ok "dave signs in before the change" || bad "dave cannot log in (rc=$RC)"

RC=$(reqcode PUT /api/me/password "$JD" '{"current_password":"wrong-password","new_password":"another-horse"}')
[ "$RC" = "401" ] && ok "a wrong current password is refused (401)" || bad "expected 401, got $RC"
RC=$(reqcode PUT /api/me/password "$JD" '{"current_password":"correct-horse","new_password":"short"}')
[ "$RC" = "400" ] && ok "a short new password is refused (400)" || bad "expected 400, got $RC"
RC=$(reqcode PUT /api/me/password "$JD" '{"current_password":"correct-horse","new_password":"another-horse"}')
[ "$RC" = "200" ] && ok "the password changes (200)" || bad "expected 200, got $RC"

RC=$(reqcode POST /api/login "$JD" '{"username":"dave","password":"correct-horse"}')
[ "$RC" = "401" ] && ok "the old password no longer signs in" || bad "old password still works (rc=$RC)"
RC=$(reqcode POST /api/login "$JD" '{"username":"dave","password":"another-horse"}')
[ "$RC" = "200" ] && ok "the new password signs in" || bad "new password refused (rc=$RC)"
RC=$(reqcode PUT /api/me/password "$JD" '{"current_password":"another-horse","new_password":"correct-horse"}')
[ "$RC" = "200" ] && ok "dave's password restored for later checks" || bad "restore failed (rc=$RC)"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' \
  -d '{"current_password":"correct-horse","new_password":"another-horse"}' "$BASE/api/me/password")
[ "$RC" = "401" ] && ok "PUT /api/me/password without session -> 401" || bad "expected 401, got $RC"

# ---- user administration ----
note "user administration: the first account is the administrator"

# Pull one field of one account out of the /api/admin/users array.
afield() { # afield <list-json> <username> <key>
  printf '%s' "$1" | perl -MJSON::PP -0777 -e '
    my ($u, $k) = @ARGV;
    my $l = decode_json(do { local $/; <STDIN> });
    for my $x (@$l) {
      next unless $x->{username} eq $u;
      my $v = $x->{$k};
      print defined $v ? $v : "";
      last;
    }' "$2" "$3"
}

ME=$(req GET /api/me "$JA")
[ "$(jget "$ME" is_admin)" = "1" ] \
  && ok "the first account (alice) is an administrator" \
  || bad "alice should be an admin (is_admin=$(jget "$ME" is_admin))"
ME=$(req GET /api/me "$JB")
[ "$(jget "$ME" is_admin)" = "0" ] \
  && ok "a later account (bob) is not an administrator" \
  || bad "bob should not be an admin"

note "user administration: non-admins are refused (403)"
RC=$(reqcode GET /api/admin/users "$JD")
[ "$RC" = "403" ] && ok "a signed-in non-admin gets 403 on /api/admin/users" || bad "expected 403, got $RC"

note "user administration: the admin lists every account"
LIST=$(req GET /api/admin/users "$JA")
[ "$(jget "$LIST" 0.username)" != "" ] && ok "GET /api/admin/users returns the accounts" || bad "empty admin list"
[ "$(afield "$LIST" alice is_admin)" = "1" ] && ok "the list marks alice as admin" || bad "alice not marked admin"
[ "$(afield "$LIST" bob is_active)" = "1" ] && ok "the list carries bob's active flag" || bad "bob active flag missing"
[ "$(afield "$LIST" bob quota_bytes)" != "" ] && ok "the list carries the quota" || bad "quota missing"
[ "$(afield "$LIST" bob used_bytes)" != "" ] && ok "the list carries storage usage" || bad "used_bytes missing"

note "user administration: activate a new account through the API"
req POST /api/register "$ROOT/erin.jar" '{"username":"erin","password":"correct-horse"}' >/dev/null
LIST=$(req GET /api/admin/users "$JA")
ERIN=$(afield "$LIST" erin id)
RC=$(reqcode POST /api/login "$ROOT/erin.jar" '{"username":"erin","password":"correct-horse"}')
[ "$RC" = "403" ] && ok "a freshly registered account cannot sign in yet" || bad "expected 403 for inactive erin, got $RC"
RC=$(reqcode PUT "/api/admin/users/$ERIN" "$JA" '{"is_active":true}')
[ "$RC" = "200" ] && ok "the administrator activates the account (200)" || bad "activate failed (rc=$RC)"
RC=$(reqcode POST /api/login "$ROOT/erin.jar" '{"username":"erin","password":"correct-horse"}')
[ "$RC" = "200" ] && ok "the activated account can sign in" || bad "erin still cannot log in (rc=$RC)"

note "user administration: set a quota and keep the safety rules"
LIST=$(req GET /api/admin/users "$JA")
DAVE=$(afield "$LIST" dave id)
ALICE=$(afield "$LIST" alice id)
RC=$(reqcode PUT "/api/admin/users/$DAVE" "$JA" '{"quota_bytes":2147483648}')
[ "$RC" = "200" ] && ok "the quota is set (200)" || bad "quota set failed (rc=$RC)"
LIST=$(req GET /api/admin/users "$JA")
[ "$(afield "$LIST" dave quota_bytes)" = "2147483648" ] && ok "the new quota is stored" || bad "quota not stored"
RC=$(reqcode PUT "/api/admin/users/$DAVE" "$JA" '{"quota_bytes":-5}')
[ "$RC" = "400" ] && ok "a negative quota is refused (400)" || bad "expected 400 for negative quota, got $RC"
RC=$(reqcode PUT "/api/admin/users/$ALICE" "$JA" '{"is_active":false}')
[ "$RC" = "400" ] && ok "an admin cannot deactivate themselves (400)" || bad "expected 400 for self-deactivate, got $RC"
RC=$(reqcode PUT "/api/admin/users/$ALICE" "$JA" '{"is_admin":false}')
[ "$RC" = "400" ] && ok "the last admin cannot be demoted (400)" || bad "expected 400 for last-admin demote, got $RC"

note "user administration: manage the admin role"
RC=$(reqcode PUT "/api/admin/users/$DAVE" "$JA" '{"is_admin":true}')
[ "$RC" = "200" ] && ok "the admin promotes another account (200)" || bad "promote failed (rc=$RC)"
LIST=$(req GET /api/admin/users "$JA")
[ "$(afield "$LIST" dave is_admin)" = "1" ] && ok "the promoted account is now an admin" || bad "dave not admin"

note "user administration: password reset hands back a temporary password"
RESET=$(req POST "/api/admin/users/$DAVE/password" "$JA")
TMP=$(jget "$RESET" temporary_password)
[ "${#TMP}" = "16" ] && ok "the reset returns a 16-character temporary password" || bad "temp password length ${#TMP}, expected 16"
RC=$(reqcode POST /api/login "$JD" '{"username":"dave","password":"'"$TMP"'"}')
[ "$RC" = "200" ] && ok "the temporary password signs in" || bad "temp password refused (rc=$RC)"
RC=$(reqcode POST /api/login "$JD" '{"username":"dave","password":"correct-horse"}')
[ "$RC" = "401" ] && ok "the old password no longer signs in" || bad "old password still works (rc=$RC)"

note "user administration: reset on a missing account -> 404"
RC=$(reqcode POST /api/admin/users/99999/password "$JA")
[ "$RC" = "404" ] && ok "resetting a missing account is 404" || bad "expected 404, got $RC"

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

# ---- content sniffing: the bytes decide the stored type ----
# A browser says "application/octet-stream" for a file without an extension -
# its type table is keyed on the name. The server reads the bytes instead
# (magic numbers first, then a text heuristic), so a note without an extension
# still opens in the editor.
note "the server sniffs the type of a file that has no extension"
printf 'Notiz ohne Endung, mit Umlauten: Gr\303\274\303\237e\n' > "$ROOT/src/ohne-endung"
NR=$(up "$JA" "$DOC" ohne-endung)
OID=$(jget "$NR" entry.id)
[ -n "$OID" ] && ok "uploaded a text file without an extension (id $OID)" \
  || bad "ohne-endung upload failed: $NR"
OLIST=$(req GET "/api/files?parent=$DOC" "$JA")
[ "$(field "$OLIST" ohne-endung mime)" = "text/plain" ] \
  && ok "its stored type is text/plain (sniffed, not the browser's word)" \
  || bad "stored mime: '$(field "$OLIST" ohne-endung mime)'"
RC=$(reqcode GET "/api/files/preview?id=$OID" "$JA")
[ "$RC" = "200" ] && ok "and the preview serves it (extension-less text is viewable)" \
  || bad "preview of the sniffed text file: $RC"

printf '\211PNG\r\n\032\n\000\000\000\rIHDR\000\000\000\001\000\000\000\001\010\002\000\000\000\220wS\336' \
  > "$ROOT/src/bild-ohne-endung"
NR=$(up "$JA" "$DOC" bild-ohne-endung)
BID=$(jget "$NR" entry.id)
[ -n "$BID" ] && ok "uploaded PNG bytes without an extension (id $BID)" \
  || bad "bild-ohne-endung upload failed: $NR"
[ "$(field "$(req GET "/api/files?parent=$DOC" "$JA")" bild-ohne-endung mime)" = "image/png" ] \
  && ok "magic bytes win: stored as image/png" \
  || bad "png mime: '$(field "$(req GET "/api/files?parent=$DOC" "$JA")" bild-ohne-endung mime)'"

printf 'BINAER\000\001\002\000\377\376' > "$ROOT/src/dat-ohne-endung"
NR=$(up "$JA" "$DOC" dat-ohne-endung)
DID=$(jget "$NR" entry.id)
[ -n "$DID" ] && ok "uploaded binary junk without an extension (id $DID)" \
  || bad "dat-ohne-endung upload failed: $NR"
[ -z "$(field "$(req GET "/api/files?parent=$DOC" "$JA")" dat-ohne-endung mime)" ] \
  && ok "unnamed binary stays untyped (mime NULL, not a guess)" \
  || bad "binary mime: '$(field "$(req GET "/api/files?parent=$DOC" "$JA")" dat-ohne-endung mime)'"

# The editor's save is a write path like any other: without the sniff it
# would wipe the type of an extension-less file on its first save and drop
# it back out of the editor menu.
note "an extension-less text file keeps its type across an editor save"
printf 'zweite Fassung, immer noch ohne Endung\n' > "$ROOT/src/neu-ohne-endung.txt"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -b "$JA" \
  -H 'Content-Type: text/plain' --data-binary "@$ROOT/src/neu-ohne-endung.txt" \
  "$BASE/api/files/content?id=$OID")
[ "$RC" = "200" ] && ok "PUT content -> 200" || bad "save: $RC"
[ "$(field "$(req GET "/api/files?parent=$DOC" "$JA")" ohne-endung mime)" = "text/plain" ] \
  && ok "the stored type survived the save" \
  || bad "mime after save: '$(field "$(req GET "/api/files?parent=$DOC" "$JA")" ohne-endung mime)'"

# The named case must not regress: a declared *specific* text type beats the
# heuristic's flat text/plain, so a Markdown note keeps text/markdown.
note "a named text file keeps its specific type (mime_guess, not text/plain)"
NR=$(req POST /api/files/file "$JA" "{\"parent_id\":$DOC,\"name\":\"notiz.md\"}")
MID=$(jget "$NR" entry.id)
[ -n "$MID" ] && ok "created the empty row notiz.md (id $MID)" || bad "create notiz.md: $NR"
printf '# Titel\n\nnur Text\n' > "$ROOT/src/notiz-body.txt"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -b "$JA" \
  -H 'Content-Type: text/plain' --data-binary "@$ROOT/src/notiz-body.txt" \
  "$BASE/api/files/content?id=$MID")
[ "$RC" = "200" ] && ok "saved the body via the editor route" || bad "notiz.md save: $RC"
[ "$(field "$(req GET "/api/files?parent=$DOC" "$JA")" notiz.md mime)" = "text/markdown" ] \
  && ok "notiz.md keeps text/markdown (a named type beats the sniff)" \
  || bad "notiz.md mime: '$(field "$(req GET "/api/files?parent=$DOC" "$JA")" notiz.md mime)'"

# WebDAV is the other door into the same storage: a client that pushes a
# file without an extension gets the same sniffing.
note "a WebDAV PUT without an extension is sniffed the same way"
printf 'dav notiz ohne endung\n' > "$ROOT/src/dav-ohne-endung"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -u "alice:correct-horse" \
  --data-binary "@$ROOT/src/dav-ohne-endung" "$BASE/dav/docs/dav-ohne-endung")
[ "$RC" = "201" ] && ok "DAV PUT created the file (201)" || bad "dav sniff create: $RC"
[ "$(field "$(req GET "/api/files?parent=$DOC" "$JA")" dav-ohne-endung mime)" = "text/plain" ] \
  && ok "the DAV-written file is stored as text/plain" \
  || bad "dav sniff mime: '$(field "$(req GET "/api/files?parent=$DOC" "$JA")" dav-ohne-endung mime)'"

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
req POST /api/shares/batch "$JA" "{\"items\":[{\"file_id\":$EDID}],\"username\":\"bob\",\"permissions\":3}" >/dev/null
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
# The sniff must never look at ciphertext: the server would store a type that
# describes neither the wrapper nor the plaintext it never saw.
[ -z "$(field "$ELIST" secret.txt mime)" ] \
  && ok "the encrypted row keeps mime NULL (ciphertext is not sniffed)" \
  || bad "encrypted row claims a mime: '$(field "$ELIST" secret.txt mime)'"
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

# ---- key exchange: envelopes and folder key records (5.2 / 5.5) --------
# A grantee has to be able to *open* what a share points at, so the server
# stores two things it cannot read: one envelope per item (5.5) and the key
# records of a folder chain (5.2). Every check below is one the client's
# walk down that chain - or the share dialog sealing into it - depends on.
note "key exchange: an envelope rides with the share (5.5)"

# A fresh encrypted row, shared the way the dialog shares now: one envelope
# per item, sealed for the grantee's published key before the request goes.
printf 'sealed for bob, opened with his own key\n' > "$ROOT/src/keyguard.txt"
RC=$(reqsave POST /api/files/file "$JA" "$ROOT/k.json" "{\"parent_id\":$DOC,\"name\":\"keyguard.txt\"}")
KGID=$(jget "$(cat "$ROOT/k.json")" entry.id)
[ "$RC" = "200" ] && [ -n "$KGID" ] \
  && ok "the key-exchange fixture row is reserved" \
  || bad "create: $RC $(cat "$ROOT/k.json")"
GKEY=$("$NODE" "$FXTOOL" encrypt "$FXS" "$KGID" "$ROOT/src/keyguard.txt" "$ROOT/kg-cipher.bin" 2>"$ROOT/fx.err")
RC=$(curl -s -o "$ROOT/k.json" -w '%{http_code}' -X PUT -b "$JA" -c "$JA" \
  -H 'Content-Type: application/octet-stream' --data-binary "@$ROOT/kg-cipher.bin" \
  "$BASE/api/files/content?id=$KGID&enc=1&key=$(urlencode "$GKEY")")
[ "$RC" = "200" ] && [ -n "$GKEY" ] \
  && ok "the fixture lands encrypted, record and ciphertext on the same row" \
  || bad "fixture upload: $RC key='$GKEY' $(cat "$ROOT/k.json")"

ENV1='ZXZfZW52ZWxvcGVfMDAxMjM0NTY3ODk'
BIG=$(printf 'a%.0s' $(seq 1 9000))

# Checked before the loop, so one oversized blob cannot leave half of a
# selection shared without it.
RC=$(reqsave POST /api/shares/batch "$JA" "$ROOT/k.json" \
  "{\"items\":[{\"file_id\":$KGID,\"envelope\":\"$BIG\"}],\"username\":\"bob\",\"permissions\":3}")
[ "$RC" = "400" ] && grep -q "8192" "$ROOT/k.json" \
  && ok "an oversized envelope is refused before anything is shared (8 KiB cap)" \
  || bad "big envelope: $RC $(cat "$ROOT/k.json")"

OUT=$(req POST /api/shares/batch "$JA" \
  "{\"items\":[{\"file_id\":$KGID,\"envelope\":\"$ENV1\"}],\"username\":\"bob\",\"permissions\":3}")
echo "$OUT"
printf '%s' "$OUT" | grep -q '"ok":\[' \
  && ok "an item may carry an envelope into the batch request" \
  || bad "batch with envelope: $OUT"

BINC=$(req GET /api/shares/incoming "$JB")
BENV=$(printf '%s' "$BINC" | perl -MJSON::PP -0777 -ne '
  for my $s (@{decode_json($_)->{shares} || []}) {
    next unless defined $s->{file_id} && $s->{file_id} == '"$KGID"';
    print defined $s->{envelope} ? $s->{envelope} : "";
    last;
  }')
[ "$BENV" = "$ENV1" ] && ok "the envelope reaches the grantee's inbox byte for byte" \
  || bad "incoming envelope: '$BENV' want '$ENV1'"
AENV=$(printf '%s' "$BINC" | perl -MJSON::PP -0777 -ne '
  for my $s (@{decode_json($_)->{shares} || []}) {
    next unless defined $s->{file_id} && $s->{file_id} == '"$A"';
    print defined $s->{envelope} ? $s->{envelope} : "";
    last;
  }')
[ -z "$AENV" ] && ok "a share sent without an envelope stays without one" \
  || bad "the plaintext share grew an envelope: '$AENV'"

# The body shape moved with the exchange: `items` names the row *and* its
# envelope, so the retired field cannot silently be shared without one. The
# JSON extractor reads a schema mismatch as 422 rather than 400 - what
# matters here is that the request never reaches a single share.
RC=$(reqsave POST /api/shares/batch "$JA" "$ROOT/k.json" \
  "{\"file_ids\":[$A],\"username\":\"bob\",\"permissions\":1}")
[ "$RC" = "422" ] \
  && ok "the retired file_ids body is refused (items is the shape now)" \
  || bad "legacy batch body: $RC $(cat "$ROOT/k.json")"

note "PUT /api/files/key: the folder record the chain is built from (5.2)"
# A folder gains its record lazily - on the first encrypted write below it,
# or when a share migrates the subtree - and this is the door for that.
KTF=$(jget "$(req POST /api/files/folder "$JA" '{"name":"keytest"}')" entry.id)
printf 'plaintext inside a keyed folder\n' > "$ROOT/src/innerplain.txt"
PLAINID=$(jget "$(up "$JA" "$KTF" innerplain.txt)" entry.id)
[ -n "$KTF" ] && [ -n "$PLAINID" ] \
  && ok "a folder fixture with a plaintext file inside it" \
  || bad "fixtures: folder=$KTF child=$PLAINID"
KVAL=$(printf 'chain-key-for-the-keytest-folder' | base64 | tr -d '\n')

RC=$(reqsave PUT /api/files/key "$JA" "$ROOT/k.json" "{\"id\":$KTF,\"key\":\"$KVAL\"}")
[ "$RC" = "200" ] && ok "the owner may give a folder its key record" \
  || bad "put key: $RC $(cat "$ROOT/k.json")"
[ "$(jget "$(cat "$ROOT/k.json")" entry.enc_key)" = "$KVAL" ] \
  && ok "the answer carries the folder with exactly that record" \
  || bad "body: $(cat "$ROOT/k.json")"
RC=$(reqsave PUT /api/files/key "$JA" "$ROOT/k.json" "{\"id\":$KTF,\"key\":\"nicht-base64!\"}")
[ "$RC" = "400" ] && grep -q "base64" "$ROOT/k.json" \
  && ok "a key record that is not base64 -> 400" \
  || bad "bad key: $RC $(cat "$ROOT/k.json")"

# The walk the client performs starts at Home and unwraps one record per
# keyed level (5.2); a crumb without its record would stop the walk one
# level early and leave the fallback to guess.
BC=$(req GET "/api/files/breadcrumb?id=$KTF" "$JA")
BC0=$(printf '%s' "$BC" | perl -MJSON::PP -0777 -ne '
  my $b = decode_json($_)->{breadcrumbs} || [];
  print defined $b->[0]{id} ? "id" : "home";')
[ "$BC0" = "home" ] && ok "the breadcrumb starts with the id-less Home crumb" \
  || bad "breadcrumb head: $BC"
BCK=$(printf '%s' "$BC" | perl -MJSON::PP -0777 -ne '
  for my $c (@{decode_json($_)->{breadcrumbs} || []}) {
    next unless defined $c->{id} && $c->{id} == '"$KTF"';
    print defined $c->{enc_key} ? $c->{enc_key} : "";
    last;
  }')
[ "$BCK" = "$KVAL" ] && ok "the keyed crumb carries its record down the trail" \
  || bad "crumb record: '$BCK' want '$KVAL'"

# The crypto mirrors the API permission (5.5): READ lets a grantee read
# every record in the trail, UPDATE is what writes one.
req POST /api/shares "$JA" "{\"file_id\":$KTF,\"username\":\"bob\",\"permissions\":1}" >/dev/null
RC=$(reqsave PUT /api/files/key "$JB" "$ROOT/k.json" \
  "{\"id\":$KTF,\"key\":\"Ym9iLWZha2VieXRlcy1oZXJl\"}")
[ "$RC" = "403" ] && ok "a read-only grantee cannot write a folder's key record" \
  || bad "grantee put key: $RC $(cat "$ROOT/k.json")"

# A plaintext file has no record to replace, so the server says so instead
# of storing one the client would later believe in (DECISION 10).
RC=$(reqsave PUT /api/files/key "$JA" "$ROOT/k.json" "{\"id\":$PLAINID,\"key\":\"$KVAL\"}")
[ "$RC" = "400" ] && grep -q "not encrypted" "$ROOT/k.json" \
  && ok "a plaintext file refuses a key record (400 naming the reason)" \
  || bad "plaintext key: $RC $(cat "$ROOT/k.json")"

# The copy gate looks at *files* (5.4): a folder that carries a record but
# holds only plaintext copies fine - and like every copy it arrives unkeyed.
RC=$(reqsave POST /api/files/copy "$JA" "$ROOT/k.json" "{\"id\":$KTF,\"dest_parent\":$DOC}")
CPI=$(jget "$(cat "$ROOT/k.json")" entry.id)
[ "$RC" = "200" ] && [ -n "$CPI" ] \
  && ok "a keyed folder of plaintext files still copies" \
  || bad "copy: $RC $(cat "$ROOT/k.json")"
CINFO=$(req GET "/api/files/info?id=$CPI" "$JA")
[ "$(jget "$CINFO" entry.enc_version)" = "0" ] && [ -z "$(jget "$CINFO" entry.enc_key)" ] \
  && ok "the copy arrives unkeyed, like every copy" \
  || bad "copy record: $CINFO"

# The JSON move is the key-aware door (5.4): the client re-binds the row's
# record to the destination before asking, so the server must not compare
# key domains it cannot read - in a keyed tree every folder carries its own
# record, and that guard would refuse exactly the prepared move.
OUT=$(req POST /api/files/batch/move "$JA" "{\"ids\":[$KGID],\"dest_parent\":$KTF}")
printf '%s' "$OUT" | grep -q "\"ok\":\[$KGID\]" \
  && ok "a prepared JSON move of an encrypted row into a keyed folder lands" \
  || bad "json move: $OUT"
# WebDAV holds no keys to re-wrap with (DECISION 9), so the same travel
# refuses there rather than leaving a row whose record no longer opens.
RC=$(curl -s -o "$ROOT/k.json" -w '%{http_code}' -X MOVE -u "$DAVU" \
  -H "Destination: $BASE/dav/keyguard.txt" "$BASE/dav/keytest/keyguard.txt")
[ "$RC" = "409" ] && ok "DAV MOVE of that row back out of the keyed folder -> 409" \
  || bad "dav move: $RC $(cat "$ROOT/k.json")"

note "a grantee re-saves the record they were handed, never another one"
# Bob holds UPDATE on the row above (permissions 3) and may write its
# content - but the server cannot read keys, so only the row's owner may
# swap the record that unlocks it (5.5): an identical record passes
# through, a foreign one is refused by name.
OTHERKEY=$(printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' | base64 | tr -d '\n')
RC=$(curl -s -o "$ROOT/kg2.json" -w '%{http_code}' -X PUT -b "$JB" -c "$JB" \
  -H 'Content-Type: application/octet-stream' --data-binary "@$ROOT/kg-cipher.bin" \
  "$BASE/api/files/content?id=$KGID&enc=1&key=$(urlencode "$OTHERKEY")")
[ "$RC" = "403" ] && grep -q "only the row's owner may change its key record" "$ROOT/kg2.json" \
  && ok "a grantee saving a different key record -> 403 naming why" \
  || bad "record swap: $RC $(cat "$ROOT/kg2.json")"
RC=$(curl -s -o "$ROOT/kg2.json" -w '%{http_code}' -X PUT -b "$JB" -c "$JB" \
  -H 'Content-Type: application/octet-stream' --data-binary "@$ROOT/kg-cipher.bin" \
  "$BASE/api/files/content?id=$KGID&enc=1&key=$(urlencode "$GKEY")")
[ "$RC" = "200" ] && ok "the same grantee passing their own record back -> 200" \
  || bad "identical record: $RC $(cat "$ROOT/kg2.json")"

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

# The checks above drive fxcrypto.js through fxtool.js; the browser itself
# calls the same primitives from fxenc.js, which has to pick every argument
# and every request body on its own. That distinction shipped twice: a lost
# parameter in jsonCall and a scrambled encryptBytes(plain, id, fileKey),
# each of which broke the real UI while every check above stayed green. This
# harness runs that file as a tab would - fake DOM, cookie-carrying fetch -
# against this instance, over both crypto paths (page and worker, below).
note "the browser encryption path, end to end (fxenc.js as a tab runs it)"
HX_COOKIE=$(awk '$6 == "fxcloud_session" { print $6 "=" $7 }' "$JA" | tail -1)
# The passphrase-change test above rewrapped alice's record, so the tab now
# opens with that passphrase rather than with the one setup used.
HX_PASS='a-brand-new-pass'
# Twice, because a browser tab always has a Worker: once with `Worker`
# undefined, which is the documented fallback an engine without one takes,
# and once with a Worker whose message handler is the real fxworker.js -
# that is the path every whole-file operation actually travels in a browser,
# and the cloned hop is invisible to everything else in this file. Fixture
# rows carry the mode in their name, so the two runs do not collide.
for HX_MODE in page worker; do
  HX_LOG=$ROOT/fxenc-$HX_MODE.log
  if [ "$HX_MODE" = "worker" ]; then
    FXENC_WORKER=1 "$NODE" "$REPO/frontend/tests/fxenc-harness.js" \
      "$BASE" "$HX_COOKIE" "$HX_PASS" alice > "$HX_LOG" 2>&1
  else
    "$NODE" "$REPO/frontend/tests/fxenc-harness.js" \
      "$BASE" "$HX_COOKIE" "$HX_PASS" alice > "$HX_LOG" 2>&1
  fi
  HX_RC=$?
  HX_OK=0
  HX_FAIL=0
  while IFS= read -r HX_LINE; do
    case "$HX_LINE" in
      OK\ *)
        ok "fxenc[$HX_MODE]: ${HX_LINE#OK   }"
        HX_OK=$((HX_OK + 1))
        ;;
      FAIL\ *)
        bad "fxenc[$HX_MODE]: ${HX_LINE#FAIL }"
        HX_FAIL=$((HX_FAIL + 1))
        ;;
    esac
  done < "$HX_LOG"
  # A harness that died before printing anything must not read as a pass.
  if [ "$HX_RC" -ne 0 ] && [ "$HX_FAIL" -eq 0 ]; then
    bad "fxenc[$HX_MODE] harness exited $HX_RC: $(tail -3 "$HX_LOG" | tr '\n' ' ')"
  fi
  [ "$HX_OK" -gt 0 ] || bad "fxenc[$HX_MODE] harness reported no checks at all"
done

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
# The encryption files and the login page are loaded by <script> tags rather
# than by app.js, so nothing in the wiring check above would notice a syntax
# error in them. webauthn-client.js sits between the two pages (login tab and
# settings dialog), and tests/webauthn.js is the virtual authenticator the
# passkey section below drives.
for SRC in "$REPO/frontend/assets/i18n.js" \
           "$REPO/frontend/assets/fxcrypto.js" \
           "$REPO/frontend/assets/fxenc.js" \
           "$REPO/frontend/assets/fxworker.js" \
           "$REPO/frontend/assets/hashwasm-argon2.js" \
           "$REPO/frontend/assets/webauthn-client.js" \
           "$REPO/frontend/assets/login.js" \
           "$REPO/frontend/tests/fxtool.js" \
           "$REPO/frontend/tests/crypto-roundtrip.js" \
           "$REPO/frontend/tests/fxenc-harness.js" \
           "$REPO/frontend/tests/webauthn.js"; do
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
     "$REPO/frontend/assets/i18n.js" \
     "$REPO/frontend/assets/app.js" \
     "$REPO/frontend/assets/fxcrypto.js" \
     "$REPO/frontend/assets/fxenc.js" \
     "$REPO/frontend/assets/fxworker.js" \
     "$REPO/frontend/assets/webauthn-client.js" \
     "$REPO/frontend/assets/login.js" \
     "$REPO/frontend/tests/fxtool.js" \
     "$REPO/frontend/tests/crypto-roundtrip.js" \
     "$REPO/frontend/tests/fxenc-harness.js" \
     "$REPO/frontend/tests/webauthn.js" >"$ROOT/arity.log" 2>&1; then
  ok "every frontend helper is called with its declared argument count"
else
  bad "frontend arity: $(tr '\n' ' ' < "$ROOT/arity.log")"
fi

# ---- language switch (i18n.js) ----
# English stays the default; German is the first flag in the switcher. The
# dictionaries have to agree key for key and every marked key has to exist
# in both, or a translated page falls back to English mid-sentence - the
# failure no parser above would notice.
note "language switch: English default, German first, dictionaries in step"
I18N_JS="$REPO/frontend/assets/i18n.js"
LOGIN_HTML="$REPO/frontend/login.html"
IDX=$REPO/frontend/index.html
first_script=$(grep -o '<script src="[^"]*"' "$IDX" | head -1 || true)
[ "$first_script" = '<script src="/assets/i18n.js"' ] \
  && ok "index.html loads i18n.js before every other script" \
  || bad "i18n.js is not the first script in index.html"
first_script=$(grep -o '<script src="[^"]*"' "$LOGIN_HTML" | head -1 || true)
[ "$first_script" = '<script src="/assets/i18n.js"' ] \
  && ok "login.html loads i18n.js before every other script" \
  || bad "i18n.js is not the first script in login.html"
grep -q 'class="lang-switch" id="lang-switch"' "$IDX" \
  && ok "the topbar carries the flag switcher" \
  || bad "no flag switcher in the topbar"
grep -q 'id="settings-lang"' "$IDX" \
  && ok "the settings dialog offers the language too" \
  || bad "no language section in the settings dialog"
grep -q 'class="lang-switch auth-lang" id="lang-switch"' "$LOGIN_HTML" \
  && ok "the login/register card carries the flag switcher" \
  || bad "no flag switcher on the login page"
grep -q 'var currentCode = "en"' "$I18N_JS" \
  && ok "English is the default language" \
  || bad "the default language is not English"
grep -q 'var CODES = \["de", "en", "tlh"\]' "$I18N_JS" \
  && ok "the switcher offers German, English and Klingon - German first" \
  || bad "the switcher order is not de, en, tlh"
grep -q 'code === "tlh"' "$I18N_JS" \
  && ok "Klingon carries its own flag" \
  || bad "no flag is drawn for Klingon"
grep -q 'tlhIngan Hol' "$I18N_JS" \
  && ok "the Klingon flag names itself tlhIngan Hol" \
  || bad "the Klingon endonym is missing"
LC_ALL=C grep -q 'navigator.language' "$I18N_JS" \
  && bad "the UI sniffs the browser language instead of asking" \
  || ok "no browser-language guessing: the flags decide"
grep -q 'fxcloud.lang' "$I18N_JS" \
  && ok "the language choice is remembered in localStorage" \
  || bad "the language choice is not persisted"
LC_ALL=C grep -q '[^ -~	]' "$I18N_JS" \
  && bad "i18n.js contains non-ASCII bytes (glyphs must be \XXXX escapes)" \
  || ok "i18n.js stays pure ASCII"
# One pass for parity across every offered language, JS call sites and the
# data-i18n marks in both pages: the parity walk is what stops a
# half-translated language from shipping.
if "$NODE" -e '
  const fs = require("fs");
  globalThis.window = globalThis;
  require(process.argv[1]);
  const I = globalThis.I18N;
  const codes = ["de", "en", "tlh"];
  const ref = Object.keys(I.dict("en")).sort();
  let bad = 0;
  for (const c of codes) {
    const keys = Object.keys(I.dict(c)).sort();
    if (keys.join("\n") !== ref.join("\n")) {
      console.error("dictionary " + c + " disagrees: " + keys.length + " vs " + ref.length + " keys");
      bad = 1;
    }
  }
  const have = (k) => codes.every((c) => k in I.dict(c));
  for (const f of ["app", "fxenc", "login"]) {
    const src = fs.readFileSync(process.argv[2] + "/assets/" + f + ".js", "utf8");
    for (const m of src.matchAll(/\bt\("([a-z][a-zA-Z0-9_.]*)"\)/g)) {
      if (!have(m[1])) {
        console.error(f + ".js uses an unknown key: " + m[1]);
        bad = 1;
      }
    }
  }
  for (const h of ["index.html", "login.html"]) {
    const src = fs.readFileSync(process.argv[2] + "/" + h, "utf8");
    for (const m of src.matchAll(/data-i18n(?:-title|-aria|-ph)?="([^"]+)"/g)) {
      if (!have(m[1])) {
        console.error(h + " marks an unknown key: " + m[1]);
        bad = 1;
      }
    }
  }
  process.exit(bad ? 1 : 0);
' "$I18N_JS" "$REPO/frontend"; then
  ok "every language dictionary agrees and every marked or used key exists"
else
  bad "i18n dictionary or key usage is broken"
fi
# The server names failures with a stable code so the UI can translate them
# instead of echoing the English message.
grep -q 'pub fn code(&self)' "$REPO/src/error.rs" \
  && grep -q '"code": code' "$REPO/src/error.rs" \
  && ok "every server error carries a stable code to the frontend" \
  || bad "error responses do not carry a stable code"
grep -q 'pub code: String' "$REPO/src/models.rs" \
  && ok "batch failures carry the code per item" \
  || bad "BatchFailure has no code field"
grep -q 'fxcloud:langchange' "$UI" \
  && grep -q 'fxcloud:langchange' "$REPO/frontend/assets/fxenc.js" \
  && ok "both renderers repaint on a language switch" \
  || bad "a language switch leaves stale labels behind"

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

# The editor round trip and the encrypt-on-create rule are decisions rather
# than accidents, and neither leaves a trace on the wire that a check above
# could see: app.js would happily keep opening and saving files if someone
# dropped either branch, just always in the clear. That is exactly how a new
# .md file stayed plaintext while encryption was on, so both call sites are
# pinned here.
grep -q 'FXEnc.readText(entry)' "$UI" && grep -q 'FXEnc.writeText(entry, content)' "$UI" \
  && ok "the editor decrypts on open and encrypts on save" \
  || bad "app.js does not round-trip encrypted rows through fxenc.js"
grep -q 'FXEnc.writeText(entry, "")' "$UI" \
  && ok "a file created while encryption is on is encrypted immediately" \
  || bad "newFile() creates its file without encrypting it"

# The stored MIME type is the second opinion of previewKind(): the extension
# stays the first answer (it is what the name promises), and the sniffed type
# decides only when the name says nothing - which is exactly the case of a
# file uploaded without an extension. Encrypted rows carry mime = null and
# are decided by name alone, as before. Dropping either half shows up as
# "the file no longer opens" rather than as a failed request, so both are
# pinned here.
grep -q 'function previewKind(name, mime)' "$UI" \
  && ok "previewKind() takes the stored MIME type as its second opinion" \
  || bad "previewKind() does not accept a mime parameter"
grep -q 'previewKind(entry\.name, entry\.mime)' "$UI" \
  && ok "the callers pass the entry's mime along with its name" \
  || bad "no caller hands entry.mime to previewKind()"
[ "$(grep -c 'previewKind(entry\.name, entry\.mime)' "$UI")" = "3" ] \
  && ok "all three decision points consult the mime type" \
  || bad "expected 3 mime-aware previewKind() calls, found $(grep -c 'previewKind(entry\.name, entry\.mime)' "$UI")"
grep -q 'mime\.startsWith("text/")' "$UI" \
  && ok "the fallback maps text/* onto the editor kind" \
  || bad "app.js has no text/* fallback in previewKind()"

# A save changes the row on the server, and the folder behind the lightbox is
# the second place that holds a key for it: newFile() hands the editor the
# *save response*, not one of the rendered rows. So the refresh has to happen
# before the "is this still the open file?" check - put it behind that and
# closing the lightbox during the round trip skips it, every row keeps the
# previous wrapped key, and the next open unwraps that key happily and fails
# much further down, as "decryption failed for chunk 0".
SAVE_BODY=$(awk '/^  function saveEditor\(\)/,/^  }$/' "$UI")
REFRESH=$(printf '%s\n' "$SAVE_BODY" | grep -n 'openFolder(currentParent);' | cut -d: -f1 | head -1)
SAVE_GUARD=$(printf '%s\n' "$SAVE_BODY" | grep -n 'if (editorEntry !== entry) return;' | cut -d: -f1 | head -1)
[ -n "$REFRESH" ] && [ -n "$SAVE_GUARD" ] && [ "$REFRESH" -lt "$SAVE_GUARD" ] \
  && ok "a save refreshes the folder before it drops the response" \
  || bad "saveEditor() refreshes the listing only while that file is still open"

# Sign-in and the app are two page loads, so login.js has to park the password
# while its own document still exists - and it has to ask the key row first,
# because a separate passphrase is never carried (ENCRYPTION.md 5.7). Neither
# mistake throws anything: both compile, run, and leave the pane asking for
# the string the user typed a moment ago, so they are pinned here.
LOGIN_JS=$REPO/frontend/assets/login.js
CARRY=$(grep -n 'await carrySecretAcrossRedirect(form.password.value);' "$LOGIN_JS" | cut -d: -f1 | head -1)
REDIRECT=$(grep -n 'window.location.href = "/";' "$LOGIN_JS" | cut -d: -f1 | head -1)
[ -n "$CARRY" ] && [ -n "$REDIRECT" ] && [ "$CARRY" -lt "$REDIRECT" ] \
  && ok "sign-in parks the secret before it redirects to the app" \
  || bad "login.js parks the handoff only after its document is gone"
grep -q 'params.secret === "separate"' "$LOGIN_JS" \
  && ok "sign-in never parks a secret for a 'separate' row" \
  || bad "login.js would carry the login password into a separate-passphrase account"

# Whether a new write ends up encrypted follows the badge, not a prompt.
# Gating these two call sites on enabled() ("this account has a key record")
# turned every reload into a passphrase request for an ordinary upload, and
# declining threw the batch away while the header said nothing about what
# would have happened instead - so a locked tab silently meant "blocked" and
# an unencrypted one meant nothing in particular. The behaviour and the label
# are one decision (ENCRYPTION.md 9, flows 2-3, DECISION 11): the labels are
# asserted by fxenc-harness.js, the write gates are pinned here.
[ "$(grep -c 'FXEnc\.unlocked()' "$UI")" -ge 2 ] \
  && ok "new file and upload each decide on FXEnc.unlocked()" \
  || bad "a write path no longer asks whether this tab is encrypted"
grep -q 'FXEnc\.enabled()' "$UI" \
  && bad "app.js still gates a write on FXEnc.enabled() - that is the old prompt" \
  || ok "no write in app.js is gated on 'the account has keys' any more"

# The share dialog's two halves - sealing an envelope per item and the key
# it seals to - exist only as call sites in app.js: drop either and the
# request still succeeds, with a grantee who receives a share they can look
# at and never open. The retired body shape is pinned as gone, because the
# server now answers it with 400 (5.5).
grep -q 'file_ids' "$UI" \
  && bad "app.js still posts the retired file_ids field" \
  || ok "app.js no longer posts the retired file_ids field"
grep -q 'FXEnc\.shareEnvelope(' "$UI" && grep -q '^\s*items,$' "$UI" \
  && ok "the dialog seals one envelope per item and posts them as items" \
  || bad "shareAdd() does not seal an envelope per item into the items body"
grep -q 'id="share-fp"' "$ENC_HTML" && grep -q 'showShareFingerprint()' "$UI" \
  && ok "the grantee's fingerprint is shown while they are picked (DECISION 6)" \
  || bad "the share dialog never shows the grantee's key fingerprint"
grep -q 'fxcloud.peerfp' "$UI" \
  && ok "the one thing in localStorage is a public fingerprint, nothing else" \
  || bad "the TOFU record is not where ENCRYPTION.md 11 says it is"
[ "$(grep -c 'FXEnc\.requestKeys()' "$UI")" -ge 2 ] \
  && ok "sharing and moving keyed rows both wait for the unlock prompt" \
  || bad "a keyed share or move no longer asks for keys first"

# A move re-binds the record *before* the row travels: the record has to
# name the destination by the time the row stands there, and a rejected
# move then has one local wrap to undo. After the move would open the row
# against a parent it is not under yet - which reads as a dead file much
# later, not as an error now (5.4).
MOVE_BODY=$(awk '/^  async function transferConfirm\(\)/,/^  }$/' "$UI")
REBIND=$(printf '%s\n' "$MOVE_BODY" | grep -n 'FXEnc\.rewrapForParent(entry, oldParent, dest\.id);' | cut -d: -f1 | head -1)
POST=$(printf '%s\n' "$MOVE_BODY" | grep -n 'await api(endpoint, {' | cut -d: -f1 | head -1)
[ -n "$REBIND" ] && [ -n "$POST" ] && [ "$REBIND" -lt "$POST" ] \
  && ok "an encrypted move re-binds the record before the row moves" \
  || bad "transferConfirm() does not re-bind before the move request (rebind=$REBIND post=$POST)"

# An encrypted preview happens in this tab: fetch the container, the worker
# decrypts, the frame renders a blob URL. None of that leaves a trace the
# server checks above could see - dropping the decrypt branch would leave
# <img>/<iframe> happily rendering ciphertext, and the sandbox that the
# server's CSP header used to carry would move with it, since a blob URL
# never reaches a server header. So the preview decision (12, phase 2) is
# pinned here, at the only place that can still see it.
grep -q 'FXEnc\.previewBlob(' "$UI" \
  && ok "an encrypted preview pulls and decrypts the container in the tab" \
  || bad "app.js does not preview encrypted rows through fxenc.js"
grep -q 'previewBlob: previewBlob' "$ENC_JS" \
  && ok "fxenc.js exports previewBlob beside download" \
  || bad "fxenc.js does not export previewBlob"
grep -q 'mimeForPreview: mimeForPreview' "$REPO/frontend/assets/fxcrypto.js" \
  && ok "the renderer type is its own map, not the download's" \
  || bad "fxcrypto.js does not export mimeForPreview"
grep -q 'arrives in a later phase' "$UI" \
  && bad "app.js still defers the encrypted preview to a later phase" \
  || ok "no preview is refused with 'arrives in a later phase' any more"
grep -q 'entry\.enc_version === 0 &&' "$UI" \
  && bad "the row click still refuses encrypted rows" \
  || ok "a clickable preview row is no longer gated on plaintext"
grep -q 'setAttribute("sandbox", "")' "$UI" \
  && ok "a previewed HTML frame carries its own sandbox (blob URLs skip server CSP)" \
  || bad "the encrypted HTML preview renders without a sandbox"
grep -q 'URL\.revokeObjectURL(previewUrl)' "$UI" \
  && ok "closing the lightbox releases the decrypted blob URL" \
  || bad "a decrypted preview URL outlives the lightbox"

# ---- file list sorting ----
note "file list sorting (name / date / size, both directions)"
IDX=$REPO/frontend/index.html
grep -q 'data-sort="name"' "$IDX" && grep -q 'data-sort="size"' "$IDX" \
  && grep -q 'data-sort="date"' "$IDX" \
  && ok "the Name, Size and Modified headers are sortable" \
  || bad "sortable column headers missing from index.html"
grep -q 'function sortEntries(' "$UI" && grep -q 'function compareEntries(' "$UI" \
  && ok "the listing sorts its rows locally" \
  || bad "no local sort functions in app.js"
grep -q 'sortState\.dir === "asc" ? "desc" : "asc"' "$UI" \
  && ok "a header click toggles between both directions" \
  || bad "sort direction does not toggle asc/desc"
grep -q 'SORT_FIRST_DIR' "$UI" \
  && ok "each column starts from its natural direction" \
  || bad "no natural first-click direction"
grep -q 'a\.is_dir !== b\.is_dir' "$UI" \
  && ok "folders stay grouped before files when sorting" \
  || bad "folders are not kept ahead of files"
grep -q 'entries = sortEntries(entries)' "$UI" \
  && ok "every list render goes through the sort" \
  || bad "renderRows bypasses the sort"

# ---- hidden files toggle ----
note "hidden files (dot entries) toggle"
IDX=$REPO/frontend/index.html
grep -q 'id="hidden-toggle"' "$IDX" \
  && ok "the toolbar carries a Show hidden toggle" \
  || bad "no #hidden-toggle in index.html"
grep -q 'e\.name\.startsWith("\.")' "$UI" \
  && ok "entries whose name starts with a dot are recognised as hidden" \
  || bad "no dot-prefix test in app.js"
grep -q 'fxcloud\.showHidden' "$UI" \
  && ok "the hidden preference is remembered in localStorage" \
  || bad "the hidden preference is not persisted"
grep -q 'let rawEntries' "$UI" && grep -q 'rawEntries = entries' "$UI" \
  && ok "the unfiltered listing is kept so the toggle can repaint" \
  || bad "the raw listing is not retained"
grep -q 'entries = showHidden ? entries : entries\.filter' "$UI" \
  && ok "rows are filtered by the toggle before the sort" \
  || bad "the toggle does not filter the rows"

# ---- toolbar button hierarchy ----
# One rule across the file list's two button rows: a primary (.btn) action
# carries an icon, a secondary or danger one is plain text. Every glyph is
# spelled with an escape so this suite file stays pure ASCII.
note "toolbar buttons: primary carries an icon, secondary stays plain"
IDX=$REPO/frontend/index.html
UP=$'\u2b06'             # upload glyph (U+2B06), escaped so the suite stays ASCII
FLD=$'\U1F4C1'      # folder emoji
BASKET=$'\U1F5D1'   # wastebasket emoji
grep -q "class=\"btn\" id=\"upload-folder-btn\" data-i18n=\"files.uploadFolder\">${UP} Upload folder</button>" "$IDX" \
  && ok "upload folder is a primary button like upload file" \
  || bad "upload folder is not styled like upload file"
grep -q 'class="btn secondary" id="trash-btn" data-i18n="files.trash">Trash</button>' "$IDX" \
  && ok "the trash button is a plain secondary label" \
  || bad "the trash button still carries an icon"
grep -q "${FLD}\|${BASKET}" "$IDX" \
  && bad "index.html still mixes loose emoji into the buttons" \
  || ok "the two icons that broke the hierarchy are gone"
perl -0777 -e '
  my $html = <>;
  my ($n, $bad) = (0, 0);
  for my $open (q{<div class="toolbar">}, q{<div class="bulkbar"}) {
    my $i = index($html, $open);
    if ($i < 0) { $bad++; next; }
    my $rest = substr($html, $i);
    my $block = substr($rest, 0, index($rest, "\n    </div>"));
    while ($block =~ /<button class="(btn[^"]*)"[^>]*>(.*?)<\/button>/sg) {
      my ($cls, $label) = ($1, $2);
      $n++;
      (my $plain = $label) =~ s/\xE2\x80\xA6//g;  # dialog ellipsis, not an icon
      my $glyph = ($plain =~ /[^\x00-\x7F]/) ? 1 : 0;
      my $want  = ($cls eq "btn") ? 1 : 0;
      $bad++ if $glyph != $want;
    }
  }
  exit(($bad || !$n) ? 1 : 0);
' "$IDX" \
  && ok "every primary toolbar button carries an icon, every secondary one is plain" \
  || bad "icons do not line up with the button hierarchy"

# ---- user administration UI ----
note "user administration UI"
IDX=$REPO/frontend/index.html
grep -q 'id="user-admin-btn"' "$IDX" \
  && ok "the user menu carries a User administration entry" \
  || bad "no #user-admin-btn in index.html"
grep -q 'id="admin-modal"' "$IDX" \
  && ok "the user-administration dialog exists" \
  || bad "no #admin-modal in index.html"
grep -q 'id="reset-modal"' "$IDX" \
  && ok "the temporary-password dialog exists" \
  || bad "no #reset-modal in index.html"
grep -q 'res\.is_admin ? "" : "none"' "$UI" \
  && ok "the admin menu entry is gated on the is_admin flag" \
  || bad "the User administration entry is not gated on is_admin"
grep -q 'function openAdmin()' "$UI" && grep -q '/api/admin/users' "$UI" \
  && ok "the dialog loads the accounts from /api/admin/users" \
  || bad "the admin dialog does not reach /api/admin/users"
grep -q 'temporary_password' "$UI" \
  && ok "the reset dialog shows the generated temporary password" \
  || bad "the temporary password is not surfaced in the UI"
grep -q 'quota_bytes' "$UI" \
  && ok "the dialog can change the quota" \
  || bad "no quota control in the admin dialog"

# ---- passkeys (WebAuthn) ----
# A virtual authenticator (frontend/tests/webauthn.js) builds every ceremony
# output byte by byte - clientDataJSON, authenticatorData, the COSE key, the
# signature - so the happy paths and each rejection are driven over the real
# endpoints with the exact bytes a browser would send, including the bad ones
# no honest browser produces. Placed after every server restart above:
# challenges live in memory and would not survive a restart.
note "passkeys (WebAuthn): registration, sign-in, rejections, device list"
WA=$REPO/frontend/tests/webauthn.js
PKB=$BASE          # what clientDataJSON must claim; no Origin header is sent
                   # below, so the server derives this same origin itself
PLOGIN=$ROOT/pk-login.jar

# -- registration -------------------------------------------------------
RC=$(reqsave POST /api/passkeys/register/start "$JA" "$ROOT/pk-rstart.json" '{}')
[ "$RC" = "200" ] && ok "a signed-in account starts a registration ceremony" \
  || bad "register/start: $RC"

RC=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' -d '{}' "$BASE/api/passkeys/register/start")
[ "$RC" = "401" ] && ok "starting a registration needs a session" \
  || bad "sessionless register/start: $RC"

# Without an Origin header the server derives the origin from Host and the
# secure-cookie flag; the clientData built below claims exactly that.
RC=$(curl -s -o /dev/null -w '%{http_code}' -X POST -b "$JA" -c "$JA" \
  -H 'Content-Type: application/json' -d '{}' "$BASE/api/passkeys/register/start")
[ "$RC" = "200" ] && ok "the WebAuthn origin is derived when no Origin header is sent" \
  || bad "derived origin: $RC"

RC=$(curl -s -o /dev/null -w '%{http_code}' -X POST -b "$JA" -c "$JA" \
  -H 'Content-Type: application/json' -H 'Origin: https://evil.example' \
  -d '{}' "$BASE/api/passkeys/register/start")
[ "$RC" = "400" ] && ok "a foreign Origin header fails before a challenge is spent" \
  || bad "foreign Origin: $RC"

"$NODE" "$WA" register "$ROOT/pk-rstart.json" "$ROOT/pk-state.json" \
  "$ROOT/pk-rcred.json" --origin=$PKB \
  && ok "the virtual authenticator answers with an attestation" \
  || bad "webauthn.js register failed"

BODY=$(printf '{"label":"Laptop","credential":%s}' "$(cat "$ROOT/pk-rcred.json")")
RC=$(reqsave POST /api/passkeys/register/finish "$JA" "$ROOT/pk-rfin.json" "$BODY")
[ "$RC" = "201" ] && grep -q '"label":"Laptop"' "$ROOT/pk-rfin.json" \
  && ok "the attestation verifies and the first passkey is stored" \
  || bad "register/finish: $RC $(head -c 200 "$ROOT/pk-rfin.json")"

CREDID=$(jget "$(cat "$ROOT/pk-rcred.json")" id)
reqsave POST /api/passkeys/register/start "$JA" "$ROOT/pk-rstart2.json" '{}' >/dev/null
"$NODE" "$WA" register "$ROOT/pk-rstart2.json" "$ROOT/pk-state2.json" \
  "$ROOT/pk-rcred2.json" --origin=$PKB --cred-id="$CREDID"
BODY=$(printf '{"label":"Dup","credential":%s}' "$(cat "$ROOT/pk-rcred2.json")")
RC=$(reqsave POST /api/passkeys/register/finish "$JA" "$ROOT/pk-rfin2.json" "$BODY")
[ "$RC" = "409" ] && ok "the same authenticator cannot register twice" \
  || bad "duplicate credential: $RC"

RC=$(reqsave GET /api/me/passkeys "$JA" "$ROOT/pk-list.json")
NPK=$(perl -MJSON::PP -0777 -e 'print scalar @{decode_json(<STDIN>)}' <"$ROOT/pk-list.json")
[ "$RC" = "200" ] && [ "$NPK" = "1" ] && ok "the device list shows the stored passkey" \
  || bad "device list: $RC/$NPK"

RC=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/me/passkeys")
[ "$RC" = "401" ] && ok "the device list needs a session" \
  || bad "sessionless device list: $RC"

# -- sign-in ------------------------------------------------------------
RC=$(reqsave POST /api/passkeys/login/start "$PLOGIN" "$ROOT/pk-lstart.json" \
  '{"username":"alice"}')
NALLOW=$(perl -MJSON::PP -0777 -e 'print scalar @{decode_json(<STDIN>)->{allowCredentials}}' <"$ROOT/pk-lstart.json")
[ "$RC" = "200" ] && [ "$NALLOW" = "1" ] && ok "login/start offers alice's credential" \
  || bad "login/start: $RC/$NALLOW"

RC=$(reqsave POST /api/passkeys/login/start "$PLOGIN" "$ROOT/pk-lghost.json" \
  '{"username":"nobody-here"}')
NGHOST=$(perl -MJSON::PP -0777 -e 'print scalar @{decode_json(<STDIN>)->{allowCredentials}}' <"$ROOT/pk-lghost.json")
[ "$RC" = "200" ] && [ "$NGHOST" = "1" ] \
  && ok "an unknown name gets the identical shape (one dummy entry)" \
  || bad "ghost login/start: $RC/$NGHOST"

"$NODE" "$WA" assert "$ROOT/pk-lstart.json" "$ROOT/pk-state.json" \
  "$ROOT/pk-lcred.json" --origin=$PKB \
  && ok "the authenticator signs the challenge" \
  || bad "webauthn.js assert failed"
BODY=$(printf '{"credential":%s}' "$(cat "$ROOT/pk-lcred.json")")
RC=$(reqsave POST /api/passkeys/login/finish "$PLOGIN" "$ROOT/pk-lfin.json" "$BODY")
[ "$RC" = "200" ] && grep -q 'fxcloud_session' "$PLOGIN" \
  && grep -q '"username":"alice"' "$ROOT/pk-lfin.json" \
  && ok "a verified assertion opens a session" \
  || bad "login/finish: $RC $(head -c 200 "$ROOT/pk-lfin.json")"

RC=$(reqsave POST /api/passkeys/login/finish "$PLOGIN" "$ROOT/pk-lfin2.json" "$BODY")
[ "$RC" = "401" ] && ok "a replayed assertion is refused (challenges are single-use)" \
  || bad "replay: $RC"

# One tampered output per fresh ceremony. The state file's counter advances
# like a real device's even when the server refuses, so the clone-detection
# pin below sees the value the server last accepted (1), not a fresh one.
pk_bad() { # pk_bad <webauthn.js flags...> -> status of the finish call
  reqsave POST /api/passkeys/login/start "$PLOGIN" "$ROOT/pk-lb.json" \
    '{"username":"alice"}' >/dev/null || return 99
  "$NODE" "$WA" assert "$ROOT/pk-lb.json" "$ROOT/pk-state.json" \
    "$ROOT/pk-lcred-bad.json" --origin=$PKB "$@" || return 99
  reqsave POST /api/passkeys/login/finish "$PLOGIN" "$ROOT/pk-lfin-bad.json" \
    "{\"credential\":$(cat "$ROOT/pk-lcred-bad.json")}"
}

RC=$(pk_bad --bad-challenge)
[ "$RC" = "401" ] && ok "an unknown challenge is refused" || bad "unknown challenge: $RC"
RC=$(pk_bad --bad-origin=https://evil.example)
[ "$RC" = "400" ] && ok "a clientData origin of another site is refused" \
  || bad "bad origin: $RC"
RC=$(pk_bad --bad-sig)
[ "$RC" = "401" ] && ok "a tampered signature is refused" || bad "bad signature: $RC"
RC=$(pk_bad --rp=evil.example)
[ "$RC" = "400" ] && ok "a credential minted for a foreign rpId is refused" \
  || bad "foreign rpId: $RC"
RC=$(pk_bad --cross-origin)
[ "$RC" = "400" ] && ok "cross-origin ceremonies are refused" || bad "crossOrigin: $RC"
RC=$(pk_bad --bad-userhandle)
[ "$RC" = "401" ] && ok "a userHandle of another account is refused" \
  || bad "userHandle: $RC"
RC=$(pk_bad --counter=1)
[ "$RC" = "400" ] && ok "a standing signature counter is refused (clone detection)" \
  || bad "counter: $RC"
RC=$(pk_bad)
[ "$RC" = "200" ] && ok "the next honest assertion still signs in" \
  || bad "honest retry: $RC"

# The ceremony kind is re-checked at redemption, in both directions: a
# registration challenge cannot open a session and a login challenge cannot
# register a device.
reqsave POST /api/passkeys/register/start "$JA" "$ROOT/pk-kindreg.json" '{}' >/dev/null
"$NODE" "$WA" assert "$ROOT/pk-kindreg.json" "$ROOT/pk-state.json" \
  "$ROOT/pk-kindcred.json" --origin=$PKB --rp=127.0.0.1
BODY=$(printf '{"credential":%s}' "$(cat "$ROOT/pk-kindcred.json")")
RC=$(reqsave POST /api/passkeys/login/finish "$PLOGIN" "$ROOT/pk-kindfin.json" "$BODY")
[ "$RC" = "401" ] && ok "a registration challenge cannot redeem as a login" \
  || bad "kind guard register->login: $RC"

reqsave POST /api/passkeys/login/start "$PLOGIN" "$ROOT/pk-kindlog.json" \
  '{"username":"alice"}' >/dev/null
"$NODE" "$WA" register "$ROOT/pk-kindlog.json" "$ROOT/pk-kindstate.json" \
  "$ROOT/pk-kindcred2.json" --origin=$PKB --rp=127.0.0.1
BODY=$(printf '{"label":"Kind","credential":%s}' "$(cat "$ROOT/pk-kindcred2.json")")
RC=$(reqsave POST /api/passkeys/register/finish "$JA" "$ROOT/pk-kindfin2.json" "$BODY")
[ "$RC" = "401" ] && ok "a login challenge cannot redeem as a registration" \
  || bad "kind guard login->register: $RC"

# A real credential answering a ceremony opened for a name nobody has: the
# ceremony carries no account, so the credential never gets the chance to
# switch users silently.
reqsave POST /api/passkeys/login/start "$PLOGIN" "$ROOT/pk-lghost2.json" \
  '{"username":"nobody-here"}' >/dev/null
"$NODE" "$WA" assert "$ROOT/pk-lghost2.json" "$ROOT/pk-state.json" \
  "$ROOT/pk-lgcred.json" --origin=$PKB
BODY=$(printf '{"credential":%s}' "$(cat "$ROOT/pk-lgcred.json")")
RC=$(reqsave POST /api/passkeys/login/finish "$PLOGIN" "$ROOT/pk-lgfin.json" "$BODY")
[ "$RC" = "401" ] && ok "a real credential cannot answer an unknown account's ceremony" \
  || bad "ghost ceremony: $RC"

# -- device management --------------------------------------------------
PKID=$(jget "$(cat "$ROOT/pk-rfin.json")" id)
RC=$(reqsave PATCH "/api/me/passkeys/$PKID" "$JA" "$ROOT/pk-ren.json" \
  '{"label":"Key on the ring"}')
[ "$RC" = "200" ] && grep -q 'Key on the ring' "$ROOT/pk-ren.json" \
  && ok "a passkey can be renamed" || bad "rename: $RC"

RC=$(reqsave PATCH "/api/me/passkeys/$PKID" "$JA" "$ROOT/pk-ren2.json" '{"label":"   "}')
[ "$RC" = "400" ] && ok "a blank label is refused" || bad "blank label: $RC"

RC=$(reqsave DELETE "/api/me/passkeys/$PKID" "$JA" "$ROOT/pk-del.json")
[ "$RC" = "200" ] && ok "a passkey can be removed" || bad "delete: $RC"

RC=$(reqsave GET /api/me/passkeys "$JA" "$ROOT/pk-list2.json")
NPK=$(perl -MJSON::PP -0777 -e 'print scalar @{decode_json(<STDIN>)}' <"$ROOT/pk-list2.json")
[ "$RC" = "200" ] && [ "$NPK" = "0" ] && ok "the list is empty after the removal" \
  || bad "list after delete: $RC/$NPK"

RC=$(reqsave DELETE "/api/me/passkeys/$PKID" "$JA" "$ROOT/pk-del2.json")
[ "$RC" = "404" ] && ok "removing it twice is a 404" || bad "double delete: $RC"

# -- credential verified, account deactivated -> 403 --------------------
# Same ordering as the password flow: the credential checks out first, only
# then does the account state decide - an inactive account is not told
# anything a stranger could not learn from a wrong password.
PJ3=$ROOT/pk-inactive.jar
reqsave POST /api/register "$PJ3" "$ROOT/pk-ureg.json" \
  '{"username":"pkuser","password":"correct-horse"}' >/dev/null
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET is_active=1 WHERE username='pkuser';"
reqsave POST /api/login "$PJ3" "$ROOT/pk-ulogin.json" \
  '{"username":"pkuser","password":"correct-horse"}' >/dev/null
reqsave POST /api/passkeys/register/start "$PJ3" "$ROOT/pk-istart.json" '{}' >/dev/null
"$NODE" "$WA" register "$ROOT/pk-istart.json" "$ROOT/pk-istate.json" \
  "$ROOT/pk-icred.json" --origin=$PKB
BODY=$(printf '{"label":"Phone","credential":%s}' "$(cat "$ROOT/pk-icred.json")")
reqsave POST /api/passkeys/register/finish "$PJ3" "$ROOT/pk-ifin.json" "$BODY" >/dev/null
reqsave POST /api/passkeys/login/start "$PJ3" "$ROOT/pk-ilstart.json" \
  '{"username":"pkuser"}' >/dev/null
"$NODE" "$WA" assert "$ROOT/pk-ilstart.json" "$ROOT/pk-istate.json" \
  "$ROOT/pk-ilcred.json" --origin=$PKB
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET is_active=0 WHERE username='pkuser';"
BODY=$(printf '{"credential":%s}' "$(cat "$ROOT/pk-ilcred.json")")
RC=$(reqsave POST /api/passkeys/login/finish "$PJ3" "$ROOT/pk-ilfin.json" "$BODY")
[ "$RC" = "403" ] && grep -q 'not activated' "$ROOT/pk-ilfin.json" \
  && ok "a verified passkey cannot sign in a deactivated account (403)" \
  || bad "inactive passkey login: $RC $(head -c 200 "$ROOT/pk-ilfin.json")"

# -- passkey UI ---------------------------------------------------------
# The pages are embedded at build time, so greps here see what the running
# instance serves. Both pages load webauthn-client.js - one marshalling
# implementation for the login tab and the settings list.
note "passkey UI: login tab and the settings device list"
LHTML=$REPO/frontend/login.html
LJS=$REPO/frontend/assets/login.js
IDX=$REPO/frontend/index.html
UI=$REPO/frontend/assets/app.js

grep -q 'id="tab-passkey"' "$LHTML" && grep -q 'id="passkey-form"' "$LHTML" \
  && ok "the login page carries a passkey tab with its own form" \
  || bad "login.html has no passkey tab/form"
grep -q 'src="/assets/webauthn-client.js"' "$LHTML" \
  && ok "the login page loads the WebAuthn marshalling helper" \
  || bad "login.html does not load webauthn-client.js"
grep -q 'navigator\.credentials\.get' "$LJS" \
  && ok "login.js drives the browser's credential prompt" \
  || bad "login.js never calls navigator.credentials.get"
grep -q 'form.style.display = isPasskey' "$LJS" \
  && ok "the passkey tab hides the password form and its required field" \
  || bad "the password form is not hidden on the passkey tab"
grep -q 'id="passkey-list"' "$IDX" && grep -q 'id="passkey-add-btn"' "$IDX" \
  && ok "the settings dialog has the device section" \
  || bad "index.html has no passkey section"
grep -q 'src="/assets/webauthn-client.js"' "$IDX" \
  && ok "the app loads the WebAuthn marshalling helper" \
  || bad "index.html does not load webauthn-client.js"
grep -q 'navigator\.credentials\.create' "$UI" \
  && ok "app.js registers devices through the browser" \
  || bad "app.js never calls navigator.credentials.create"
grep -q 'loadPasskeys();' "$UI" \
  && ok "the device list refreshes when the dialog opens" \
  || bad "opening settings does not refresh the device list"
grep -q 'FXCLOUD_ORIGIN' "$REPO/src/config.rs" \
  && ok "the deployment origin is configurable (FXCLOUD_ORIGIN)" \
  || bad "no FXCLOUD_ORIGIN knob in config.rs"

note "server log (errors?)"
grep -iE 'panic|error' "$ROOT/server.log" | head -20 || true

echo
if [ "$FAIL" = "0" ]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
kill "$(cat "$ROOT/server.pid")" 2>/dev/null
exit "$FAIL"
