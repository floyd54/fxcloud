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
JD2=$ROOT/dave2.jar # a second sign-in of the same account (session checks)

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
# A second sign-in of the same account, so the change below has two live
# sessions to tell apart: the one holding the form, and the one a thief
# holding a stolen cookie would be riding.
RC=$(reqcode POST /api/login "$JD2" '{"username":"dave","password":"correct-horse"}')
[ "$RC" = "200" ] && ok "dave signs in a second time (a second live session)" \
  || bad "second sign-in failed (rc=$RC)"

RC=$(reqcode PUT /api/me/password "$JD" '{"current_password":"wrong-password","new_password":"another-horse"}')
[ "$RC" = "401" ] && ok "a wrong current password is refused (401)" || bad "expected 401, got $RC"
RC=$(reqcode PUT /api/me/password "$JD" '{"current_password":"correct-horse","new_password":"short"}')
[ "$RC" = "400" ] && ok "a short new password is refused (400)" || bad "expected 400, got $RC"
RC=$(reqcode PUT /api/me/password "$JD" '{"current_password":"correct-horse","new_password":"another-horse"}')
[ "$RC" = "200" ] && ok "the password changes (200)" || bad "expected 200, got $RC"
# F3: the change takes the account's other sessions with it - a password
# change is the incident response for a stolen credential, and the
# thief's cookie cannot be allowed to outlive the old hash for the rest
# of the TTL. The caller's own session stays: it authenticated this very
# request, and the menu that made the change keeps working.
RC=$(reqcode GET /api/me "$JD")
[ "$RC" = "200" ] && ok "the session that made the change stays open" \
  || bad "own session died with the change (rc=$RC)"
RC=$(reqcode GET /api/me "$JD2")
[ "$RC" = "401" ] && ok "the account's other session is cut off by the change" \
  || bad "other session survived the change (rc=$RC)"

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
# F3: a reset is called for precisely when an account may be compromised
# - a lost or stolen password - so it takes every session of the target
# with it. Sign in once more first, so there are two standing sessions
# for the reset to prove it dropped.
RC=$(reqcode POST /api/login "$JD2" '{"username":"dave","password":"correct-horse"}')
[ "$RC" = "200" ] && ok "dave signs in a second time before the reset" \
  || bad "pre-reset sign-in failed (rc=$RC)"
RESET=$(req POST "/api/admin/users/$DAVE/password" "$JA")
TMP=$(jget "$RESET" temporary_password)
[ "${#TMP}" = "16" ] && ok "the reset returns a 16-character temporary password" || bad "temp password length ${#TMP}, expected 16"
RC=$(reqcode GET /api/me "$JD")
[ "$RC" = "401" ] && ok "the reset drops the target's standing session" \
  || bad "standing session survived the reset (rc=$RC)"
RC=$(reqcode GET /api/me "$JD2")
[ "$RC" = "401" ] && ok "and every other session of that account" \
  || bad "second session survived the reset (rc=$RC)"
RC=$(reqcode GET /api/me "$JA")
[ "$RC" = "200" ] && ok "the administrator's own session is untouched" \
  || bad "admin session died with the reset (rc=$RC)"
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

# ---- streaming (S1): server pipes stay flat, ranges reach /download ----
# The pins below hold the memory work in place: no whole-buffer helper may
# come back (the source pins are the cheap early warning), the download
# honours ranges exactly like the preview does, and the caps answer 413 by
# counting bytes rather than by holding them.
note "streaming source pins: no whole-buffer path is back"
grep -q 'field\.bytes()' "$REPO/src/web/routes/files.rs" \
  && bad "the upload buffers the file field again" \
  || ok "source: no field.bytes() on the upload path"
grep -q 'body: Bytes' "$REPO/src/web/routes/files.rs" \
  && bad "the editor save takes a buffered body again" \
  || ok "source: editor save consumes the request, not Bytes"
grep -q 'to_bytes' "$REPO/src/webdav.rs" \
  && bad "WebDAV buffers bodies with to_bytes again" \
  || ok "source: WebDAV PUT streams instead of to_bytes"
grep -rq 'read_blob' "$REPO/src" \
  && bad "a whole-buffer read path is back" \
  || ok "source: no read_blob left - open_blob streams"
grep -q 'sweep_temps' "$REPO/src/main.rs" \
  && ok "source: startup sweeps stale temp files" \
  || bad "main.rs never calls sweep_temps"
grep -q 'fn commit_blob' "$REPO/src/files/mod.rs" \
  && ok "source: commits happen by rename (commit_blob)" \
  || bad "files/mod.rs has no commit_blob"

note "download honours byte ranges like the preview (206/416 + headers)"
curl -s -D "$ROOT/dh.txt" -o /dev/null -b "$JA" "$BASE/api/files/download?id=$NID"
grep -qi '^accept-ranges: bytes' "$ROOT/dh.txt" \
  && ok "download advertises accept-ranges: bytes" \
  || bad "download accept-ranges missing"
grep -qi '^content-length: 32' "$ROOT/dh.txt" \
  && ok "download carries the content-length from file metadata" \
  || bad "download content-length: $(grep -i '^content-length' "$ROOT/dh.txt")"
DLO=$(curl -s -D "$ROOT/dh.txt" -b "$JA" -H 'Range: bytes=7-11' "$BASE/api/files/download?id=$NID")
grep -qi '^HTTP/[0-9.]* 206' "$ROOT/dh.txt" && grep -qi '^content-range: bytes 7-11/32' "$ROOT/dh.txt" \
  && [ "$DLO" = "previ" ] \
  && ok "download range bytes=7-11 -> 206 + exact slice" \
  || bad "download range: $(head -1 "$ROOT/dh.txt") [$DLO]"
DLO=$(curl -s -D "$ROOT/dh.txt" -b "$JA" -H 'Range: bytes=-10' "$BASE/api/files/download?id=$NID")
grep -qi '^content-range: bytes 22-31/32' "$ROOT/dh.txt" && [ "$DLO" = "0123456789" ] \
  && ok "download suffix range bytes=-10 -> last 10 bytes" \
  || bad "download suffix range: [$DLO]"
RC=$(curl -s -o /dev/null -D "$ROOT/dh.txt" -w '%{http_code}' -b "$JA" \
  -H 'Range: bytes=9999-' "$BASE/api/files/download?id=$NID")
[ "$RC" = "416" ] && grep -qi '^content-range: bytes \*/32' "$ROOT/dh.txt" \
  && ok "download unsatisfiable range -> 416 + bytes */32" \
  || bad "download 416: got $RC"

note "a 16 MiB file streams in and answers a ranged read at its far end"
head -c 16777216 /dev/urandom > "$ROOT/src/big.bin"
BIGR=$(up "$JA" "$DOC" big.bin)
BIGID=$(jget "$BIGR" entry.id)
[ -n "$BIGID" ] && ok "16 MiB upload succeeded (id $BIGID)" \
  || bad "16 MiB upload failed: $BIGR"
OLIST=$(req GET "/api/files?parent=$DOC" "$JA")
[ "$(field "$OLIST" big.bin size)" = "16777216" ] \
  && ok "its stored size is exactly 16 MiB" \
  || bad "big.bin size: '$(field "$OLIST" big.bin size)'"
RC=$(curl -s -o "$ROOT/big.dl" -D "$ROOT/dh.txt" -w '%{http_code}' -b "$JA" \
  -H 'Range: bytes=16711680-16777215' "$BASE/api/files/download?id=$BIGID")
grep -qi '^HTTP/[0-9.]* 206' "$ROOT/dh.txt" \
  && grep -qi '^content-range: bytes 16711680-16777215/16777216' "$ROOT/dh.txt" \
  && [ "$RC" = "206" ] \
  && ok "far-end range -> 206 + exact window on the 16 MiB file" \
  || bad "far-end range: rc=$RC $(head -1 "$ROOT/dh.txt")"
tail -c 65536 "$ROOT/src/big.bin" > "$ROOT/big.tail"
cmp -s "$ROOT/big.tail" "$ROOT/big.dl" \
  && ok "the last 64 KiB arrive byte-identical (streamed from disk)" \
  || bad "ranged slice differs from the source file"
[ -z "$(find "$DATA/tmp" -name '*.part' -print -quit 2>/dev/null)" ] \
  && ok "no temp file survives a completed upload" \
  || bad "leftover temp files: $(ls "$DATA/tmp")"

note "a refused upload takes its temp file with it"
# enc_version=1 without enc_key fails *past* the file field: the bytes were
# already streamed into the temp file when the refusal lands, so only the
# error path's cleanup keeps them from lingering until the next restart.
printf 'streamed-but-refused' > "$ROOT/src/refused.bin"
RC=$(curl -s -o "$ROOT/refused.json" -w '%{http_code}' -b "$JA" \
  -F "parent=$DOC" -F "enc_version=1" -F "file=@$ROOT/src/refused.bin" \
  "$BASE/api/files/upload")
[ "$RC" = "400" ] && ok "encrypted upload without enc_key -> 400" \
  || bad "expected 400 for missing enc_key, got $RC"
[ -z "$(find "$DATA/tmp" -name '*.part' -print -quit 2>/dev/null)" ] \
  && ok "the refused upload left no temp file behind" \
  || bad "temp survived the failed upload: $(ls "$DATA/tmp")"

# -- S1: 413 is counted, not buffered --
# A sidecar with FXCLOUD_MAX_UPLOAD_MB=1 (own data dir, own loopback port):
# a 2 MiB body is twice the cap, so the byte count refuses it long before
# memory could matter. It is killed by its own PID - never by comm name,
# the shared binary name would take the instance under test with it.
note "the upload cap answers 413 while counting (sidecar, 1 MiB limit)"
MINI="$ROOT/mini"
mkdir -p "$MINI"
FXCLOUD_DATA="$MINI" FXCLOUD_PORT=$((PORT + 41)) FXCLOUD_MAX_UPLOAD_MB=1 \
  "$BIN" >>"$ROOT/mini.log" 2>&1 &
MINIPID=$!
MINIBASE=http://127.0.0.1:$((PORT + 41))
MINIUP=0
for i in $(seq 1 100); do
  RC=$(curl -s -o /dev/null -w '%{http_code}' "$MINIBASE/api/me")
  [ "$RC" != "000" ] && { MINIUP=1; break; }
  sleep 0.2
done
[ "$MINIUP" = "1" ] && ok "sidecar instance came up (fresh data dir)" \
  || bad "sidecar did not come up: $(tail -5 "$ROOT/mini.log")"
RC=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
  -d '{"username":"mini","password":"correct-horse"}' "$MINIBASE/api/register")
# 200 when the fresh instance activates its first account outright, 202 when
# it parks pending activation - the login below proves which happened.
{ [ "$RC" = "200" ] || [ "$RC" = "202" ]; } \
  && ok "sidecar register accepted" || bad "sidecar register: rc=$RC"
sqlite3 "$MINI/fxcloud.db" "UPDATE users SET is_active=1 WHERE username='mini';"
RC=$(curl -s -o /dev/null -c "$ROOT/mini.jar" -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"username":"mini","password":"correct-horse"}' "$MINIBASE/api/login")
[ "$RC" = "200" ] && ok "sidecar sign-in works" || bad "sidecar login: rc=$RC"
head -c 2097152 /dev/zero > "$ROOT/mini-big.bin"
RC=$(curl -s -o "$ROOT/mini413.json" -w '%{http_code}' -b "$ROOT/mini.jar" \
  -F "file=@$ROOT/mini-big.bin" "$MINIBASE/api/files/upload")
[ "$RC" = "413" ] && ok "a 2 MiB body against a 1 MiB cap -> 413" \
  || bad "expected 413, got $RC: $(cat "$ROOT/mini413.json")"
grep -q '"code":"payload_too_large"' "$ROOT/mini413.json" \
  && ok "the 413 carries code payload_too_large" \
  || bad "413 body: $(cat "$ROOT/mini413.json")"
[ -d "$MINI/tmp" ] && [ -z "$(find "$MINI/tmp" -name '*.part' -print -quit 2>/dev/null)" ] \
  && ok "the over-cap upload's temp file is gone" \
  || bad "temp survived the 413: $(ls "$MINI/tmp" 2>&1)"
kill "$MINIPID" 2>/dev/null || true
wait "$MINIPID" 2>/dev/null || true

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

# ---- editor: unsaved-changes dialog (save / discard / cancel) ----
# The old guard was a native confirm(): two buttons, no way to say "save
# first", and a reflex click threw the edit away - which is exactly how
# users kept losing text. The dialog replaces it; Save carries the focus.
note "the editor close asks with a three-button dialog, Save as the default"
UI2="$REPO/frontend/assets/app.js"
IDX2="$REPO/frontend/index.html"
grep -q 'id="discard-modal"' "$IDX2" \
  && ok "the unsaved-changes dialog exists in index.html" \
  || bad "index.html has no discard-modal"
grep -q 'id="discard-save-btn"' "$IDX2" && grep -q 'id="discard-discard-btn"' "$IDX2" \
  && grep -q 'id="discard-cancel-btn"' "$IDX2" \
  && ok "the dialog offers save, discard and cancel" \
  || bad "the discard dialog lacks one of its three buttons"
grep -q 'discardSaveBtn\.focus()' "$UI2" \
  && ok "Save is the focused default button" \
  || bad "the dialog does not focus its Save button"
grep -q 'confirm(t("confirm.discard"))' "$UI2" \
  && bad "the editor still pops the two-button confirm()" \
  || ok "no native confirm() stands between the editor and its close"
grep -q 'async function confirmUnsaved' "$UI2" && grep -c 'await confirmUnsaved()' "$UI2" | grep -q '^2$' \
  && ok "Close and the gallery arrows share one unsaved-changes gate" \
  || bad "confirmUnsaved is not the shared gate for both close paths"
grep -q 'if (choice === "save") return saveEditor();' "$UI2" \
  && ok "the dialog's Save awaits the save before closing" \
  || bad "the Save answer does not await saveEditor()"
grep -q 'return Promise\.resolve(false);' "$UI2" \
  && ok "saveEditor answers a promise the close flow can wait on" \
  || bad "saveEditor does not report success/failure"
for DKEY in act.discard editor.unsaved.title editor.unsaved.body; do
  ND=$(grep -c "\"$DKEY\":" "$REPO/frontend/assets/i18n.js")
  [ "$ND" = "3" ] && ok "$DKEY ships in all three dictionaries" \
    || bad "$DKEY appears $ND times in i18n.js, expected 3"
done

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
# ---- version history (concepts/versioning.md) -----------------------------
# Every content replacement keeps the replaced bytes as a restorable previous
# version. The pins below walk the whole surface: listing, per-version
# download (ranges included), exchange restore (undoable), permissions,
# retention by count and by age, quota, and the trash keeping - then
# removing - the history along with its blobs.
note "version history: two saves keep the first bytes"

VDRESP=$(req POST /api/files/folder "$JA" '{"name":"ver"}')
VD=$(jget "$VDRESP" entry.id)
printf 'AAAAAAAAAA' > "$ROOT/src/v1.txt"
printf 'BBBBBBBBBB' > "$ROOT/src/v2.txt"
printf 'CCCCCCCCCCC' > "$ROOT/src/v3.txt"   # 11 bytes: the sizes must differ
VR=$(up "$JA" "$VD" v1.txt); VFILE=$(jget "$VR" entry.id)
[ -n "$VFILE" ] && ok "version test file created" || bad "version test file missing"

# Without a session the history is as closed as the file itself.
RC=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/files/versions?id=$VFILE")
[ "$RC" = "401" ] && ok "versions list without session -> 401" || bad "expected 401, got $RC"

VL=$(req GET "/api/files/versions?id=$VFILE" "$JA")
NV=$(printf '%s' "$VL" | perl -MJSON::PP -0777 -e 'my $d=decode_json(do{local $/;<STDIN>}); print scalar @{$d->{versions}}')
[ "$NV" = "0" ] && ok "an untouched file has no history" || bad "unexpected history: $VL"

# First save: the uploaded bytes become version 1.
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -b "$JA" -H 'Content-Type: text/plain' \
  --data-binary "@$ROOT/src/v2.txt" "$BASE/api/files/content?id=$VFILE")
[ "$RC" = "200" ] && ok "editor save -> 200" || bad "save v2 failed: $RC"
VL=$(req GET "/api/files/versions?id=$VFILE" "$JA")
NV=$(printf '%s' "$VL" | perl -MJSON::PP -0777 -e 'my $d=decode_json(do{local $/;<STDIN>}); print scalar @{$d->{versions}}')
[ "$NV" = "1" ] && ok "one save keeps one version" || bad "expected 1 version, got $NV: $VL"
V1ID=$(jget "$VL" versions.0.id)
V1SZ=$(jget "$VL" versions.0.size)
[ "$V1SZ" = "10" ] && ok "the kept version carries the outgoing size" || bad "version size=$V1SZ, expected 10"

note "version history: download one version, byte-exact and range-aware"
VBODY=$(curl -s -b "$JA" "$BASE/api/files/version/download?id=$VFILE&vid=$V1ID")
[ "$VBODY" = "AAAAAAAAAA" ] && ok "version download serves the old bytes" || bad "version body: [$VBODY]"
RC=$(curl -s -o "$ROOT/vr.out" -w '%{http_code}' -r 0-3 -b "$JA" \
  "$BASE/api/files/version/download?id=$VFILE&vid=$V1ID")
[ "$RC" = "206" ] && [ "$(cat "$ROOT/vr.out")" = "AAAA" ] \
  && ok "version download honours a byte range (206)" || bad "range on version: $RC [$(cat "$ROOT/vr.out")]"
CT=$(curl -s -o /dev/null -w '%{content_type}' -b "$JA" \
  "$BASE/api/files/version/download?id=$VFILE&vid=$V1ID")
echo "$CT" | grep -q "text/plain" && ok "version download keeps the mime type" || bad "content-type: $CT"
# An id that is not this file's version is simply not found.
RC=$(curl -s -o /dev/null -w '%{http_code}' -b "$JA" \
  "$BASE/api/files/version/download?id=$VFILE&vid=999999")
[ "$RC" = "404" ] && ok "foreign/unknown version id -> 404" || bad "expected 404, got $RC"

note "version history: restore exchanges the bytes, and is undoable"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -b "$JA" -H 'Content-Type: text/plain' \
  --data-binary "@$ROOT/src/v3.txt" "$BASE/api/files/content?id=$VFILE")
[ "$RC" = "200" ] && ok "second save -> 200" || bad "save v3 failed: $RC"
VL=$(req GET "/api/files/versions?id=$VFILE" "$JA")
NV=$(printf '%s' "$VL" | perl -MJSON::PP -0777 -e 'my $d=decode_json(do{local $/;<STDIN>}); print scalar @{$d->{versions}}')
[ "$NV" = "2" ] && ok "two saves keep two versions" || bad "expected 2 versions, got $NV: $VL"
PRE=$(curl -s -b "$JA" "$BASE/api/files/preview?id=$VFILE")
[ "$PRE" = "CCCCCCCCCCC" ] && ok "entry serves the newest bytes" || bad "entry content: [$PRE]"

# Restore the oldest version: the entry becomes AAAAA..., the outgoing
# CCCCCCCCCCC... pins as the newest version, and the restored row leaves the list.
RC=$(curl -s -o /dev/null -w '%{http_code}' -X POST -b "$JA" \
  "$BASE/api/files/version/restore?id=$VFILE&vid=$V1ID")
[ "$RC" = "200" ] && ok "restore -> 200" || bad "restore failed: $RC"
PRE=$(curl -s -b "$JA" "$BASE/api/files/preview?id=$VFILE")
[ "$PRE" = "AAAAAAAAAA" ] && ok "restore brings back the old bytes" || bad "restored content: [$PRE]"
VL=$(req GET "/api/files/versions?id=$VFILE" "$JA")
NSZ=$(jget "$VL" versions.0.size)
NV=$(printf '%s' "$VL" | perl -MJSON::PP -0777 -e 'my $d=decode_json(do{local $/;<STDIN>}); print scalar @{$d->{versions}}')
[ "$NV" = "2" ] && [ "$NSZ" = "11" ] \
  && ok "the outgoing content became the newest version (11 bytes)" \
  || bad "after restore: $NV versions, newest size $NSZ"
OLDID=$(jget "$VL" versions.1.id)
RC=$(curl -s -o /dev/null -w '%{http_code}' -X POST -b "$JA" \
  "$BASE/api/files/version/restore?id=$VFILE&vid=$OLDID")
[ "$RC" = "200" ] || bad "second restore failed: $RC"
PRE=$(curl -s -b "$JA" "$BASE/api/files/preview?id=$VFILE")
[ "$PRE" = "BBBBBBBBBB" ] && ok "restoring is itself undoable" || bad "undo content: [$PRE]"

note "version history: a READ grantee lists and downloads, but cannot change"
req POST /api/shares/batch "$JA" "{\"items\":[{\"file_id\":$VFILE}],\"username\":\"bob\",\"permissions\":1}" >/dev/null
VL=$(req GET "/api/files/versions?id=$VFILE" "$JB")
NV=$(printf '%s' "$VL" | perl -MJSON::PP -0777 -e 'my $d=decode_json(do{local $/;<STDIN>}); print scalar @{$d->{versions}}')
[ -n "$NV" ] && [ "$NV" -ge 1 ] && ok "a READ grantee sees the history" || bad "bob's history: $VL"
BVID=$(jget "$VL" versions.0.id)
VBODY=$(curl -s -b "$JB" "$BASE/api/files/version/download?id=$VFILE&vid=$BVID")
[ -n "$VBODY" ] && ok "a READ grantee downloads a version" || bad "bob's version download empty"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X POST -b "$JB" \
  "$BASE/api/files/version/restore?id=$VFILE&vid=$BVID")
[ "$RC" = "403" ] && ok "READ grantee restore -> 403 (needs UPDATE)" || bad "expected 403, got $RC"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -b "$JB" \
  "$BASE/api/files/version?id=$VFILE&vid=$BVID")
[ "$RC" = "403" ] && ok "READ grantee version delete -> 403" || bad "expected 403, got $RC"

note "version history: deleting a version deletes its bytes"
VKEY=$(sqlite3 "$DATA/fxcloud.db" "SELECT blob_created_at FROM file_versions WHERE id=$BVID;")
VPATH="$DATA/blobs/_versions/$VFILE/$VKEY"
[ -f "$VPATH" ] && ok "version blob lives under _versions/<file_id>/<key>" || bad "blob missing at $VPATH"
RC=$(reqcode DELETE "/api/files/version?id=$VFILE&vid=$BVID" "$JA")
[ "$RC" = "200" ] && ok "version delete -> 200" || bad "version delete: $RC"
VGONE=$(sqlite3 "$DATA/fxcloud.db" "SELECT COUNT(*) FROM file_versions WHERE id=$BVID;")
[ "$VGONE" = "0" ] && ok "the version row is gone" || bad "row still present"
[ ! -f "$VPATH" ] && ok "the version's bytes are gone from disk" || bad "blob still on disk: $VPATH"

note "version history: the first fill of an empty file keeps no history"
ZR=$(req POST /api/files/file "$JA" "{\"parent_id\":$VD,\"name\":\"zero.txt\"}")
ZID=$(jget "$ZR" entry.id)
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -b "$JA" -H 'Content-Type: text/plain' \
  --data-binary 'first fill' "$BASE/api/files/content?id=$ZID")
[ "$RC" = "200" ] || bad "first fill failed: $RC"
ZV=$(sqlite3 "$DATA/fxcloud.db" "SELECT COUNT(*) FROM file_versions WHERE file_id=$ZID;")
[ "$ZV" = "0" ] && ok "filling an empty file keeps no empty history" || bad "got $ZV versions for a first fill"

note "version history: the settings section stores and validates the bounds"
RC=$(reqcode PUT /api/me "$JA" '{"version_keep_n":5,"version_keep_days":30}')
[ "$RC" = "200" ] && ok "PUT /api/me with retention bounds -> 200" || bad "settings save: $RC"
ME=$(req GET /api/me "$JA")
[ "$(jget "$ME" version_keep_n)" = "5" ] && [ "$(jget "$ME" version_keep_days)" = "30" ] \
  && ok "the bounds round-trip through /api/me" || bad "me: $ME"
RC=$(reqcode PUT /api/me "$JA" '{"version_keep_n":-1}')
[ "$RC" = "400" ] && ok "a negative bound -> 400" || bad "expected 400, got $RC"
reqcode PUT /api/me "$JA" '{"version_keep_n":20,"version_keep_days":180}' >/dev/null

note "version history: keep_n prunes on insert, blobs included"
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET version_keep_n=1 WHERE username='alice';"
curl -s -o /dev/null -X PUT -b "$JA" -H 'Content-Type: text/plain' \
  --data-binary "@$ROOT/src/v1.txt" "$BASE/api/files/content?id=$VFILE"
curl -s -o /dev/null -X PUT -b "$JA" -H 'Content-Type: text/plain' \
  --data-binary "@$ROOT/src/v2.txt" "$BASE/api/files/content?id=$VFILE"
NV=$(sqlite3 "$DATA/fxcloud.db" "SELECT COUNT(*) FROM file_versions WHERE file_id=$VFILE;")
NB=$(ls "$DATA/blobs/_versions/$VFILE" | wc -l)
[ "$NV" = "1" ] && ok "keep_n=1 leaves exactly one version" || bad "expected 1 version row, got $NV"
[ "$NB" = "1" ] && ok "pruned versions are unlinked from disk too" || bad "$NB blobs on disk, expected 1"
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET version_keep_n=20 WHERE username='alice';"

note "phase4 migration: history=drop replaces content and history in one save"
printf 'plain bytes before the migration' > "$ROOT/src/mig.txt"
printf 'FXE1migrated-ciphertext' > "$ROOT/src/mig.enc"
MR=$(up "$JA" "" mig.txt)
MFILE=$(jget "$MR" entry.id)
[ -n "$MFILE" ] && ok "migration test file created" || bad "migration test file missing"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -b "$JA" -H 'Content-Type: text/plain' \
  --data-binary "@$ROOT/src/mig.txt" "$BASE/api/files/content?id=$MFILE")
[ "$RC" = "200" ] || bad "pre-migration save failed: $RC"
VL=$(req GET "/api/files/versions?id=$MFILE" "$JA")
NV=$(printf '%s' "$VL" | perl -MJSON::PP -0777 -e 'my $d=decode_json(do{local $/;<STDIN>}); print scalar @{$d->{versions}}')
OLDVID=$(jget "$VL" versions.0.id)
MVK=$(sqlite3 "$DATA/fxcloud.db" "SELECT blob_created_at FROM file_versions WHERE file_id=$MFILE LIMIT 1;")
MVKB="$DATA/blobs/_versions/$MFILE/$MVK"
[ "$NV" = "1" ] && [ -f "$MVKB" ] \
  && ok "the file carries one plaintext version on disk" \
  || bad "expected one version+blob, got NV=$NV blob=$MVKB"
MKEY=$(printf 'wrapped-file-key' | base64 -w0)
# the migration shape: FXE1 body + a key record + the history flag
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -b "$JA" -H 'Content-Type: application/octet-stream' \
  --data-binary "@$ROOT/src/mig.enc" \
  "$BASE/api/files/content?id=$MFILE&enc=1&key=$MKEY&history=drop")
[ "$RC" = "200" ] && ok "migration save (enc=1, history=drop) -> 200" || bad "migration save: $RC"
VL=$(req GET "/api/files/versions?id=$MFILE" "$JA")
NV=$(printf '%s' "$VL" | perl -MJSON::PP -0777 -e 'my $d=decode_json(do{local $/;<STDIN>}); print scalar @{$d->{versions}}')
[ "$NV" = "0" ] && ok "history=drop leaves no versions behind" || bad "expected 0 versions, got $NV: $VL"
ME=$(req GET "/api/files/info?id=$MFILE" "$JA")
[ "$(jget "$ME" entry.enc_version)" = "1" ] && ok "the row is encrypted now" || bad "info: $ME"
VB=$(sqlite3 "$DATA/fxcloud.db" "SELECT COUNT(*) FROM file_versions WHERE file_id=$MFILE;")
[ "$VB" = "0" ] && ok "the plaintext history row is gone from the db" || bad "$VB rows left"
[ ! -f "$MVKB" ] && ok "the plaintext bytes are unlinked from disk" || bad "blob still on disk: $MVKB"
RC=$(curl -s -o /dev/null -w '%{http_code}' -b "$JA" \
  "$BASE/api/files/version/download?id=$MFILE&vid=$OLDVID")
[ "$RC" = "404" ] && ok "the dropped version id answers 404" || bad "expected 404, got $RC"
# the flag only exists as part of an explicit promotion
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -b "$JA" -H 'Content-Type: text/plain' \
  --data-binary "@$ROOT/src/mig.txt" "$BASE/api/files/content?id=$MFILE&history=drop")
[ "$RC" = "400" ] && ok "history=drop without enc=1 -> 400" || bad "expected 400, got $RC"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -b "$JA" -H 'Content-Type: application/octet-stream' \
  --data-binary "@$ROOT/src/mig.enc" \
  "$BASE/api/files/content?id=$MFILE&enc=1&key=$MKEY&history=keep")
[ "$RC" = "400" ] && ok "an unknown history value -> 400" || bad "expected 400, got $RC"

note "phase4 zone: a folder flag the write paths read"
ZRESP=$(req POST /api/files/folder "$JA" '{"name":"vault-zone"}')
ZID=$(jget "$ZRESP" entry.id)
[ -n "$ZID" ] && ok "zone folder created" || bad "zone folder missing: $ZRESP"
RC=$(reqcode PUT /api/files/zone "$JA" "{\"id\":$ZID,\"flag\":1}")
[ "$RC" = "200" ] && ok "PUT /api/files/zone marks a folder" || bad "mark: $RC"
ME=$(req GET "/api/files/info?id=$ZID" "$JA")
[ "$(jget "$ME" entry.enc_zone)" = "1" ] && ok "the flag rides on the entry" || bad "info: $ME"
BC=$(req GET "/api/files/breadcrumb?id=$ZID" "$JA")
echo "$BC" | grep -q '"enc_zone":1' \
  && ok "the breadcrumb carries the flag (one request for the whole path)" \
  || bad "breadcrumb: $BC"
RC=$(reqcode PUT /api/files/zone "$JA" "{\"id\":$ZID,\"flag\":0}")
[ "$RC" = "200" ] && ok "unmark -> 200" || bad "unmark: $RC"
ME=$(req GET "/api/files/info?id=$ZID" "$JA")
[ "$(jget "$ME" entry.enc_zone)" = "0" ] && ok "the flag comes off" || bad "info: $ME"
# A file has no zone: only folders can demand the key.
printf 'zone target\n' > "$ROOT/src/zone.txt"
ZF=$(jget "$(up "$JA" "" zone.txt)" entry.id)
RC=$(reqcode PUT /api/files/zone "$JA" "{\"id\":$ZF,\"flag\":1}")
[ "$RC" = "400" ] && ok "a file has no zone -> 400" || bad "expected 400, got $RC"
# An UPDATE grantee may write, but may not change the folder's policy.
req POST /api/shares/batch "$JA" \
  "{\"items\":[{\"file_id\":$ZID}],\"username\":\"bob\",\"permissions\":3}" >/dev/null
RC=$(reqcode PUT /api/files/zone "$JB" "{\"id\":$ZID,\"flag\":1}")
[ "$RC" = "403" ] && ok "an UPDATE grantee cannot change the zone -> 403" || bad "expected 403, got $RC"

note "version history: quota sums live rows and version history"
ME=$(req GET /api/me "$JA")
USED=$(jget "$ME" used_bytes)
USED_DB=$(sqlite3 "$DATA/fxcloud.db" \
  "SELECT COALESCE((SELECT SUM(size) FROM files WHERE owner_id=1 AND is_dir=0),0)
        + COALESCE((SELECT SUM(v.size) FROM file_versions v JOIN files f ON f.id=v.file_id
                     WHERE f.owner_id=1 AND f.is_dir=0),0);")
[ -n "$USED" ] && [ "$USED" = "$USED_DB" ] \
  && ok "used_bytes includes the version history (api=$USED db=$USED_DB)" \
  || bad "usage mismatch (api=$USED db=$USED_DB)"

note "version history: the age bound runs in the sweep loop"
VROWS=$(sqlite3 "$DATA/fxcloud.db" "SELECT COUNT(*) FROM file_versions WHERE file_id=$VFILE;")
[ "$VROWS" -ge 1 ] && ok "history present for the age test" || bad "no versions left to age"
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET version_keep_days=1 WHERE username='alice';"
sqlite3 "$DATA/fxcloud.db" "UPDATE file_versions SET created_at='2000-01-01T00:00:00+00:00' WHERE file_id=$VFILE;"
GONE=""
for _ in $(seq 1 15); do
  C=$(sqlite3 "$DATA/fxcloud.db" "SELECT COUNT(*) FROM file_versions WHERE file_id=$VFILE;")
  [ "$C" = "0" ] && GONE=yes && break
  sleep 1
done
[ -n "$GONE" ] && ok "expired versions are swept on the trash-sweep cadence" || bad "age sweep did not drop the backdated rows"
NB=$(ls "$DATA/blobs/_versions/$VFILE" 2>/dev/null | wc -l)
[ "$NB" = "0" ] && ok "the sweep unlinked the expired blobs" || bad "$NB blobs survived the sweep"
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET version_keep_days=180 WHERE username='alice';"

note "version history: the trash keeps the history, the purge removes it"
curl -s -o /dev/null -X PUT -b "$JA" -H 'Content-Type: text/plain' \
  --data-binary "@$ROOT/src/v3.txt" "$BASE/api/files/content?id=$VFILE"
VKEYS=$(sqlite3 "$DATA/fxcloud.db" "SELECT blob_created_at FROM file_versions WHERE file_id=$VFILE;")
[ -n "$VKEYS" ] && ok "fresh history for the purge test" || bad "no versions to purge"
[ "$(reqcode POST /api/files/delete "$JA" "{\"id\":$VFILE}")" = "200" ] || bad "delete-to-trash failed"
VINT=$(sqlite3 "$DATA/fxcloud.db" "SELECT COUNT(*) FROM file_versions WHERE file_id=$VFILE;")
[ "$VINT" -ge 1 ] && ok "the trash keeps the file's history" || bad "history lost on trash"
for k in $VKEYS; do
  [ -f "$DATA/blobs/_versions/$VFILE/$k" ] || bad "version blob vanished on trash: $k"
done
ok "version blobs survive the delete-to-trash"
[ "$(reqcode POST /api/files/trash/purge "$JA" "{\"id\":$VFILE}")" = "200" ] || bad "purge failed"
VPOST=$(sqlite3 "$DATA/fxcloud.db" "SELECT COUNT(*) FROM file_versions WHERE file_id=$VFILE;")
[ "$VPOST" = "0" ] && ok "the purge removes the version rows" || bad "$VPOST rows survived the purge"
LEFT=0
for k in $VKEYS; do
  [ -f "$DATA/blobs/_versions/$VFILE/$k" ] && LEFT=$((LEFT+1))
done
[ "$LEFT" = "0" ] && ok "the purge removes the version blobs" || bad "$LEFT version blobs survived the purge"

note "version history: the i18n keys ship in all three dictionaries"
NVH=$(grep -c '"versions.history":' "$REPO/frontend/assets/i18n.js")
[ "$NVH" = "3" ] && ok "versions.history translated en/de/tlh" || bad "versions.history appears $NVH times, expected 3"
NSET=$(grep -c '"settings.versioning":' "$REPO/frontend/assets/i18n.js")
[ "$NSET" = "3" ] && ok "settings.versioning translated en/de/tlh" || bad "settings.versioning appears $NSET times, expected 3"

# ---- group folders (concepts/groups.md) ------------------------------------
# A group is a storage principal of its own (section 3): the creator staffs
# it, every member works one shared tree, the group pays the quota, and the
# folder keys travel from a manager to the members - never the other way
# round (section 5). carol joins as the second member; her activation goes
# through the same sqlite door the user-settings section used for dave.
note "group folders: admin CRUD, and the creator becomes the first manager"
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET is_active=1 WHERE username='carol';" >/dev/null
GC=$ROOT/carol.jar
req POST /api/login "$GC" '{"username":"carol","password":"correct-horse"}' >/dev/null
GLIST=$(req GET /api/admin/users "$JA")
ALICEID=$(afield "$GLIST" alice id)
BOBID=$(afield "$GLIST" bob id)
CAROLID=$(afield "$GLIST" carol id)
DAVEID=$(afield "$GLIST" dave id)

GRESP=$(req POST /api/admin/groups "$JA" '{"name":"Ops","quota_bytes":1048576}')
echo "$GRESP"
GID=$(jget "$GRESP" id)
NM=$(printf '%s' "$GRESP" | perl -MJSON::PP -0777 -ne 'print scalar @{decode_json($_)->{members}}')
[ -n "$GID" ] && [ "$(jget "$GRESP" created_by_name)" = "alice" ] && [ "$NM" = "1" ] \
  && [ "$(jget "$GRESP" members.0.role)" = "1" ] \
  && ok "create group: the creator is its first manager" || bad "group create: $GRESP"

[ "$(reqcode GET /api/admin/groups "$JB")" = "403" ] \
  && ok "group administration is admin-only (403 for bob)" || bad "bob reached /api/admin/groups"

[ "$(reqcode POST /api/admin/groups "$JA" '{"name":"ops","quota_bytes":1}')" = "409" ] \
  && ok "duplicate group names are refused (409, case-insensitive)" || bad "duplicate group name accepted"

note "group folders: members join, and see only their own groups"
[ "$(reqcode POST "/api/admin/groups/$GID/members" "$JA" '{"username":"bob","role":0}')" = "200" ] \
  && [ "$(reqcode POST "/api/admin/groups/$GID/members" "$JA" '{"username":"carol","role":0}')" = "200" ] \
  && ok "bob and carol join as members" || bad "adding members failed"
[ "$(reqcode POST "/api/admin/groups/$GID/members" "$JA" '{"username":"dave","role":7}')" = "400" ] \
  && ok "a role outside the table is refused (400)" || bad "bogus role accepted"

MV=$(req GET /api/groups "$JB")
echo "$MV"
[ "$(jget "$MV" 0.name)" = "Ops" ] && [ "$(jget "$MV" 0.role)" = "0" ] \
  && [ "$(jget "$MV" 0.quota_bytes)" = "1048576" ] \
  && ok "the member view lists the group with role and quota" || bad "member view: $MV"
NL=$(printf '%s' "$(req GET /api/groups "$JD")" | perl -MJSON::PP -0777 -ne 'print scalar @{decode_json($_)}')
[ "$NL" = "0" ] && ok "a non-member's group list is empty" || bad "non-member sees $NL groups"

note "group folders: the bootstrap creates the group's top-level folder"
BT=$(req POST /api/files/folder "$JB" "{\"parent_id\":null,\"group\":$GID,\"name\":\"OpsRoot\"}")
echo "$BT"
GROOT=$(jget "$BT" entry.id)
[ -n "$GROOT" ] && [ "$(jget "$BT" entry.owner_group_id)" = "$GID" ] \
  && [ "$(jget "$BT" entry.owner_id)" = "$BOBID" ] \
  && ok "bootstrap: the row bills the group, the creator stays the owner" \
  || bad "bootstrap: $BT"

[ "$(reqcode POST /api/files/folder "$GC" "{\"parent_id\":null,\"group\":$GID,\"name\":\"OpsRoot\"}")" = "409" ] \
  && ok "a second top-level folder of the same name is refused (409)" || bad "sibling duplicate accepted"

[ "$(field "$(req GET /api/files "$JB")" OpsRoot group_name)" = "Ops" ] \
  && ok "the root listing carries the group badge" || bad "no group badge in bob's root"
[ -n "$(idof "$(req GET /api/files "$GC")" OpsRoot)" ] \
  && ok "the other member sees the root entry" || bad "carol cannot see the group folder"
[ -z "$(idof "$(req GET /api/files "$JD")" OpsRoot)" ] \
  && ok "a non-member sees nothing of it" || bad "dave sees a group folder"

note "group folders: members work one tree, and cannot share it out"
NR=$(req POST /api/files/folder "$JB" "{\"parent_id\":$GROOT,\"name\":\"notes\"}")
NOTES=$(jget "$NR" entry.id)
up "$GC" "$NOTES" a.txt >/dev/null
[ -n "$(idof "$(req GET "/api/files?parent=$NOTES" "$JB")" a.txt)" ] \
  && ok "a member's upload lands in the shared subtree for everyone" \
  || bad "carol's upload is invisible to bob"

[ "$(reqcode POST /api/shares "$JB" "{\"file_id\":$GROOT,\"username\":\"dave\",\"permissions\":1}")" = "403" ] \
  && ok "a group folder cannot be shared out (403)" || bad "group folder was shareable"

[ "$(reqcode POST /api/files/rename "$GC" "{\"id\":$GROOT,\"name\":\"RenamedByCarol\"}")" = "200" ] \
  && [ "$(field "$(req GET /api/files "$JB")" RenamedByCarol group_name)" = "Ops" ] \
  && ok "members work the subtree normally (rename included)" || bad "member rename failed"
req POST /api/files/rename "$GC" "{\"id\":$GROOT,\"name\":\"OpsRoot\"}" >/dev/null

note "group folders: key distribution (pending list, wrap, manager gate)"
PEND=$(req GET "/api/groups/$GID/keys/pending" "$JA")
echo "$PEND"
# Every member without an envelope is one pair - and that includes the
# manager herself: alice holds no key for OpsRoot either (bob created it),
# so she is pending next to bob and carol.
NP=$(printf '%s' "$PEND" | perl -MJSON::PP -0777 -ne 'print scalar @{decode_json($_)}')
[ "$NP" = "3" ] && ok "the pending list starts with one pair per member" || bad "pending pairs: $NP"
[ "$(reqcode GET "/api/groups/$GID/keys/pending" "$JB")" = "403" ] \
  && ok "the pending list is manager-only (403 for a member)" || bad "member read the pending list"
[ "$(reqcode GET "/api/groups/$GID/keys/pending" "$JD")" = "404" ] \
  && ok "a non-member gets the listing's 404" || bad "dave read a pending list"

[ "$(reqcode POST "/api/groups/$GID/keys" "$JA" "{\"file_id\":$GROOT,\"user_id\":$BOBID,\"envelope\":\"R3JvdXBLZXkx\"}")" = "200" ] \
  && ok "the manager distributes an envelope (200)" || bad "distribution failed"
NP2=$(printf '%s' "$(req GET "/api/groups/$GID/keys/pending" "$JA")" | perl -MJSON::PP -0777 -ne 'print scalar @{decode_json($_)}')
[ "$NP2" = "2" ] && ok "the wrapped pair leaves the pending list" || bad "pending still shows $NP2 pairs"
[ "$(reqcode POST "/api/groups/$GID/keys" "$JA" "{\"file_id\":$GROOT,\"user_id\":$BOBID,\"envelope\":\"R3JvdXBLZXky\"}")" = "200" ] \
  && ok "re-distributing overwrites the envelope (200)" || bad "re-distribution failed"
EK=$(req GET /api/groups/keys "$JB")
NE=$(printf '%s' "$EK" | perl -MJSON::PP -0777 -ne 'print scalar @{decode_json($_)}')
[ "$NE" = "1" ] && [ "$(jget "$EK" 0.file_id)" = "$GROOT" ] \
  && [ "$(jget "$EK" 0.group_name)" = "Ops" ] && [ "$(jget "$EK" 0.envelope)" = "R3JvdXBLZXky" ] \
  && ok "the member's envelope cache holds exactly the latest record" || bad "envelope cache: $EK"
[ "$(reqcode POST "/api/groups/$GID/keys" "$GC" "{\"file_id\":$GROOT,\"user_id\":$CAROLID,\"envelope\":\"eA==\"}")" = "403" ] \
  && ok "only a manager hands out folder keys (403 for a member)" || bad "member distributed a key"
NC=$(printf '%s' "$(req GET /api/groups/keys "$GC")" | perl -MJSON::PP -0777 -ne 'print scalar @{decode_json($_)}')
[ "$NC" = "0" ] && ok "a member without an envelope receives no key material" || bad "carol got $NC envelopes"

note "group folders: the record-swap line (F5) holds inside a group"
[ "$(reqcode PUT /api/files/key "$JA" "{\"id\":$GROOT,\"key\":\"YWxpY2UtcmVjb3Jk\"}")" = "200" ] \
  && ok "the manager sets the folder's first record (200)" || bad "first record refused"
[ "$(reqcode PUT /api/files/key "$JB" "{\"id\":$GROOT,\"key\":\"Ym9iLXJlY29yZA==\"}")" = "403" ] \
  && ok "a member cannot swap a record that exists (403)" || bad "member swapped a record"
[ "$(reqcode PUT /api/files/key "$JA" "{\"id\":$GROOT,\"key\":\"YWxpY2UtdjI=\"}")" = "200" ] \
  && ok "the manager may swap it (200)" || bad "manager swap refused"

note "group folders: the group's quota bills the group, not the member"
sqlite3 "$DATA/fxcloud.db" "UPDATE groups SET quota_bytes=4 WHERE id=$GID;" >/dev/null
RC=$(curl -s -o /dev/null -w '%{http_code}' -b "$JB" -F "parent=$GROOT" -F "file=@$ROOT/src/b.txt" "$BASE/api/files/upload")
[ "$RC" = "507" ] && ok "upload beyond the group's budget is refused (507)" || bad "quota not enforced (rc=$RC)"
sqlite3 "$DATA/fxcloud.db" "UPDATE groups SET quota_bytes=1048576 WHERE id=$GID;" >/dev/null
USED=$(jget "$(req GET /api/groups "$JB")" 0.used_bytes)
[ -n "$USED" ] && [ "$USED" -ge 10 ] \
  && ok "the member view reports the group's consumption ($USED bytes)" || bad "used_bytes: $USED"

note "group folders: trash spans the members, removal cuts the access"
[ "$(reqcode POST /api/files/delete "$JB" "{\"id\":$NOTES}")" = "200" ] \
  && [ -n "$(idof "$(req GET /api/files/trash "$JA")" notes)" ] \
  && ok "a row trashed by one member shows up in the other's trash" || bad "cross-member trash failed"
[ "$(reqcode POST /api/files/trash/restore "$JA" "{\"id\":$NOTES}")" = "200" ] \
  && [ -n "$(idof "$(req GET "/api/files?parent=$GROOT" "$GC")" notes)" ] \
  && ok "the other member restores it (back in the group)" || bad "cross-member restore failed"

up "$JB" "" d.txt >/dev/null
PERF=$(idof "$(req GET /api/files "$JB")" d.txt)
[ "$(reqcode POST /api/files/move "$JB" "{\"id\":$PERF,\"dest_parent\":$GROOT}")" = "200" ] \
  && [ "$(field "$(req GET "/api/files?parent=$GROOT" "$JB")" d.txt owner_group_id)" = "$GID" ] \
  && ok "a personal file moved in bills the group from then on" || bad "move-in attribution"
[ "$(reqcode POST /api/files/move "$JB" "{\"id\":$PERF,\"dest_parent\":null}")" = "200" ] \
  && [ "$(field "$(req GET /api/files "$JB")" d.txt owner_group_id)" = "" ] \
  && ok "moved back out, the attribution is cleared" || bad "move-out attribution"

[ "$(reqcode DELETE "/api/admin/groups/$GID/members/$CAROLID" "$JA")" = "200" ] \
  && [ -z "$(idof "$(req GET /api/files "$GC")" OpsRoot)" ] \
  && ok "a removed member no longer sees the group's folders" || bad "removal did not cut access"
NC2=$(printf '%s' "$(req GET /api/groups/keys "$GC")" | perl -MJSON::PP -0777 -ne 'print scalar @{decode_json($_)}')
[ "$NC2" = "0" ] && ok "the removed member's envelopes went with the membership" \
  || bad "$NC2 envelopes outlived the membership"
[ "$(reqcode GET "/api/groups/$GID/keys/pending" "$GC")" = "404" ] \
  && ok "and so did their place in the group (404)" || bad "carol still reaches the group"

note "group folders: a group is deleted only once it is empty"
[ "$(reqcode DELETE "/api/admin/groups/$GID" "$JA")" = "409" ] \
  && ok "content still attributed to the group refuses the delete (409)" \
  || bad "delete with content went through"
[ "$(reqcode POST /api/files/delete "$JB" "{\"id\":$GROOT}")" = "200" ] \
  && [ "$(reqcode POST /api/files/trash/purge "$JB" "{\"id\":$GROOT}")" = "200" ] \
  && [ "$(reqcode DELETE "/api/admin/groups/$GID/members/$BOBID" "$JA")" = "200" ] \
  && [ "$(reqcode DELETE "/api/admin/groups/$GID/members/$ALICEID" "$JA")" = "200" ] \
  && [ "$(reqcode DELETE "/api/admin/groups/$GID" "$JA")" = "200" ] \
  && ok "emptied and unmembered, the group deletes cleanly" || bad "empty-group delete failed"

note "group folders: the i18n keys ship in all three dictionaries"
for GKEY in admin.groups group.newFolder group.distribute; do
  NGK=$(grep -c "\"$GKEY\":" "$REPO/frontend/assets/i18n.js")
  [ "$NGK" = "3" ] && ok "$GKEY translated en/de/tlh" || bad "$GKEY appears $NGK times, expected 3"
done

# ---- public links (concepts/public_links.md) ------------------------------
# A bearer-token share outside every session: mint, visit, download, drop a
# file in, take one out, revoke. The expiry model (rolling slides on use,
# fixed never moves, never has no deadline), the three presets, the
# plaintext-only rule, the subtree a token may reach, and the per-IP budgets
# that keep one leaked URL from turning into a load.
note "public links: minting hands out the token exactly once"

# The fixture: pub/ holds pl.txt and sub/ (holding deep.txt); outside.txt
# sits at alice's root, deliberately outside every link minted below.
PLR=$(req POST /api/files/folder "$JA" '{"name":"pub"}')
PUB=$(jget "$PLR" entry.id)
printf 'PUBLICDATA' > "$ROOT/src/pl.txt"
up "$JA" "$PUB" pl.txt >/dev/null
PSR=$(req POST /api/files/folder "$JA" "{\"name\":\"sub\",\"parent_id\":$PUB}")
PSUB=$(jget "$PSR" entry.id)
printf 'DEEPDATA!!' > "$ROOT/src/deep.txt"
up "$JA" "$PSUB" deep.txt >/dev/null
printf 'OUTSIDE!!!' > "$ROOT/src/outside.txt"
up "$JA" "" outside.txt >/dev/null
OUT=$(idof "$(req GET /api/files "$JA")" outside.txt)
PUBL=$(req GET "/api/files?parent=$PUB" "$JA")
PL=$(idof "$PUBL" pl.txt)
[ -n "$PUB" ] && [ -n "$PSUB" ] && [ -n "$PL" ] && [ -n "$OUT" ] \
  && ok "fixture: pub/ with pl.txt, sub/deep.txt and an outside file" \
  || bad "fixture failed (pub=$PUB sub=$PSUB pl=$PL out=$OUT)"

MINT=$(req POST /api/links "$JA" "{\"file_id\":$PUB,\"permissions\":1,\"label\":\"holiday photos\"}")
echo "$MINT"
TOKEN=$(jget "$MINT" token)
LID=$(jget "$MINT" link.id)
[ -n "$LID" ] && [ "${#TOKEN}" = "43" ] && echo "$TOKEN" | grep -Eq '^[A-Za-z0-9_-]{43}$' \
  && ok "the token is 43 base64url characters (256 random bits)" \
  || bad "mint: $MINT"
[ "$(jget "$MINT" url)" = "/s/$TOKEN" ] \
  && ok "the response pairs the token with its visitor URL" || bad "url: $(jget "$MINT" url)"
[ "$(jget "$MINT" link.permissions)" = "1" ] \
  && [ "$(jget "$MINT" link.expiry_mode)" = "rolling" ] \
  && [ "$(jget "$MINT" link.expires_in_days)" = "30" ] \
  && [ -n "$(jget "$MINT" link.expires_at)" ] \
  && ok "defaults: read preset, rolling, 30 days, a deadline" || bad "defaults: $MINT"
[ "$(jget "$MINT" link.download_count)" = "0" ] \
  && [ "$(jget "$MINT" link.label)" = "holiday photos" ] \
  && ok "a fresh link counts no downloads and keeps the label" || bad "record: $MINT"

# Only the sha256 ever touches the disk: the raw token exists in this one
# response and nowhere else, so a database dump yields no working link.
TH=$(sqlite3 "$DATA/fxcloud.db" "SELECT token_hash FROM public_links WHERE id=$LID;")
[ "$TH" = "$(printf '%s' "$TOKEN" | sha256sum | awk '{print $1}')" ] \
  && ok "the stored token_hash is sha256(token)" || bad "hash mismatch: $TH"
[ "$(sqlite3 "$DATA/fxcloud.db" "SELECT COUNT(*) FROM public_links WHERE instr(token_hash,'$TOKEN')>0;")" = "0" ] \
  && ok "the raw token appears nowhere in the database" || bad "raw token stored"

note "public links: the overview never carries a usable token"
OVER=$(req GET /api/links "$JA")
echo "$OVER" | grep -q "\"id\":$LID" && echo "$OVER" | grep -q '"label":"holiday photos"' \
  && ok "the overview lists the link with its label" || bad "overview: $OVER"
echo "$OVER" | grep -q '"token"' \
  && bad "the overview echoes a token" \
  || ok "the overview carries the record only, never a token"
[ "$(jget "$OVER" default_expiry_days)" = "30" ] \
  && ok "the overview advertises the default window" || bad "default_expiry_days: $OVER"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/links")" = "401" ] \
  && ok "the overview requires a session (401)" || bad "sessionless overview"

# A link on a single file, expiring never: the second source for the
# file_id filter below, and the token the revoke step will kill first.
FRESP=$(req POST /api/links "$JA" "{\"file_id\":$PL,\"permissions\":1,\"expiry_mode\":\"never\"}")
FTOKEN=$(jget "$FRESP" token)
FLID=$(jget "$FRESP" link.id)
[ -n "$FLID" ] && ok "a link may point at a single file" || bad "file link: $FRESP"
[ "$(jget "$FRESP" link.expiry_mode)" = "never" ] && [ -z "$(jget "$FRESP" link.expires_at)" ] \
  && ok "'never' stores no deadline at all" || bad "never: $FRESP"
FILT=$(req GET "/api/links?file_id=$PL" "$JA")
echo "$FILT" | grep -q "\"id\":$FLID" && ! echo "$FILT" | grep -q "\"id\":$LID" \
  && ok "file_id filters the overview to one source" || bad "filter: $FILT"

note "public links: what the server refuses"
[ "$(reqcode POST /api/links "$JA" "{\"file_id\":$PUB,\"permissions\":2}")" = "400" ] \
  && ok "a mask outside the presets is refused (400)" || bad "mask=2 accepted"
[ "$(reqcode POST /api/links "$JA" "{\"file_id\":$PUB,\"permissions\":31}")" = "400" ] \
  && ok "a mask carrying PERM_SHARE is refused (400)" || bad "mask=31 accepted"
[ "$(reqcode POST /api/links "$JA" "{\"file_id\":$PUB,\"permissions\":5}")" = "400" ] \
  && ok "read|create (5) is not a preset - only 1, 4 and 15 are" \
  || bad "mask=5 accepted"
[ "$(reqcode POST /api/links "$JA" "{\"file_id\":$PUB,\"permissions\":1,\"expiry_mode\":\"sometimes\"}")" = "400" ] \
  && ok "an unknown expiry_mode is refused (400)" || bad "expiry_mode accepted"
[ "$(reqcode POST /api/links "$JA" "{\"file_id\":$PUB,\"permissions\":1,\"expires_in_days\":0}")" = "400" ] \
  && [ "$(reqcode POST /api/links "$JA" "{\"file_id\":$PUB,\"permissions\":1,\"expires_in_days\":4000}")" = "400" ] \
  && ok "expires_in_days is bounded to 1..3650 (400 outside)" || bad "day bounds not enforced"
LONG=$(perl -e 'print "x" x 201')
[ "$(reqcode POST /api/links "$JA" "{\"file_id\":$PUB,\"permissions\":1,\"label\":\"$LONG\"}")" = "400" ] \
  && ok "a label over 200 characters is refused (400)" || bad "long label accepted"
[ "$(reqcode POST /api/links "$JB" "{\"file_id\":$PUB,\"permissions\":1}")" = "404" ] \
  && ok "minting on someone else's folder is a 404" || bad "bob minted a link"
RC=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -d "{\"file_id\":$PUB,\"permissions\":1}" "$BASE/api/links")
[ "$RC" = "401" ] && ok "minting without a session is a 401" || bad "sessionless mint: $RC"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/public/$(perl -e 'print "A" x 43')/meta")" = "404" ] \
  && ok "an unknown token answers 404" || bad "unknown token"

note "public links: the visitor page and its meta"
PVH="$ROOT/pv-h.txt"
curl -sD "$PVH" -o "$ROOT/pv-page.html" "$BASE/s/$TOKEN"
grep -qi '^referrer-policy: no-referrer' "$PVH" \
  && grep -qi '^cache-control: no-store' "$PVH" \
  && grep -qi '^x-robots-tag: noindex' "$PVH" \
  && ok "the visitor page carries no-referrer, no-store and noindex" \
  || bad "visitor headers: $(grep -iE 'referrer-policy|cache-control|x-robots-tag' "$PVH" | tr -d '\r' | tr '\n' ' ')"
grep -q 'data-i18n' "$ROOT/pv-page.html" \
  && ok "the embedded shell ships with its i18n marks" || bad "visitor.html lost its data-i18n marks"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/s/$(perl -e 'print "Z" x 43')")" = "200" ] \
  && ok "the shell answers 200 for any token - the API is where truth lives" \
  || bad "visitor shell for a garbage token"
META=$(curl -s "$BASE/api/public/$TOKEN/meta")
echo "$META" | grep -q "\"id\":$PUB" && echo "$META" | grep -q '"name":"pub"' \
  && echo "$META" | grep -q '"is_dir":true' \
  && ok "meta names the shared folder for the visitor" || bad "meta: $META"
echo "$META" | grep -q '"can_read":true' && echo "$META" | grep -q '"can_create":false' \
  && echo "$META" | grep -q '"can_delete":false' \
  && echo "$META" | grep -q '"permission_names":\["read"\]' \
  && ok "a read link may look and download, nothing else" || bad "permissions: $META"
echo "$META" | grep -q '"label":"holiday photos"' \
  && ok "the owner's label rides along for context" || bad "label: $META"

note "public links: the listing walks only the linked subtree"
LIST=$(curl -s "$BASE/api/public/$TOKEN/list?id=$PUB")
echo "$LIST" | grep -q "\"id\":$PUB" && echo "$LIST" | grep -q '"name":"pl.txt"' \
  && echo "$LIST" | grep -q '"name":"sub"' \
  && ok "the listing shows the folder's children" || bad "list: $LIST"
echo "$LIST" | grep -q '"name":"deep.txt"' \
  && bad "a grandchild leaks into its parent's listing" \
  || ok "children are listed one level at a time"
SUBL=$(curl -s "$BASE/api/public/$TOKEN/list?id=$PSUB")
echo "$SUBL" | grep -q '"name":"deep.txt"' \
  && ok "a subfolder inside the subtree is listable" || bad "sub list: $SUBL"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/public/$TOKEN/list?id=$PL")" = "400" ] \
  && ok "listing a file answers 400, not a crash" || bad "list file"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/public/$TOKEN/list?id=$OUT")" = "404" ] \
  && ok "ids outside the subtree answer 404" || bad "outside list"

note "public links: downloads are attachment-only and counted"
DLH="$ROOT/pv-dl.h"
RC=$(curl -sD "$DLH" -o "$ROOT/pv-dl.bin" -w '%{http_code}' "$BASE/api/public/$TOKEN/download?id=$PL")
[ "$RC" = "200" ] && [ "$(cat "$ROOT/pv-dl.bin")" = "PUBLICDATA" ] \
  && ok "the file's bytes come back intact" || bad "download rc=$RC"
grep -qi '^content-disposition: attachment' "$DLH" \
  && ok "downloads are attachments, never inline" \
  || bad "disposition: $(grep -i '^content-disposition' "$DLH" | tr -d '\r')"
grep -qi '^referrer-policy: no-referrer' "$DLH" && grep -qi '^cache-control: no-store' "$DLH" \
  && ok "visitor headers ride the download too" || bad "download headers"
[ "$(jget "$(req GET "/api/links?file_id=$PUB" "$JA")" links.0.download_count)" = "1" ] \
  && ok "a successful download is counted on the record" || bad "download_count not bumped"
# No byte ranges on the public surface (v1): a Range ask gets the whole file.
RC=$(curl -s -o "$ROOT/pv-r.bin" -w '%{http_code}' -H 'Range: bytes=0-3' \
  "$BASE/api/public/$TOKEN/download?id=$PL")
[ "$RC" = "200" ] && [ "$(wc -c < "$ROOT/pv-r.bin")" = "10" ] \
  && ok "a Range request is answered whole (200, not 206)" \
  || bad "range: rc=$RC size=$(wc -c < "$ROOT/pv-r.bin")"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/public/$TOKEN/download?id=$PUB")" = "400" ] \
  && ok "a folder is not downloadable (400)" || bad "folder download"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/public/$TOKEN/download?id=$OUT")" = "404" ] \
  && ok "bytes outside the subtree stay closed (404)" || bad "outside download"
[ "$(curl -s "$BASE/api/public/$FTOKEN/download?id=$PL")" = "PUBLICDATA" ] \
  && ok "the file link serves its file directly" || bad "file link download"

note "public links: a rolling deadline slides on use, never backwards"
# Push the deadline close to now: the next visit must restore the full
# window - that is what "rolling" means.
sqlite3 "$DATA/fxcloud.db" "UPDATE public_links SET expires_at='$(perl -e 'my @t=gmtime(time()+7200); printf "%04d-%02d-%02dT%02d:%02d:%02d+00:00",$t[5]+1900,$t[4]+1,$t[3],$t[2],$t[1],$t[0]')' WHERE id=$LID;" >/dev/null
OLDX=$(sqlite3 "$DATA/fxcloud.db" "SELECT julianday(expires_at) FROM public_links WHERE id=$LID;")
curl -s -o /dev/null "$BASE/api/public/$TOKEN/meta"
NEWX=$(sqlite3 "$DATA/fxcloud.db" "SELECT julianday(expires_at) FROM public_links WHERE id=$LID;")
awk -v a="$OLDX" -v b="$NEWX" 'BEGIN{exit !(b-a>28)}' \
  && ok "a visit slides a rolling deadline a full window forward" \
  || bad "slide: $OLDX -> $NEWX"

# The owner's own operations never touch a link - only visitor calls do.
NEV=$(req POST /api/links "$JA" "{\"file_id\":$PUB,\"permissions\":1,\"expiry_mode\":\"never\",\"label\":\"permanent\"}")
NTOKEN=$(jget "$NEV" token)
NLID=$(jget "$NEV" link.id)
[ -n "$NLID" ] && [ -n "$NTOKEN" ] || bad "never link mint failed: $NEV"
OEX=$(sqlite3 "$DATA/fxcloud.db" "SELECT IFNULL(expires_at,'')||'|'||IFNULL(last_access_at,'') FROM public_links WHERE id=$LID;")
req GET /api/links "$JA" >/dev/null
req GET "/api/links?file_id=$PUB" "$JA" >/dev/null
NEX=$(sqlite3 "$DATA/fxcloud.db" "SELECT IFNULL(expires_at,'')||'|'||IFNULL(last_access_at,'') FROM public_links WHERE id=$LID;")
[ -n "$OEX" ] && [ "$OEX" = "$NEX" ] \
  && ok "owner operations never touch a link's deadline or access time" \
  || bad "owner touch: $OEX -> $NEX"

note "public links: expiry answers 410, the sweep turns it into 404"
# The sweep runs every 2 seconds in this suite and would delete the very
# row the 410 check is about; park it (3600s) for the lazy-answer checks,
# then restart with the normal cadence to prove the deletion itself.
kill "$(cat "$ROOT/server.pid")" 2>/dev/null
wait 2>/dev/null
FXCLOUD_DATA="$DATA" FXCLOUD_PORT=$PORT FXCLOUD_TRASH_DAYS=30 FXCLOUD_TRASH_SWEEP_SECS=3600 \
  "$BIN" >>"$ROOT/server.log" 2>&1 &
echo $! > "$ROOT/server.pid"
for _ in $(seq 1 100); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/me")" != "000" ] && break
  sleep 0.2
done
sqlite3 "$DATA/fxcloud.db" \
  "UPDATE public_links SET expires_at='2020-01-01T00:00:00+00:00' WHERE id=$LID;" >/dev/null
RC=$(curl -s -o "$ROOT/pv-gone.json" -w '%{http_code}' "$BASE/api/public/$TOKEN/meta")
[ "$RC" = "410" ] && grep -q '"code":"gone"' "$ROOT/pv-gone.json" \
  && ok "an expired link answers 410 Gone with its own code" \
  || bad "expired: rc=$RC body=$(cat "$ROOT/pv-gone.json")"
[ "$(sqlite3 "$DATA/fxcloud.db" "SELECT expires_at FROM public_links WHERE id=$LID;")" = "2020-01-01T00:00:00+00:00" ] \
  && ok "the dead link was never reanimated by the visit" || bad "touch revived it"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/public/$TOKEN/meta")" = "410" ] \
  && ok "still 410 on the second visit" || bad "second visit"
restart_server || { bad "server did not restart for the sweep"; exit 1; }
GONE=""
for _ in 1 2 3 4 5 6 7 8; do
  sleep 1
  [ "$(sqlite3 "$DATA/fxcloud.db" "SELECT COUNT(*) FROM public_links WHERE id=$LID;")" = "0" ] && { GONE=1; break; }
done
[ -n "$GONE" ] && ok "the sweep removes the expired row" || bad "expired row survived the sweep"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/public/$TOKEN/meta")" = "404" ] \
  && ok "once swept, the same token answers 404 (not 410)" || bad "post-sweep answer"
[ "$(sqlite3 "$DATA/fxcloud.db" "SELECT COUNT(*) FROM public_links WHERE id=$NLID;")" = "1" ] \
  && ok "a 'never' link outlives the sweep (NULL is not expired)" || bad "never link swept"
[ -z "$(jget "$(curl -s "$BASE/api/public/$NTOKEN/meta")" expires_at)" ] \
  && ok "its meta reports no deadline either" || bad "never meta"

note "public links: a fixed deadline never moves"
FIX=$(req POST /api/links "$JA" "{\"file_id\":$PUB,\"permissions\":1,\"expiry_mode\":\"fixed\",\"expires_in_days\":2,\"label\":\"conference\"}")
FIXT=$(jget "$FIX" token)
FIXID=$(jget "$FIX" link.id)
[ "$(jget "$FIX" link.expiry_mode)" = "fixed" ] && [ "$(jget "$FIX" link.expires_in_days)" = "2" ] \
  && ok "a fixed link records its mode and lifetime" || bad "fixed: $FIX"
FDIFF=$(sqlite3 "$DATA/fxcloud.db" \
  "SELECT CAST(ROUND((julianday(expires_at)-julianday(created_at))*86400) AS INTEGER) FROM public_links WHERE id=$FIXID;")
awk -v d="$FDIFF" 'BEGIN{exit !(d>=172799 && d<=172801)}' \
  && ok "its deadline is exactly the lifetime away from creation" \
  || bad "fixed lifetime: $FDIFF seconds"
FBEFORE=$(sqlite3 "$DATA/fxcloud.db" "SELECT expires_at FROM public_links WHERE id=$FIXID;")
curl -s -o /dev/null "$BASE/api/public/$FIXT/meta"
FAFTER=$(sqlite3 "$DATA/fxcloud.db" "SELECT expires_at FROM public_links WHERE id=$FIXID;")
[ "$FBEFORE" = "$FAFTER" ] && ok "a visit leaves a fixed deadline byte-identical" \
  || bad "fixed slid: $FBEFORE -> $FAFTER"

note "public links: the three presets and what each one may do"
ADD=$(req POST /api/links "$JA" "{\"file_id\":$PUB,\"permissions\":4,\"label\":\"drop box\"}")
ADDT=$(jget "$ADD" token)
AMETA=$(curl -s "$BASE/api/public/$ADDT/meta")
echo "$AMETA" | grep -q '"can_read":false' && echo "$AMETA" | grep -q '"can_create":true' \
  && echo "$AMETA" | grep -q '"can_delete":false' \
  && ok "the add preset may write but not look around" || bad "add meta: $AMETA"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/public/$ADDT/list?id=$PUB")" = "403" ] \
  && ok "an add-only visitor cannot list (403)" || bad "add list"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/public/$ADDT/download?id=$PL")" = "403" ] \
  && ok "an add-only visitor cannot download (403)" || bad "add download"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$BASE/api/public/$ADDT/entry?id=$PL")" = "403" ] \
  && ok "an add-only visitor cannot delete (403)" || bad "add delete"

printf 'FROMVISITOR' > "$ROOT/src/vis.txt"
RC=$(curl -s -o "$ROOT/pv-up.json" -w '%{http_code}' -F "file=@$ROOT/src/vis.txt" \
  "$BASE/api/public/$ADDT/upload")
[ "$RC" = "200" ] && grep -q '"ok":true' "$ROOT/pv-up.json" \
  && ok "an add-only visitor may drop a file in (200)" \
  || bad "upload: rc=$RC $(cat "$ROOT/pv-up.json")"
VID=$(idof "$(req GET "/api/files?parent=$PUB" "$JA")" vis.txt)
[ -n "$VID" ] && [ "$(curl -s -b "$JA" "$BASE/api/files/download?id=$VID")" = "FROMVISITOR" ] \
  && ok "the drop lands in the owner's folder with its bytes intact" \
  || bad "owner cannot fetch the upload (vid=$VID)"
[ "$(curl -s -o /dev/null -w '%{http_code}' -F "parent=$PSUB" -F "file=@$ROOT/src/vis.txt" \
  "$BASE/api/public/$ADDT/upload")" = "403" ] \
  && ok "an add-only visitor cannot aim its upload deeper (403)" \
  || bad "pinned upload"

FULL=$(req POST /api/links "$JA" "{\"file_id\":$PUB,\"permissions\":15,\"label\":\"full\"}")
FULLT=$(jget "$FULL" token)
FMETA=$(curl -s "$BASE/api/public/$FULLT/meta")
echo "$FMETA" | grep -q '"can_read":true' && echo "$FMETA" | grep -q '"can_create":true' \
  && echo "$FMETA" | grep -q '"can_delete":true' \
  && ok "the full preset may read, write and delete" || bad "full meta: $FMETA"
[ "$(curl -s -o /dev/null -w '%{http_code}' -F "parent=$PSUB" -F "file=@$ROOT/src/vis.txt" \
  "$BASE/api/public/$FULLT/upload")" = "200" ] \
  && ok "a full visitor may upload into a subfolder" || bad "deep upload"
# Containment hands back the row that was asked for: a file id as the
# destination is a file, never the shared folder behind it.
[ "$(curl -s -o /dev/null -w '%{http_code}' -F "parent=$PL" -F "file=@$ROOT/src/vis.txt" \
  "$BASE/api/public/$FULLT/upload")" = "400" ] \
  && ok "an upload aimed at a file id is refused (400)" || bad "file-parent upload"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$BASE/api/public/$FULLT/entry?id=$VID")" = "200" ] \
  && ok "a full visitor may delete (200)" || bad "full delete"
echo "$(req GET /api/files/trash "$JA")" | grep -q '"name":"vis.txt"' \
  && ok "the deleted file lands in the owner's trash, not in limbo" \
  || bad "owner trash lacks vis.txt"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$BASE/api/public/$FULLT/entry?id=$PUB")" = "400" ] \
  && ok "the shared folder itself cannot be trashed through its own link (400)" \
  || bad "root delete"

note "public links: plaintext only (public_links.md section 5)"
printf 'CIPHERTEXT!' > "$ROOT/src/cipher.txt"
RC=$(curl -s -o "$ROOT/pv-enc.json" -w '%{http_code}' -b "$JA" \
  -F "parent=$PUB" -F "enc_version=1" -F "enc_key=R3JvdXBLZXkx" \
  -F "file=@$ROOT/src/cipher.txt" "$BASE/api/files/upload")
CIPHER=$(idof "$(req GET "/api/files?parent=$PUB" "$JA")" cipher.txt)
[ "$RC" = "200" ] && [ -n "$CIPHER" ] \
  && [ "$(field "$(req GET "/api/files?parent=$PUB" "$JA")" cipher.txt enc_version)" = "1" ] \
  && ok "an encrypted row joins the folder (real enc_version=1)" \
  || bad "encrypted upload: rc=$RC id=$CIPHER"
[ "$(reqcode POST /api/links "$JA" "{\"file_id\":$CIPHER,\"permissions\":1}")" = "409" ] \
  && ok "an encrypted source refuses a link (409)" || bad "encrypted mint"
FLIST=$(curl -s "$BASE/api/public/$FULLT/list?id=$PUB")
echo "$FLIST" | grep -q '"name":"pl.txt"' && ! echo "$FLIST" | grep -q '"name":"cipher.txt"' \
  && ok "the encrypted child never appears in a public listing" \
  || bad "listing leaked: $FLIST"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/public/$FULLT/download?id=$CIPHER")" = "404" ] \
  && ok "an encrypted child answers 404, not 403 (existence stays secret)" \
  || bad "encrypted download"

note "public links: a group folder cannot back one (403)"
G2=$(req POST /api/admin/groups "$JA" '{"name":"LinkGuard","quota_bytes":1048576}')
G2ID=$(jget "$G2" id)
[ -n "$G2ID" ] && [ "$(reqcode POST "/api/admin/groups/$G2ID/members" "$JA" '{"username":"bob","role":0}')" = "200" ] \
  || bad "guard group setup: $G2"
G2R=$(req POST /api/files/folder "$JB" "{\"parent_id\":null,\"group\":$G2ID,\"name\":\"GuardRoot\"}")
G2ROOT=$(jget "$G2R" entry.id)
[ "$(reqcode POST /api/links "$JB" "{\"file_id\":$G2ROOT,\"permissions\":1}")" = "403" ] \
  && ok "a group folder refuses a public link (403)" || bad "group mint: $G2R"
# Leave no trace: the group goes away the way the section above removed it.
[ "$(reqcode POST /api/files/delete "$JB" "{\"id\":$G2ROOT}")" = "200" ] \
  && [ "$(reqcode POST /api/files/trash/purge "$JB" "{\"id\":$G2ROOT}")" = "200" ] \
  && [ "$(reqcode DELETE "/api/admin/groups/$G2ID/members/$BOBID" "$JA")" = "200" ] \
  && [ "$(reqcode DELETE "/api/admin/groups/$G2ID/members/$ALICEID" "$JA")" = "200" ] \
  && [ "$(reqcode DELETE "/api/admin/groups/$G2ID" "$JA")" = "200" ] \
  && ok "the guard group deletes cleanly again" || bad "group cleanup"

note "public links: revocation is owner-only and immediate"
[ "$(reqcode DELETE "/api/links/$FLID" "$JB")" = "404" ] \
  && ok "another account cannot revoke it (404)" || bad "bob revoked"
[ "$(reqcode DELETE "/api/links/$FLID" "$JA")" = "200" ] \
  && ok "the owner revokes their link (200)" || bad "alice revoke"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/public/$FTOKEN/meta")" = "404" ] \
  && ok "the revoked token is dead immediately" || bad "revoked token still live"
[ -z "$(jget "$(req GET "/api/links?file_id=$PL" "$JA")" links.0.id)" ] \
  && ok "the overview no longer lists it" || bad "revoked link still listed"

note "public links: the per-IP budgets (public_links.md section 8.3)"
# The budgets live in memory (state.rs), so a restart starts an empty
# ledger: exactly 20 unknown tokens fit into one window, and the 21st
# request is refused *before* the lookup - even carrying a valid token.
restart_server || { bad "server did not restart before the budget test"; exit 1; }
GHOST=$(perl -e 'print "A" x 43')
i=0
RC=000
while [ "$i" -lt 20 ]; do
  RC=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/public/$GHOST/meta")
  i=$((i + 1))
done
[ "$RC" = "404" ] && ok "20 unknown tokens each answer 404 inside the budget" \
  || bad "budget run ended with rc=$RC"
RC=$(curl -sD "$ROOT/pv-429.h" -o "$ROOT/pv-429.json" -w '%{http_code}' \
  "$BASE/api/public/$NTOKEN/meta")
[ "$RC" = "429" ] && grep -qi '^retry-after:' "$ROOT/pv-429.h" \
  && ok "the 21st request is refused with 429 + Retry-After, even on a live link" \
  || bad "gate: rc=$RC $(cat "$ROOT/pv-429.json")"
grep -q '"code":"rate_limited"' "$ROOT/pv-429.json" \
  && ok "the refusal carries the machine-readable code" \
  || bad "429 body: $(cat "$ROOT/pv-429.json")"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/public/$NTOKEN/meta")" = "429" ] \
  && ok "the budget does not refill within its window" || bad "budget refilled"
restart_server || { bad "server did not restart after the budget test"; exit 1; }
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/public/$NTOKEN/meta")" = "200" ] \
  && ok "a restart clears the counters (memory-only, like the auth limiter)" \
  || bad "still blocked after a restart"

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

note "the same line on the key door: only the owner replaces a record that exists (F5)"
# PUT /api/files/key asks the question /files/content asks of its key
# field, and now answers it the same way. A folder shared with
# READ|UPDATE (3) - the mask a collaborative subtree carries - may
# still be given its FIRST record by the grantee: that is the first
# encrypted write below it, nothing is keyed under a record yet, so
# there is nothing a swapped-in key could orphan.
F5F=$(jget "$(req POST /api/files/folder "$JA" '{"name":"f5key"}')" entry.id)
req POST /api/shares "$JA" "{\"file_id\":$F5F,\"username\":\"bob\",\"permissions\":3}" >/dev/null
F5A=$(printf 'aaaaaaaa-f5-first-record-aaaaaaaaaaaa' | base64 | tr -d '\n')
RC=$(reqsave PUT /api/files/key "$JB" "$ROOT/k.json" "{\"id\":$F5F,\"key\":\"$F5A\"}")
[ "$RC" = "200" ] \
  && ok "an update-grantee may still give a folder with no record its first one" \
  || bad "first record: $RC $(cat "$ROOT/k.json")"
# Replacing it is the owner's move alone. The wrapper is opaque - the
# server holds no key - so it cannot tell the owner's re-binding after a
# move from a grantee handing themselves the row for good; the audit
# called the second one the one real abuse path in the share model, and
# the only answer to an unverifiable wrapper is a narrower door.
F5B=$(printf 'bbbbbbbb-f5-swapped-record-bbbbbbbbbbbb' | base64 | tr -d '\n')
RC=$(reqsave PUT /api/files/key "$JB" "$ROOT/k.json" "{\"id\":$F5F,\"key\":\"$F5B\"}")
[ "$RC" = "403" ] && grep -q "only the row's owner may change its key record" "$ROOT/k.json" \
  && ok "the same grantee replacing that record -> 403 naming the line" \
  || bad "record replace: $RC $(cat "$ROOT/k.json")"
F5I=$(req GET "/api/files/info?id=$F5F" "$JB")
[ "$(jget "$F5I" entry.enc_key)" = "$F5A" ] \
  && ok "the refused replacement left the stored record alone" \
  || bad "record after refusal: $F5I"
RC=$(reqsave PUT /api/files/key "$JA" "$ROOT/k.json" "{\"id\":$F5F,\"key\":\"$F5B\"}")
[ "$RC" = "200" ] && [ "$(jget "$(cat "$ROOT/k.json")" entry.enc_key)" = "$F5B" ] \
  && ok "the owner replaces a record that exists without asking anyone" \
  || bad "owner replace: $RC $(cat "$ROOT/k.json")"

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
# The switcher is a dropdown, not a row of flags: one current-flag button
# opens a menu with every language, however many CODES grows.
grep -q 'className = "lang-current"' "$I18N_JS" \
  && ok "the switcher opens as a dropdown (one current-flag button)" \
  || bad "no current-flag button is drawn"
grep -q 'className = "lang-menu"' "$I18N_JS" \
  && ok "every language lives in the dropdown menu" \
  || bad "no dropdown menu is drawn"
grep -q 'aria-haspopup' "$I18N_JS" \
  && ok "the dropdown button announces the popup" \
  || bad "the dropdown button lacks aria-haspopup"
grep -q 'Escape' "$I18N_JS" \
  && ok "the dropdown closes on Escape" \
  || bad "the dropdown cannot be closed with the keyboard"
# The topbar host: the menu opens inside the blue topbar DOM-wise, so
# the unprefixed .lang-btn lost to `.topbar button` (higher specificity)
# and the language names were painted white onto the menu's white panel
# - white-on-white in the light theme, invisible. The .topbar prefix is
# the fix (the same remedy .user-dropdown got, same comment above it);
# pin the block so it cannot be "simplified" back into the bug, and pin
# the restated hover/active the prefix otherwise silently kills.
TOPBAR_LANG=$(sed -n '/^\.topbar \.lang-btn {/,/^}/p' "$REPO/frontend/assets/style.css" | grep -c 'color: var(--text)')
[ "$TOPBAR_LANG" = "1" ] \
  && ok "the topbar language menu reads with the theme's text color" \
  || bad "the topbar language menu is white-on-white again ($TOPBAR_LANG)"
TOPBAR_LANG_HOV=$(grep -c '^\.topbar \.lang-btn:hover\|^\.topbar \.lang-btn\.active' "$REPO/frontend/assets/style.css")
[ "$TOPBAR_LANG_HOV" = "2" ] \
  && ok "the topbar language rows keep their hover and active states" \
  || bad "topbar language row states appear $TOPBAR_LANG_HOV times, want 2"
# A fake DOM: render the dropdown, count its parts, switch to Klingon,
# and read the redrawn trigger - the structure a browser would get.
if "$NODE" -e '
  function fake(tag) {
    return {
      tag: tag, children: [], attrs: {}, className: "", hidden: false,
      innerHTML: "", title: "", type: "", firstChild: null,
      appendChild: function (c) { this.children.push(c); this.firstChild = this.children[0]; return c; },
      removeChild: function (c) {
        this.children = this.children.filter(function (x) { return x !== c; });
        this.firstChild = this.children[0] || null;
        return c;
      },
      setAttribute: function (k, v) { this.attrs[k] = String(v); },
      getAttribute: function (k) { return k in this.attrs ? this.attrs[k] : null; },
      addEventListener: function () {},
      focus: function () {},
      contains: function () { return false; },
      querySelector: function (sel) {
        var name = sel.slice(1);
        var walk = function (n) {
          for (var i = 0; i < n.children.length; i++) {
            var c = n.children[i];
            if ((" " + c.className + " ").indexOf(" " + name + " ") >= 0) return c;
            var f = walk(c);
            if (f) return f;
          }
          return null;
        };
        return walk(this);
      },
    };
  }
  var boxes = [fake("div"), fake("div"), fake("div")];
  globalThis.document = {
    readyState: "complete",
    documentElement: {},
    querySelectorAll: function (sel) {
      return sel === ".lang-switch" ? boxes : [];
    },
    createElement: function (tag) { return fake(tag); },
    addEventListener: function () {},
    dispatchEvent: function () {},
  };
  globalThis.window = globalThis;
  require(process.argv[1]);
  var I = globalThis.I18N;
  var ok = true;
  var fail = function (msg) { console.error(msg); ok = false; };
  var box = boxes[0];
  if (box.children.length !== 2) fail("expected trigger + menu, got " + box.children.length);
  var trigger = box.children[0];
  var menu = box.children[1];
  if (trigger.className !== "lang-current") fail("no current-flag button on top");
  if (trigger.getAttribute("aria-haspopup") !== "true") fail("trigger lacks aria-haspopup");
  if (trigger.getAttribute("aria-expanded") !== "false") fail("trigger starts announced-open");
  if (!menu.hidden) fail("the menu starts open");
  if (menu.children.length !== 3) fail("menu lists " + menu.children.length + " languages");
  if (menu.children[0].getAttribute("data-lang") !== "de") fail("menu does not start with German");
  if (menu.children[1].className.indexOf("active") < 0) fail("English is not marked active");
  I.setLang("tlh");
  trigger = box.children[0];
  menu = box.children[1];
  if (trigger.innerHTML.indexOf("rotate(240") < 0) fail("switching to Klingon does not redraw the trigger flag");
  if (menu.children[2].className.indexOf("active") < 0) fail("Klingon is not marked active after the switch");
  if (trigger.getAttribute("aria-expanded") !== "false") fail("a switch leaves the trigger announced-open");
  I.setLang("en");
  process.exit(ok ? 0 : 1);
' "$I18N_JS"; then
  ok "the flag switcher is a dropdown: current flag opens a list of all languages"
else
  bad "the language dropdown is not built as expected"
fi
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
  for (const f of ["app", "fxenc", "login", "visitor"]) {
    const src = fs.readFileSync(process.argv[2] + "/assets/" + f + ".js", "utf8");
    for (const m of src.matchAll(/\bt\("([a-z][a-zA-Z0-9_.]*)"\)/g)) {
      if (!have(m[1])) {
        console.error(f + ".js uses an unknown key: " + m[1]);
        bad = 1;
      }
    }
  }
  for (const h of ["index.html", "login.html", "visitor.html"]) {
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
SAVE_GUARD=$(printf '%s\n' "$SAVE_BODY" | grep -n 'if (editorEntry !== entry) return true;' | cut -d: -f1 | head -1)
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

# ---- gallery arrows (lightbox navigation) ----
# The lightbox walks the listing on screen: previewable rows in display
# order, arrows at both ends, click or arrow key, one dirty-guard away from
# unsaved text.
note "gallery arrows walk the listing inside the lightbox"
IDX=$REPO/frontend/index.html
CSS=$REPO/frontend/assets/style.css
grep -q 'id="preview-prev-btn"' "$IDX" && grep -q 'id="preview-next-btn"' "$IDX" \
  && ok "the lightbox carries prev/next buttons" \
  || bad "index.html lacks the gallery arrow buttons"
grep -q 'getElementById("preview-prev-btn").addEventListener("click"' "$UI" \
  && ok "the left arrow steps the gallery on click" \
  || bad "the prev button has no click handler"
grep -q 'getElementById("preview-next-btn").addEventListener("click"' "$UI" \
  && ok "the right arrow steps the gallery on click" \
  || bad "the next button has no click handler"
grep -q 'function buildGallery' "$UI" && grep -q 'currentEntries\.filter' "$UI" \
  && ok "the gallery is the listing on screen, in display order" \
  || bad "app.js does not build the gallery from currentEntries"
grep -q 'function stepPreview' "$UI" && grep -q 'await confirmUnsaved()' "$UI" \
  && ok "stepping away from a dirty editor asks first (same rule as Close)" \
  || bad "stepPreview has no unsaved-changes gate"
grep -q 'e\.key === "ArrowLeft"' "$UI" && grep -q 'e\.key === "ArrowRight"' "$UI" \
  && ok "arrow keys walk the gallery next to the buttons" \
  || bad "no ArrowLeft/ArrowRight handling for the lightbox"
grep -q 'el\.tagName === "INPUT" || el\.tagName === "TEXTAREA" || el\.isContentEditable' "$UI" \
  && ok "arrows never fire while the caret sits in the editor" \
  || bad "the arrow handler does not spare text inputs"
NAVL=$(grep -c '"preview\.\(prev\|next\)"' "$REPO/frontend/assets/i18n.js")
[ "$NAVL" = "6" ] && ok "both arrow labels exist in all three dictionaries" \
  || bad "preview.prev/next appear $NAVL times in i18n.js, expected 6"
grep -q 'buildGallery(previewEntry)' "$UI" \
  && ok "a language switch restamps the arrow labels" \
  || bad "the arrow labels stay in the old language"
grep -q '^\.preview-nav {' "$CSS" && grep -q '\.preview-nav\[hidden\]' "$CSS" \
  && ok "the arrows are styled and honour the hidden attribute" \
  || bad "style.css lacks the .preview-nav block"

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
# The admin dialog took the settings dialog's nav-plus-panes shape in
# v0.1.6: a few accounts *and* groups stacked past the viewport and the
# close button slipped below the fold.
grep -q 'data-admin-tab' "$IDX" \
  && grep -q 'data-admin-panel' "$IDX" \
  && ok "the admin dialog is a nav plus panes, not one long column" \
  || bad "the admin dialog has no tab structure"
grep -q 'activateAdminTab' "$UI" \
  && grep -q 'activateAdminTab("users")' "$UI" \
  && ok "the admin nav switches panes and the dialog reopens on Users" \
  || bad "the admin nav is not wired in app.js"
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

# A refused origin is a deployment misconfiguration - it must be visible
# in the journal, with the knob that fixes it and the headers in play.
# The log carries ANSI colors, so strip them before reading the line.
grep -q 'FXCLOUD_ORIGIN' "$ROOT/server.log" \
  && ok "the refused origin is journaled with the FXCLOUD_ORIGIN hint" \
  || bad "the journal says nothing about the refused origin"
WARNLINE=$(perl -pe 's/\e\[[0-9;]*m//g' "$ROOT/server.log" | grep 'refused: the browser' | tail -n 1)
case "$WARNLINE" in
  *browser_origin=https://evil.example*derived_origin=*fxcloud_origin_set=false*)
    ok "the journal carries the debugging fields (origins, knob state)" ;;
  *) bad "the origin warning lacks its debugging fields: $WARNLINE" ;;
esac
grep -q 'fxcloud_origin_set' "$REPO/src/webauthn.rs" \
  && ok "origin refusals log every knob that matters" \
  || bad "webauthn.rs does not journal the refusal context"
grep -q 'challenge unknown or older than the ceremony timeout' "$REPO/src/web/routes/passkeys.rs" \
  && ok "expired or replayed ceremonies are journaled" \
  || bad "passkeys.rs does not log ceremony refusals"
grep -q 'passkey origin derived from the Host header' "$REPO/src/main.rs" \
  && ok "the journal states the passkey origin mode at startup" \
  || bad "main.rs does not log the origin mode"
grep -q 'code !== "bad_request" && code !== "conflict"' "$REPO/frontend/assets/app.js" \
  && ok "bad_request and conflict show the server's reason, not just the label" \
  || bad "app.js hides the actionable reason behind the generic label"

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

# ---- security headers on every response (Audit.md F2) ----
curl -sD "$ROOT/hd.txt" -o /dev/null "$BASE/login"
grep -qi '^x-content-type-options: nosniff' "$ROOT/hd.txt" \
  && ok "the UI carries nosniff" \
  || bad "no X-Content-Type-Options on /login"
grep -qi '^x-frame-options: SAMEORIGIN' "$ROOT/hd.txt" \
  && ok "the UI refuses cross-origin framing (SAMEORIGIN, not DENY: previews self-embed)" \
  || bad "no X-Frame-Options on /login"
grep -qi '^referrer-policy: same-origin' "$ROOT/hd.txt" \
  && ok "the UI leaks no referrer past its own origin" \
  || bad "no Referrer-Policy on /login"
CSP_LINE=$(grep -i '^content-security-policy:' "$ROOT/hd.txt")
echo "$CSP_LINE" | grep -q "script-src 'self' 'wasm-unsafe-eval'" \
  && echo "$CSP_LINE" | grep -q "frame-ancestors 'none'" \
  && echo "$CSP_LINE" | grep -q "connect-src 'self'" \
  && echo "$CSP_LINE" | grep -q "object-src 'none'" \
  && echo "$CSP_LINE" | grep -q "base-uri 'self'" \
  && ok "the app CSP pins scripts to its own assets and blocks embedding" \
  || bad "app CSP missing or weakened: $CSP_LINE"
grep -o 'WebAssembly\.instantiate' "$REPO/frontend/assets/hashwasm-argon2.js" >/dev/null \
  && ok "the CSP's wasm exception has a reason (hashwasm compiles WASM)" \
  || bad "hashwasm no longer compiles WASM - revisit the CSP exception"
curl -sD "$ROOT/hd.txt" -o /dev/null "$BASE/api/me"
grep -qi '^x-content-type-options: nosniff' "$ROOT/hd.txt" \
  && ok "the API answers carry the headers too" \
  || bad "API responses lack the security headers"
# or_insert, not insert: a route's own CSP (the preview sandbox) wins.
grep -q 'or_insert(csp_for(&state.config))' "$REPO/src/web/mod.rs" \
  && ok "the header layer never overwrites a route's own CSP (preview sandbox)" \
  || bad "the security-header layer force-overwrites route headers"
grep -q 'STRICT_TRANSPORT_SECURITY' "$REPO/src/web/mod.rs" \
  && ok "HSTS rides along when the deployment declares HTTPS" \
  || bad "no HSTS in the header layer"
# The knob that flips Secure cookies also has to flip HSTS; over plain HTTP
# the suite restarts once with it set, then returns to the default server.
kill "$(cat "$ROOT/server.pid")" 2>/dev/null
wait 2>/dev/null
FXCLOUD_DATA="$DATA" FXCLOUD_PORT=$PORT FXCLOUD_TRASH_DAYS=30 FXCLOUD_TRASH_SWEEP_SECS=2 \
  FXCLOUD_SECURE_COOKIE=1 "$BIN" >>"$ROOT/server.log" 2>&1 &
echo $! > "$ROOT/server.pid"
for _ in $(seq 1 100); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/me")" != "000" ] && break
  sleep 0.2
done
curl -sD "$ROOT/hd.txt" -o /dev/null "$BASE/login"
grep -qi '^strict-transport-security: max-age=' "$ROOT/hd.txt" \
  && ok "FXCLOUD_SECURE_COOKIE=1 turns on HSTS" \
  || bad "secure-cookie mode sends no HSTS"
curl -sD "$ROOT/hd.txt" -o /dev/null -X POST \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct-horse"}' "$BASE/api/login"
grep -qi '^set-cookie: fxcloud_session=.*secure' "$ROOT/hd.txt" \
  && ok "secure-cookie mode marks the cookie Secure" \
  || bad "secure-cookie mode sends no Secure attribute"
restart_server || { bad "server did not return to plain mode"; exit 1; }
curl -sD "$ROOT/hd.txt" -o /dev/null "$BASE/login"
grep -qi '^strict-transport-security' "$ROOT/hd.txt" \
  && bad "plain-HTTP mode must not send HSTS" \
  || ok "plain-HTTP mode stays HSTS-free"

# ---- session management: listing, ending, sliding renewal (Audit.md F4) ----
# Sits before the F1 section on purpose: every request here carries the
# right password, so nothing spends a failure budget, and the section's
# only state is the fresh sessions it creates itself. The server was
# restarted by the HSTS detour above, so the in-memory budget maps are
# empty and the DB rows below are the whole story.
note "sessions: settings listing, per-device end, sign out everywhere else, sliding renewal"

JA4="$ROOT/alice-sessions.jar"
JB4="$ROOT/bob-sessions.jar"
ALICE="user_id=(SELECT id FROM users WHERE username='alice') \
AND expires_at > strftime('%Y-%m-%dT%H:%M:%S','now')"

# A fresh sign-in arrives with a named device; the listing must carry it
# as its own session with the device line, and exactly one row marked
# as the session that asked.
RC=$(curl -s -o /dev/null -w '%{http_code}' -c "$JA4" \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: FxSuite/4.0 (laptop)' \
  -d '{"username":"alice","password":"correct-horse"}' "$BASE/api/login")
[ "$RC" = "200" ] && ok "a fresh sign-in with a named device succeeds" \
  || bad "fresh sign-in gave rc=$RC"

RC=$(reqsave GET /api/me/sessions "$JA4" "$ROOT/sessions4.json")
N=$(grep -o '"sid"' "$ROOT/sessions4.json" | wc -l)
CUR=$(grep -o '"current":true' "$ROOT/sessions4.json" | wc -l)
[ "$RC" = "200" ] && [ "$N" -ge 2 ] && [ "$CUR" = "1" ] \
  && grep -q 'FxSuite/4.0 (laptop)' "$ROOT/sessions4.json" \
  && grep -q '"created_at"' "$ROOT/sessions4.json" \
  && grep -q '"last_seen_at"' "$ROOT/sessions4.json" \
  && grep -q '"expires_at"' "$ROOT/sessions4.json" \
  && ok "the listing shows both sessions, exactly one current, with device and dates" \
  || bad "listing: rc=$RC n=$N current=$CUR body=$(head -c 200 "$ROOT/sessions4.json")"

# The primary key IS the secret token; an endpoint that listed tokens
# would defeat the HttpOnly cookie. The visible handle is the sid.
grep -q '"token"' "$ROOT/sessions4.json" \
  && bad "the session listing leaked a token field" \
  || ok "the listing carries handles, never the session token"

# The default window is seven days, measured on the session that has not
# been renewed yet - renewal rewrites expires_at, see the pins below.
TTL=$(sqlite3 "$DATA/fxcloud.db" \
  "SELECT CAST(ROUND((julianday(expires_at)-julianday(created_at))*86400) AS INTEGER) FROM sessions WHERE user_agent='FxSuite/4.0 (laptop)'")
[ "$TTL" = "604800" ] && ok "a fresh session lives 604800 seconds (7 days) by default" \
  || bad "default session window is $TTL seconds, not 604800"

# End another device by its handle: the row dies for real - its cookie
# is refused on the very next call - while the session that pressed the
# button keeps working. The victim is the sign-in that sits in the
# suite's original alice jar, addressed through that jar's own cookie.
TOK=$(awk '$6=="fxcloud_session"{print $7}' "$JA")
OTHER=$(sqlite3 "$DATA/fxcloud.db" "SELECT sid FROM sessions WHERE id='$TOK'")
RC=$(reqcode DELETE "/api/me/sessions/$OTHER" "$JA4")
ACODE=$(reqcode GET /api/me "$JA")
MCODE=$(reqcode GET /api/me "$JA4")
[ "$RC" = "204" ] && [ "$ACODE" = "401" ] && [ "$MCODE" = "200" ] \
  && ok "ending one session kills its cookie and leaves the current one alive" \
  || bad "end-one: rc=$RC ended=$ACODE current=$MCODE"

# Another account's handle gets the same 404 a stranger's id gets
# everywhere - never a 403, which would confirm the session exists.
reqsave POST /api/login "$JB4" "$ROOT/blogin4.json" \
  '{"username":"bob","password":"correct-horse"}' >/dev/null
CURSID=$(sqlite3 "$DATA/fxcloud.db" \
  "SELECT sid FROM sessions WHERE user_agent='FxSuite/4.0 (laptop)'")
RC=$(reqcode DELETE "/api/me/sessions/$CURSID" "$JB4")
[ "$RC" = "404" ] && ok "another account's sid answers 404, not 403" \
  || bad "foreign sid delete gave rc=$RC"

# Sign out everywhere else: one more session joins, the button ends
# every row but the one that pressed it.
RC=$(reqcode POST /api/login "$JA4" \
  '{"username":"alice","password":"correct-horse"}')
[ "$RC" = "200" ] && ok "a third sign-in prepares the incident button" \
  || bad "third sign-in gave rc=$RC"
RC=$(reqsave DELETE /api/me/sessions "$JA4" "$ROOT/sdel4.json")
ENDED=$(jget "$(cat "$ROOT/sdel4.json")" "ended")
REST=$(sqlite3 "$DATA/fxcloud.db" "SELECT COUNT(*) FROM sessions WHERE $ALICE")
MCODE=$(reqcode GET /api/me "$JA4")
[ "$RC" = "200" ] && [ -n "$ENDED" ] && [ "$ENDED" -ge 1 ] && [ "$REST" = "1" ] \
  && [ "$MCODE" = "200" ] \
  && ok "sign out everywhere else ends $ENDED session(s) and keeps the current one" \
  || bad "end-others: rc=$RC ended='$ENDED' rest=$REST me=$MCODE"

# Sliding renewal: backdate the survivor's last use two days, then one
# authenticated call must move it - and rewrite the window to exactly
# seven days from the touch, not from creation.
sqlite3 "$DATA/fxcloud.db" \
  "UPDATE sessions SET last_seen_at='2026-10-27 09:00:00' WHERE $ALICE"
RC=$(reqcode GET /api/me "$JA4")
MOVED=$(sqlite3 "$DATA/fxcloud.db" \
  "SELECT (julianday(last_seen_at) > julianday('now','-2 hours')) FROM sessions WHERE $ALICE")
WINDOW=$(sqlite3 "$DATA/fxcloud.db" \
  "SELECT CAST(ROUND((julianday(expires_at)-julianday(last_seen_at))*86400) AS INTEGER) FROM sessions WHERE $ALICE")
[ "$RC" = "200" ] && [ "$MOVED" = "1" ] && [ "$WINDOW" = "604800" ] \
  && ok "one authenticated call slides a stale session and renews its 7-day window" \
  || bad "renewal: rc=$RC moved=$MOVED window=$WINDOW"

# Renewal is at most one write per window: a session used within it is
# not touched again, so the hot path never rewrites the row.
E1=$(sqlite3 "$DATA/fxcloud.db" "SELECT expires_at FROM sessions WHERE $ALICE")
req GET /api/me "$JA4" >/dev/null
E2=$(sqlite3 "$DATA/fxcloud.db" "SELECT expires_at FROM sessions WHERE $ALICE")
[ "$E1" = "$E2" ] \
  && ok "a session used within its window is not rewritten (one write per window)" \
  || bad "a fresh session's expires_at moved: $E1 -> $E2"

# The UI half of the feature: section in the dialog, wired in app.js,
# strings present in all three languages, migration registered.
grep -q 'id="session-list"' "$REPO/frontend/index.html" \
  && grep -q 'id="session-others-btn"' "$REPO/frontend/index.html" \
  && ok "the settings dialog carries the sessions section" \
  || bad "no sessions section in the settings dialog"
grep -q 'loadSessions' "$REPO/frontend/assets/app.js" \
  && grep -q 'revokeOtherSessions' "$REPO/frontend/assets/app.js" \
  && ok "the settings dialog loads, renders and revokes sessions" \
  || bad "the session UI is not wired in app.js"
NI18N=$(grep -c '"settings.sessions":' "$REPO/frontend/assets/i18n.js")
[ "$NI18N" = "3" ] && ok "the sessions strings exist in all three languages" \
  || bad "settings.sessions appears $NI18N times, want 3"
grep -q '"settings.sessionEndConfirm"' "$REPO/frontend/assets/i18n.js" \
  && grep -q '"settings.sessionRevokeOthersConfirm"' "$REPO/frontend/assets/i18n.js" \
  && ok "both end-session actions ask for confirmation first" \
  || bad "a session confirmation string is missing"
grep -q '013_sessions_meta' "$REPO/src/db/mod.rs" \
  && ok "migration 013 (sid, user_agent, last_seen_at) is registered" \
  || bad "013_sessions_meta is not registered"

# ---- the settings dialog: a nav column, one pane at a time (v0.0.35) ----
# Seven stacked sections outran the viewport in 0.0.33 - the dialog cut
# off at the top and bottom. The layout answers with a nav on the left
# and the active pane on the right: the dialog is capped at the screen,
# its content column scrolls, and no account can make it outgrow the
# window however many sessions or passkeys it holds.
grep -q 'data-settings-tab' "$REPO/frontend/index.html" \
  && grep -q 'data-settings-panel' "$REPO/frontend/index.html" \
  && ok "the settings dialog is a nav plus panes, not one long column" \
  || bad "the settings dialog has no tab structure"
grep -q 'activateSettingsTab' "$REPO/frontend/assets/app.js" \
  && grep -q 'activateSettingsTab("account")' "$REPO/frontend/assets/app.js" \
  && ok "the nav switches panes and the dialog reopens on Account" \
  || bad "the settings nav is not wired in app.js"
grep -q 'max-height: min(' "$REPO/frontend/assets/style.css" \
  && grep -q '.settings-content {' "$REPO/frontend/assets/style.css" \
  && ok "the dialog is capped at the viewport and its content scrolls" \
  || bad "the settings dialog has no height cap or scrolling pane"
NS18N=$(grep -c '"settings.appearance":' "$REPO/frontend/assets/i18n.js")
[ "$NS18N" = "3" ] && ok "the nav's Appearance label exists in all three languages" \
  || bad "settings.appearance appears $NS18N times, want 3"

# ---- hardening batch: walk caps, origin warning, timing parity (F6/F8/F10) ----
# Placed before the F1 section like the session pins above: the sign-ins
# here are cheap (two failed logins, far from every budget) and the tree
# surgery touches only fixtures this section creates itself.
note "hardening: depth caps on the share walks, FXCLOUD_ORIGIN warning, login timing parity"

# -- F6: covering_share gains the 64-hop cap under_trash already has --
grep -q 'hops > 64' "$REPO/src/db/share.rs" \
  && ok "covering_share caps its parent walk at 64 hops" \
  || bad "covering_share walks parents without a depth cap"
grep -q 'hops > 64' "$REPO/src/db/file.rs" \
  && ok "the breadcrumb walk carries the same depth cap" \
  || bad "breadcrumbs walks parents without a depth cap"

# Functional: a parent cycle written straight into the database must
# answer with clean 404s - the walks end at the cap instead of spinning
# their connection thread forever (the finding's impact, reproduced).
# Every probe is timeout-guarded, so a regression reads as a failed pin,
# not a stuck suite.
FA=$(req POST /api/files/folder "$JA4" '{"name":"f6tree"}')
A_ID=$(jget "$FA" entry.id)
FB=$(req POST /api/files/folder "$JA4" "{\"name\":\"f6b\",\"parent_id\":$A_ID}")
B_ID=$(jget "$FB" entry.id)
FC=$(req POST /api/files/folder "$JA4" "{\"name\":\"f6c\",\"parent_id\":$A_ID}")
C_ID=$(jget "$FC" entry.id)
FD=$(req POST /api/files/folder "$JA4" "{\"name\":\"f6d\",\"parent_id\":$B_ID}")
D_ID=$(jget "$FD" entry.id)
OUT=$(req POST /api/shares/batch "$JA4" \
  "{\"items\":[{\"file_id\":$A_ID}],\"username\":\"bob\",\"permissions\":1}")
echo "$OUT" | grep -q '"ok":\[' \
  && ok "the cycle's tree is shared with a grantee (F6 setup)" \
  || bad "share setup failed: $OUT"
# B <-> C closes the cycle below the shared root: every walk upwards
# from D loops without ever reaching the share.
sqlite3 "$DATA/fxcloud.db" \
  "UPDATE files SET parent_id=$C_ID WHERE id=$B_ID; \
   UPDATE files SET parent_id=$B_ID WHERE id=$C_ID;"
RC=$(timeout 15 curl -s -o /dev/null -w '%{http_code}' -X GET \
  -b "$JB4" "$BASE/api/files?parent=$D_ID")
[ "$RC" = "404" ] \
  && ok "a grantee's listing inside a corrupt cycle answers 404, not a hang" \
  || bad "cycle listing gave rc=$RC (124 would mean the walk hung)"
RC=$(timeout 15 curl -s -o /dev/null -w '%{http_code}' -X GET \
  -b "$JB4" "$BASE/api/files/breadcrumb?id=$D_ID")
[ "$RC" = "404" ] \
  && ok "the breadcrumb walk ends at the cap instead of spinning" \
  || bad "cycle breadcrumbs gave rc=$RC"
RC=$(timeout 15 curl -s -o /dev/null -w '%{http_code}' -X GET \
  -b "$JB4" "$BASE/api/files?parent=$A_ID")
[ "$RC" = "200" ] \
  && ok "the shared root above the cycle stays readable (the cap costs nothing healthy)" \
  || bad "listing the shared root gave rc=$RC"

# -- F8: the derived-origin deployment says so at WARN --
grep -q 'listening beyond loopback' "$REPO/src/main.rs" \
  && ok "startup warns when the bind is beyond loopback without FXCLOUD_ORIGIN" \
  || bad "main.rs carries no origin warning"
mkdir -p "$ROOT/f8data"
FXCLOUD_DATA="$ROOT/f8data" FXCLOUD_BIND=0.0.0.0 FXCLOUD_PORT=$((PORT + 41)) \
  timeout 4 "$BIN" >>"$ROOT/f8.log" 2>&1 &
sleep 1.5
grep -q 'listening beyond loopback' "$ROOT/f8.log" \
  && ok "the warning actually fires on a non-loopback bind without the origin" \
  || bad "no origin warning in the sidecar's journal"
grep -q 'listening beyond loopback' "$ROOT/server.log" \
  && bad "the loopback suite server warns without need" \
  || ok "the loopback server stays quiet (the warning is for the risky shape only)"

# -- F10: an unknown username pays the same verification a wrong
# password pays, so this 401 cannot be timed apart from a real one --
grep -q 'TIMING_DUMMY_HASH' "$REPO/src/web/routes/auth.rs" \
  && ok "the unknown-user path spends a dummy Argon2 verification" \
  || bad "login does not equalize the unknown-user timing"
RC=$(reqsave POST /api/login "$ROOT/ghost.jar" "$ROOT/ghost.json" \
  '{"username":"no-such-user-today","password":"whatever-12345"}')
RC2=$(reqsave POST /api/login "$ROOT/awrong.jar" "$ROOT/awrong.json" \
  '{"username":"alice","password":"wrong-password-x"}')
GHOST=$(cat "$ROOT/ghost.json")
AWRON=$(cat "$ROOT/awrong.json")
[ "$RC" = "401" ] && [ "$RC2" = "401" ] && [ -n "$GHOST" ] && [ "$GHOST" = "$AWRON" ] \
  && ok "unknown user and wrong password answer the identical 401" \
  || bad "the 401s differ: rc=$RC/$RC2 bodies '$GHOST' vs '$AWRON'"

# ---- authentication rate limiting (F1) ----
# The HSTS detour above restarted the server, so every counter here starts
# from zero: the section is self-contained no matter what ran before.
note "sign-in throttling: account backoff, source budgets, challenge cap"

FJ="$ROOT/frank.jar"
RC=$(reqcode POST /api/register "$FJ" \
  '{"username":"frank","password":"correct-horse"}')
[ "$RC" = "202" ] && ok "frank registers pending activation" \
  || bad "frank register gave rc=$RC (want 202)"
sqlite3 "$DATA/fxcloud.db" "UPDATE users SET is_active=1 WHERE username='frank';"

# Five plain 401s: the lock starts after the fifth failure, not before.
FRANK401=1
for i in 1 2 3 4 5; do
  RC=$(reqcode POST /api/login "$FJ" \
    '{"username":"frank","password":"wrong-password"}')
  [ "$RC" = "401" ] || FRANK401=0
done
[ "$FRANK401" = "1" ] && ok "five wrong passwords are five plain 401s" \
  || bad "a pre-lock attempt did not answer 401"

# The sixth is refused with 429; Retry-After, body code and body seconds
# all name the same window.
RC=$(curl -sD "$ROOT/hf.txt" -o "$ROOT/fb.json" -w '%{http_code}' \
  -X POST "$BASE/api/login" -H 'Content-Type: application/json' \
  -d '{"username":"frank","password":"wrong-password"}')
RETRY=$(grep -i '^retry-after:' "$ROOT/hf.txt" | tr -dc '0-9')
[ "$RC" = "429" ] && [ -n "$RETRY" ] \
  && grep -q '"code":"rate_limited"' "$ROOT/fb.json" \
  && grep -q "\"retry_after\":$RETRY" "$ROOT/fb.json" \
  && ok "the sixth wrong password is 429 + Retry-After $RETRY (header and body agree)" \
  || bad "sixth wrong password gave rc=$RC retry='$RETRY' body=$(cat "$ROOT/fb.json")"

# The refusal runs before verification: even the right password waits,
# which is also what keeps the window from costing an Argon2 hash.
RC=$(reqcode POST /api/login "$FJ" \
  '{"username":"frank","password":"correct-horse"}')
[ "$RC" = "429" ] && ok "the right password waits out the window too (gate before verify)" \
  || bad "a locked account answered a correct password with rc=$RC"

sleep $((RETRY + 1))
RC=$(reqcode POST /api/login "$FJ" \
  '{"username":"frank","password":"correct-horse"}')
[ "$RC" = "200" ] && ok "after the window the account signs in again" \
  || bad "recovery after the window gave rc=$RC"
RC=$(reqcode POST /api/login "$FJ" \
  '{"username":"frank","password":"wrong-password"}')
[ "$RC" = "401" ] && ok "a successful sign-in clears the counter" \
  || bad "the counter survived a success (rc=$RC)"

# An invented name locks exactly like a real one - the 429 cannot be used
# to tell an account holder from a name someone made up - and the passkey
# door honours the same backoff.
for i in 1 2 3 4 5; do
  reqcode POST /api/login "$FJ" \
    '{"username":"ghost-user","password":"wrong-password"}' >/dev/null
done
RC=$(reqcode POST /api/login "$FJ" \
  '{"username":"ghost-user","password":"wrong-password"}')
[ "$RC" = "429" ] && ok "an unknown name locks identically (no enumeration via 429)" \
  || bad "an unknown name did not lock (rc=$RC)"
RC=$(reqcode POST /api/passkeys/login/start "$FJ" '{"username":"ghost-user"}')
[ "$RC" = "429" ] && ok "the passkey door honours the same account backoff" \
  || bad "passkeys/login/start ignored the account lock (rc=$RC)"
RC=$(reqcode POST /api/passkeys/login/start "$FJ" '{"username":"frank"}')
[ "$RC" = "200" ] && ok "an unlocked name still gets its challenge" \
  || bad "an unlocked name was refused a challenge (rc=$RC)"

# The register door spends its budget before the hash: a flood of fresh
# names cannot borrow the CPU a single registration is allowed.
i=0; RC=""
while [ "$i" -lt 16 ]; do
  i=$((i + 1))
  RC=$(reqcode POST /api/register "$FJ" \
    "{\"username\":\"reg-spam-$i\",\"password\":\"correct-horse\"}")
  [ "$RC" = "429" ] && break
done
[ "$RC" = "429" ] && ok "the register budget trips with 429 (after $i attempts)" \
  || bad "the register budget never tripped (rc=$RC after $i attempts)"

# The WebAuthn challenge map is capped: once full, a new challenge is
# refused instead of the map growing with the flood.
i=0; RC=""
while [ "$i" -lt 300 ]; do
  i=$((i + 1))
  RC=$(reqcode POST /api/passkeys/login/start "$FJ" '{"username":"cer-spam"}')
  [ "$RC" = "429" ] && break
done
[ "$RC" = "429" ] && ok "the challenge map caps with 429 (after $i starts)" \
  || bad "the challenge map never capped (rc=$RC after $i starts)"

# Last pin of the server section: the source-address budget that bounds
# the aggregate one address can trigger. Its behaviour is pinned by the
# unit tests in src/web/state.rs (the suite cannot: every counted failure
# pays an Argon2 verification, and on the suite's cores the debug build
# spends so long per hash that the budget fills exactly as fast as its
# 60-second window lapses - flaky by physics, not by code). What the
# suite keeps is the wiring: the gate answers 429 off this budget, and
# the 429 shape itself is pinned by the account lockout above.
grep -q 'LOGIN_FAIL_BUDGET' "$REPO/src/web/state.rs" \
  && grep -q 'spend.spent >= LOGIN_FAIL_BUDGET' "$REPO/src/web/state.rs" \
  && ok "the source-address budget refuses the failure after the budget is gone" \
  || bad "the source login-failure budget is gone from the gate"

# ---- office integration (concepts/office.md) ----
# The engine is curl: everything WOPI-shaped is plain REST, so the contract
# (mint, CheckFileInfo, both GetFile spellings, PutFile + decision 12) is
# pinned without Docker in CI. The real-engine smoke test lives in INSTALL.md.
note "office editing: routes absent while unconfigured"

# Feature off first (decision 3): none of the office paths exist at all.
RC=$(reqcode POST /api/office/start "$JA" '{"id":1}')
[ "$RC" = "404" ] \
  && ok "office start route does not exist while unconfigured" \
  || bad "office start answered $RC while unconfigured"
RC=$(reqcode GET "/wopi/files/1?access_token=x" "$JA")
[ "$RC" = "404" ] \
  && ok "CheckFileInfo route does not exist while unconfigured" \
  || bad "wopi info answered $RC while unconfigured"
RC=$(reqcode GET "/wopi/files/1/contents?access_token=x" "$JA")
[ "$RC" = "404" ] \
  && ok "GetFile route does not exist while unconfigured" \
  || bad "wopi content answered $RC while unconfigured"
RC=$(reqcode POST "/wopi/files/1/contents?access_token=x" "$JA" '{"x":1}')
[ "$RC" = "404" ] \
  && ok "PutFile route does not exist while unconfigured" \
  || bad "wopi put answered $RC while unconfigured"

# The knobs and the gates live in the source (the behavioural halves are
# below, once a server is running with them set).
grep -q 'FXCLOUD_OFFICE_URL' "$REPO/src/config.rs" \
  && grep -q 'FXCLOUD_OFFICE_SECRET' "$REPO/src/config.rs" \
  && grep -q 'FXCLOUD_OFFICE_WOPI_BASE' "$REPO/src/config.rs" \
  && ok "the three office knobs are configurable" \
  || bad "office env knobs missing from config.rs"
grep -q 'enc_version > 0' "$REPO/src/web/routes/office.rs" \
  && ok "the mint refuses encrypted rows (plaintext only, section 7)" \
  || bad "no encryption gate in office.rs"
grep -q 'require_update' "$REPO/src/web/routes/office.rs" \
  && ok "every office call re-checks the UPDATE grant live (decision 11)" \
  || bad "office.rs does not check UPDATE"
grep -q '/wopi/files/{id}/contents' "$REPO/src/web/mod.rs" \
  && grep -q '/wopi/files/{id}/content"' "$REPO/src/web/mod.rs" \
  && ok "GetFile answers both content spellings (MS spec and Collabora)" \
  || bad "one of the two content spellings is missing from the router"
grep -q 'buildOfficeOverlay' "$REPO/frontend/assets/app.js" \
  && grep -q 'data-office' "$REPO/frontend/index.html" \
  && ok "the frontend carries the overlay and the server-side engine slot" \
  || bad "office overlay wiring missing from the frontend"

note "office editing: mint, WOPI host and the pin rule"
# Fresh sign-in: the session-management section above ended every other
# alice session on purpose ("sign out everywhere else"), so inheriting $JA
# here would upload into a 401. Re-login writes the new cookie into the
# same jar, and everything below rides on it.
req POST /api/login "$JA" '{"username":"alice","password":"correct-horse"}' >/dev/null
printf 'ORIGINALEINZEILE' > "$ROOT/src/brief.docx"
up "$JA" "$DOC" brief.docx >/dev/null
BRIEF=$(idof "$(req GET "/api/files?parent=$DOC" "$JA")" brief.docx)
[ -n "$BRIEF" ] && ok "office fixture uploaded" || { bad "office fixture upload"; exit 1; }

# Restart with the office config - the same one-shot pattern the HSTS test
# uses; restart_server afterwards returns the suite to plain mode.
kill "$(cat "$ROOT/server.pid")" 2>/dev/null
wait 2>/dev/null
FXCLOUD_DATA="$DATA" FXCLOUD_PORT=$PORT FXCLOUD_TRASH_DAYS=30 FXCLOUD_TRASH_SWEEP_SECS=2 \
  FXCLOUD_OFFICE_URL=http://office.example:9980 \
  FXCLOUD_OFFICE_SECRET=unit-secret-0123456789 \
  FXCLOUD_OFFICE_WOPI_BASE=http://127.0.0.1:$PORT \
  "$BIN" >>"$ROOT/server.log" 2>&1 &
echo $! > "$ROOT/server.pid"
for _ in $(seq 1 100); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/me")" != "000" ] && break
  sleep 0.2
done

# The app shell learns the engine URL at render time (no extra round trip).
curl -s -b "$JA" "$BASE/" | grep -q 'data-office="http://office.example:9980"' \
  && ok "the app shell carries the configured engine URL" \
  || bad "index.html does not expose the engine URL"

# CSP: exactly two directives gain the engine origin (section 7).
curl -sD "$ROOT/hd.txt" -o /dev/null "$BASE/login"
grep -q "frame-src 'self' blob: http://office.example:9980" "$ROOT/hd.txt" \
  && grep -q "form-action 'self' http://office.example:9980" "$ROOT/hd.txt" \
  && ok "CSP widens frame-src and form-action for the engine" \
  || bad "office CSP missing: $(grep -i '^content-security-policy' "$ROOT/hd.txt")"

# The mint: session-gated, file-scoped, secret-free.
: > "$ROOT/nojar"
RC=$(reqcode POST /api/office/start "$ROOT/nojar" "{\"id\":$BRIEF}")
[ "$RC" = "401" ] \
  && ok "the mint needs a signed-in account" \
  || bad "unauthenticated mint answered $RC"
START=$(req POST /api/office/start "$JA" "{\"id\":$BRIEF}")
MODE=$(jget "$START" mode)
TOK=$(jget "$START" access_token)
TTL=$(jget "$START" access_token_ttl)
URL=$(jget "$START" url)
[ "$MODE" = "form" ] \
  && ok "the default embed flow is the official form POST" \
  || bad "mode=$MODE, expected form"
echo "$START" | grep -q 'unit-secret' \
  && bad "the WOPI secret leaked into the mint response: $START" \
  || ok "the HMAC secret never reaches the browser"
echo "$URL" | grep -q "/hosting/wopi/word/edit?wopisrc=" \
  && ok "the target URL is the OnlyOffice-family host page for docx" \
  || bad "url=$URL"
echo "$URL" | grep -q "wopisrc=http%3A%2F%2F127%2E0%2E0%2E1%3A${PORT}%2Fwopi%2Ffiles%2F${BRIEF}" \
  && ok "WOPISrc uses the configured base and names exactly this file" \
  || bad "wopisrc wrong: $URL"
[ -n "$TOK" ] && [ "${TTL:-0}" -gt 0 ] 2>/dev/null \
  && ok "a token with a future expiry is minted" \
  || bad "token=$TOK ttl=$TTL"

RC=$(reqcode POST /api/office/start "$JA" "{\"id\":$DOC}")
[ "$RC" = "400" ] \
  && ok "folders have no office editor" \
  || bad "folder mint answered $RC"
RC=$(reqcode POST /api/office/start "$JA" '{"id":99999999}')
[ "$RC" = "404" ] \
  && ok "an unknown id never exists" \
  || bad "unknown-id mint answered $RC"

# CheckFileInfo: description plus the spike's stability rule (section 11).
CF=$(req GET "/wopi/files/$BRIEF?access_token=$TOK" "$JA")
[ "$(jget "$CF" BaseFileName)" = "brief.docx" ] \
  && ok "CheckFileInfo describes the file" \
  || bad "CheckFileInfo: $CF"
[ "$(jget "$CF" UserCanWrite)" = "1" ] \
  && ok "v1 sessions are write sessions (decision 11)" \
  || bad "UserCanWrite: $(jget "$CF" UserCanWrite)"
CF2=$(req GET "/wopi/files/$BRIEF?access_token=$TOK" "$JA")
LMT1=$(jget "$CF" LastModifiedTime)
LMT2=$(jget "$CF2" LastModifiedTime)
[ -n "$LMT1" ] && [ "$LMT1" = "$LMT2" ] \
  && ok "LastModifiedTime stays byte-stable between writes (spike finding)" \
  || bad "time drifted: [$LMT1] vs [$LMT2]"

# Every token refusal is the same 404 - never a hint (section 5).
first=${TOK:0:1}
if [ "$first" = "A" ]; then TOKBAD="B${TOK:1}"; else TOKBAD="A${TOK:1}"; fi
RC=$(reqcode GET "/wopi/files/$BRIEF?access_token=$TOKBAD" "$JA")
[ "$RC" = "404" ] && ok "a tampered token answers 404" || bad "tampered token: $RC"
RC=$(reqcode GET "/wopi/files/$DOC?access_token=$TOK" "$JA")
[ "$RC" = "404" ] \
  && ok "a token bound to another file answers 404" \
  || bad "cross-file token: $RC"
RC=$(reqcode GET "/wopi/files/$BRIEF" "$JA")
[ "$RC" = "404" ] && ok "no token answers 404" || bad "tokenless: $RC"

# GetFile: both spellings, the same bytes (measured against both engines).
BODY=$(req GET "/wopi/files/$BRIEF/contents?access_token=$TOK" "$JA")
[ "$BODY" = "ORIGINALEINZEILE" ] \
  && ok "GetFile (Collabora spelling) serves the bytes" \
  || bad "contents=[$BODY]"
BODY2=$(req GET "/wopi/files/$BRIEF/content?access_token=$TOK" "$JA")
[ "$BODY2" = "ORIGINALEINZEILE" ] \
  && ok "GetFile (MS spec spelling) serves the bytes too" \
  || bad "content=[$BODY2]"

# PutFile round-trip and decision 12 (pin per session).
SAVE1=$(req POST "/wopi/files/$BRIEF/contents?access_token=$TOK" "$JA" "NEUEINHALTV1")
echo "$SAVE1" | grep -q '"LastModifiedTime"' \
  && echo "$SAVE1" | grep -q '"Version"' \
  && ok "PutFile answers with the WOPI save fields" \
  || bad "save1=$SAVE1"
DLO=$(req GET "/api/files/download?id=$BRIEF" "$JA")
[ "$DLO" = "NEUEINHALTV1" ] \
  && ok "the office save landed in the file store" \
  || bad "download=[$DLO]"
VN=$(req GET "/api/files/versions?id=$BRIEF" "$JA" | grep -o '"id"' | wc -l)
[ "$VN" -eq 1 ] \
  && ok "the first office save pins the outgoing content (rule b)" \
  || bad "expected 1 version after save1, got $VN"

SAVE2=$(req POST "/wopi/files/$BRIEF/contents?access_token=$TOK" "$JA" "NEUEINHALTV2")
VN=$(req GET "/api/files/versions?id=$BRIEF" "$JA" | grep -o '"id"' | wc -l)
[ -n "$SAVE2" ] && [ "$VN" -eq 1 ] \
  && ok "the session's own autosave does NOT pin again (decision 12)" \
  || bad "expected still 1 version, got $VN"

# A foreign write pins twice over: the other mechanism's outgoing content
# lands in history, and the next office save pins what it did not write.
RC=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -b "$JA" \
  -H 'Content-Type: text/plain; charset=utf-8' --data-binary 'FREMDSCHREIBER' \
  "$BASE/api/files/content?id=$BRIEF")
[ "$RC" = "200" ] || bad "foreign write failed: $RC"
VN=$(req GET "/api/files/versions?id=$BRIEF" "$JA" | grep -o '"id"' | wc -l)
[ "$VN" -eq 2 ] \
  && ok "the built-in editor's write pins the office session's content" \
  || bad "expected 2 versions after foreign write, got $VN"
SAVE3=$(req POST "/wopi/files/$BRIEF/contents?access_token=$TOK" "$JA" "NEUEINHALTV3")
VN=$(req GET "/api/files/versions?id=$BRIEF" "$JA" | grep -o '"id"' | wc -l)
[ -n "$SAVE3" ] && [ "$VN" -eq 3 ] \
  && ok "the next office save pins content this session did not write" \
  || bad "expected 3 versions, got $VN"

# The second embed flow (Collabora's), same one-shot restart pattern.
kill "$(cat "$ROOT/server.pid")" 2>/dev/null
wait 2>/dev/null
FXCLOUD_DATA="$DATA" FXCLOUD_PORT=$PORT FXCLOUD_TRASH_DAYS=30 FXCLOUD_TRASH_SWEEP_SECS=2 \
  FXCLOUD_OFFICE_URL=http://office.example:9980 \
  FXCLOUD_OFFICE_SECRET=unit-secret-0123456789 \
  FXCLOUD_OFFICE_EMBED=iframe \
  "$BIN" >>"$ROOT/server.log" 2>&1 &
echo $! > "$ROOT/server.pid"
for _ in $(seq 1 100); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/me")" != "000" ] && break
  sleep 0.2
done
IFR=$(req POST /api/office/start "$JA" "{\"id\":$BRIEF}")
[ "$(jget "$IFR" mode)" = "iframe" ] \
  && ok "FXCLOUD_OFFICE_EMBED=iframe selects the Collabora flow" \
  || bad "mode=$(jget "$IFR" mode)"
echo "$IFR" | grep -q "cool.html?WOPISrc=" \
  && echo "$IFR" | grep -q "access_token=" \
  && ok "the iframe URL carries WOPISrc and the token in the query" \
  || bad "iframe url=$(jget "$IFR" url)"

# Back to plain mode: the routes disappear again (decision 3).
restart_server || { bad "server did not return to plain mode"; exit 1; }
RC=$(reqcode GET "/wopi/files/1?access_token=x" "$JA")
[ "$RC" = "404" ] \
  && ok "back in plain mode the office routes are gone again" \
  || bad "office routes survived the restart: $RC"

# ---- install.sh, Dockerfile, --version: the shipped routines ----
note "one-line install/update and the container build"
# --version must answer and exit, not start a server (timeout would fire).
V_OUT=$(timeout 5 "$BIN" --version 2>&1) && V_RC=0 || V_RC=$?
[ "$V_RC" = "0" ] && [ "$V_OUT" = "fxcloud v$VER" ] \
  && ok "--version answers fxcloud v$VER and exits" \
  || bad "--version: rc=$V_RC out=$V_OUT"
timeout 5 "$BIN" --help 2>&1 | grep -q 'FXCLOUD_DATA' \
  && ok "--help documents the environment knobs" \
  || bad "--help does not mention FXCLOUD_DATA"
timeout 5 "$BIN" --oops >/dev/null 2>&1; RC=$?
[ "$RC" = "2" ] \
  && ok "an unknown argument exits 2 instead of starting a server" \
  || bad "unknown argument gave rc=$RC"

INSTALL="$REPO/install.sh"
README="$REPO/README.md"
head -n 1 "$INSTALL" | grep -q '^#!/bin/sh' \
  && ok "install.sh is a POSIX sh script" \
  || bad "install.sh lacks the #!/bin/sh shebang"
grep -q 'set -eu' "$INSTALL" \
  && ok "install.sh fails loudly on the first error" \
  || bad "install.sh does not run with set -eu"
grep -q 'id -u' "$INSTALL" \
  && ok "install.sh refuses to run without root" \
  || bad "install.sh has no root check"
grep -q 'releases/download' "$INSTALL" \
  && ok "install.sh downloads release assets" \
  || bad "install.sh does not fetch from GitHub releases"
grep -q 'fxcloud-$TAG-x86_64-unknown-linux-musl' "$INSTALL" \
  && grep -q 'fxcloud-\*-x86_64-unknown-linux-musl' "$REPO/.github/workflows/release.yml" \
  && grep -q '^            SHA256SUMS' "$REPO/.github/workflows/release.yml" \
  && ok "the installer's asset name matches what the release CI attaches, next to the checksums" \
  || bad "install.sh and release.yml disagree on the asset name or the checksums"
grep -q 'curl -fsSL https://raw.githubusercontent.com/.*/install.sh | sh' "$README" \
  && grep -q 'raw.githubusercontent.com/.*/install.sh | sh' "$REPO/USERGUIDE.md" \
  && grep -q 'raw.githubusercontent.com/.*/install.sh | sh' "$REPO/INSTALL.md" \
  && ok "README, USERGUIDE and INSTALL.md carry the install one-liner" \
  || bad "the one-liner is missing from README, USERGUIDE or INSTALL.md"
grep -q '$BIN.bak' "$INSTALL" \
  && ok "an update keeps the previous binary as a .bak" \
  || bad "install.sh does not back up the running binary"
grep -q 'timeout 5 "$BIN" --version' "$INSTALL" \
  && ok "a pre-version binary cannot hang the update" \
  || bad "install.sh does not guard the old binary's --version probe"
grep -q 'curl -fsSL --retry' "$INSTALL" \
  && ok "the download is silent and retries" \
  || bad "install.sh downloads without -sS and --retry"
grep -q 'rm -rf "$DATA_DIR"' "$INSTALL" \
  && bad "install.sh deletes the data directory" \
  || ok "the data directory is never touched"
grep -q 'keeping the existing' "$INSTALL" \
  && ok "an existing unit is kept, only the binary is replaced" \
  || bad "install.sh would overwrite a customized unit"
grep -q 'NoNewPrivileges' "$INSTALL" && grep -q 'ReadWritePaths' "$INSTALL" \
  && ok "the generated unit ships the hardened profile" \
  || bad "install.sh writes an unhardened unit"
grep -q '127.0.0.1:$PORT/login' "$INSTALL" \
  && ok "the installer waits for /login before reporting success" \
  || bad "install.sh does not health-check the service"
grep -q 'this unit sets no FXCLOUD_ORIGIN' "$INSTALL" \
  && ok "an upgraded unit without FXCLOUD_ORIGIN gets a passkey hint" \
  || bad "install.sh does not point at the missing origin knob"

# -- release checksums (F7) ------------------------------------------------
# CI publishes SHA256SUMS next to the binary and the installer compares
# the download against it. A release that predates the checksums has no
# file to fetch, and that must stay installable - the ELF and --version
# checks below still run.
grep -q 'sha256sum "fxcloud-${GITHUB_REF_NAME}-x86_64-unknown-linux-musl" > SHA256SUMS' \
    "$REPO/.github/workflows/release.yml" \
  && ok "the release CI writes SHA256SUMS next to the asset" \
  || bad "release.yml does not generate SHA256SUMS"
grep -q 'checksum mismatch' "$INSTALL" \
  && grep -q 'SHA256SUMS' "$INSTALL" \
  && ok "the installer verifies the download against SHA256SUMS and dies on mismatch" \
  || bad "install.sh has no checksum verification"
grep -q 'pre-v0.0.34 release' "$INSTALL" \
  && ok "a release without SHA256SUMS still installs (the file is optional)" \
  || bad "install.sh would refuse a release that predates the checksums"
# Functional: the format contract both sides share - CI writes plain
# sha256sum output, the installer picks the asset's line by name and
# compares the hashes. A round trip must pass on the intact file and
# fail on a tampered one.
CKD="$ROOT/ckd"
mkdir -p "$CKD"
printf 'not-a-real-binary' > "$CKD/fxcloud-vTEST-x86_64-unknown-linux-musl"
(cd "$CKD" && sha256sum "fxcloud-vTEST-x86_64-unknown-linux-musl" > SHA256SUMS)
WANT=$(awk -v n="fxcloud-vTEST-x86_64-unknown-linux-musl" \
  '$2 == n {print $1; exit}' "$CKD/SHA256SUMS")
GOT=$(sha256sum "$CKD/fxcloud-vTEST-x86_64-unknown-linux-musl" | awk '{print $1}')
[ -n "$WANT" ] && [ "$WANT" = "$GOT" ] \
  && ok "the checksum line format round-trips through the installer's own check" \
  || bad "the SHA256SUMS format and the installer's extraction disagree"
printf 'tampered' > "$CKD/fxcloud-vTEST-x86_64-unknown-linux-musl"
GOT=$(sha256sum "$CKD/fxcloud-vTEST-x86_64-unknown-linux-musl" | awk '{print $1}')
[ -n "$WANT" ] && [ "$WANT" != "$GOT" ] \
  && ok "a tampered download no longer matches the published checksum" \
  || bad "the tampered file still matches SHA256SUMS"

DOCKERFILE="$REPO/Dockerfile"
grep -q '^FROM rust:alpine AS build' "$DOCKERFILE" \
  && ok "the image builds the static binary on rust:alpine" \
  || bad "Dockerfile has no rust:alpine build stage"
grep -q '^FROM alpine' "$DOCKERFILE" \
  && ok "the runtime stage is plain alpine" \
  || bad "Dockerfile has no alpine runtime stage"
grep -q '^VOLUME /data' "$DOCKERFILE" \
  && ok "the container keeps its data in the /data volume" \
  || bad "Dockerfile declares no data volume"
grep -q '^EXPOSE 8080' "$DOCKERFILE" \
  && ok "the container exposes port 8080" \
  || bad "Dockerfile does not expose 8080"
grep -q '^HEALTHCHECK' "$DOCKERFILE" \
  && ok "the container has a health check on /login" \
  || bad "Dockerfile has no HEALTHCHECK"
grep -q '^USER fxcloud' "$DOCKERFILE" \
  && ok "the container runs as a non-root user" \
  || bad "Dockerfile does not switch USER"
grep -q '^target' "$REPO/.dockerignore" \
  && ok ".dockerignore keeps the host build out of the context" \
  || bad ".dockerignore does not exclude target/"
grep -q 'docker build -t fxcloud' "$REPO/INSTALL.md" \
  && grep -q 'docker run -d --name fxcloud' "$REPO/INSTALL.md" \
  && ok "INSTALL.md shows how to build and run the container" \
  || bad "INSTALL.md lacks the docker build/run lines"
# The README is the map of the docs: install lives in INSTALL.md and
# every feature has its own concept document linked from the README.
README_MAP=1
grep -q '](INSTALL.md)' "$README" || README_MAP=0
for C in "$REPO"/concepts/*.md; do
  grep -q "concepts/${C##*/}" "$README" || README_MAP=0
done
[ "$README_MAP" = "1" ] \
  && ok "the README links to INSTALL.md and every concept document" \
  || bad "the README misses a link to INSTALL.md or a concepts/ document"
grep -q 'docker build' "$REPO/.github/workflows/test.yml" \
  && ok "CI builds the image so the instructions stay honest" \
  || bad "test.yml does not build the Dockerfile"

note "server log (errors?)"
grep -iE 'panic|error' "$ROOT/server.log" | head -20 || true

echo
if [ "$FAIL" = "0" ]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
kill "$(cat "$ROOT/server.pid")" 2>/dev/null
exit "$FAIL"
