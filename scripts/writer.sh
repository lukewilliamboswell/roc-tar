#!/bin/bash
# Checks the writer against GNU tar and bsdtar. tests/tools/tarwrite.roc
# writes the sample archive (each member kind and each pax field). Then:
# 1. It must be tests/fixtures/written.tar, byte for byte (FIX=1 writes the
#    fixture and its .list file again in place of this check).
# 2. tests/tools/tarlist.roc (this reader) and GNU `tar -tv`
#    (scripts/tvlist.sh) give the same members.
# 3. GNU tar and bsdtar list and extract it the same
#    (tests/tools/tartools.py). Each FILE.tar that you give gets this check too.
# Exit 0 when all pass. Usage: scripts/writer.sh [ROC] [FILE.tar...].
# GNU_TAR (default: tar) is GNU tar, BSD_TAR (default: bsdtar) is bsdtar.
set -uo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
ROC=${1:-roc}
shift || true
GNU_TAR=${GNU_TAR:-tar}
BSD_TAR=${BSD_TAR:-bsdtar}
W=$HERE/.work/writer
F=$HERE/tests/fixtures
rm -rf "$W" && mkdir -p "$W/bin" "$W/tmp"
"$GNU_TAR" --version | grep -q "GNU tar" || { echo "GNU_TAR=$GNU_TAR is not GNU tar"; exit 1; }
"$BSD_TAR" --version | grep -q "bsdtar" || { echo "BSD_TAR=$BSD_TAR is not bsdtar"; exit 1; }
# scripts/tvlist.sh runs `tar`: GNU tar first on PATH.
ln -s "$(command -v "$GNU_TAR")" "$W/bin/tar"
export PATH="$W/bin:$PATH"
"$ROC" build --opt=speed "$HERE/tests/tools/tarwrite.roc" --output="$W/tarwrite" >/dev/null || { echo "build of tarwrite failed"; exit 1; }
"$ROC" build --opt=speed "$HERE/tests/tools/tarlist.roc" --output="$W/tarlist" >/dev/null || { echo "build of tarlist failed"; exit 1; }
FAIL=0
"$W/tarwrite" > "$W/written.tar" || { echo "tarwrite failed"; exit 1; }
if [ "${FIX:-0}" = 1 ]; then
	cp "$W/written.tar" "$F/written.tar"
	"$HERE/scripts/tvlist.sh" < "$F/written.tar" > "$F/written.list"
	echo "wrote $F/written.tar and written.list"
elif cmp -s "$W/written.tar" "$F/written.tar"; then
	echo "same bytes as tests/fixtures/written.tar"
else
	echo "DIFFERENT from tests/fixtures/written.tar"
	FAIL=1
fi
"$W/tarlist" < "$W/written.tar" > "$W/ours" 2>&1
sed -i.bak '$s/^end .*/end/' "$W/ours"
"$HERE/scripts/tvlist.sh" < "$W/written.tar" > "$W/theirs" 2>&1
if cmp -s "$W/ours" "$W/theirs"; then
	echo "same $(($(wc -l < "$W/ours") - 1)) members: tarlist and GNU tar -tv"
else
	echo "DIFFERENT: tarlist and GNU tar -tv"
	diff "$W/ours" "$W/theirs" | head -10
	FAIL=1
fi
if TMPDIR="$W/tmp" python3 -I "$HERE/tests/tools/tartools.py" "$GNU_TAR" "$BSD_TAR" "$W/written.tar" "$@" > "$W/tools" 2>&1; then
	echo "same listing and extraction: GNU tar and bsdtar ($((1 + $#)) archives)"
else
	echo "DIFFERENT: GNU tar and bsdtar"
	grep -A10 "DIFFERENT\|exit" "$W/tools" | head -20
	FAIL=1
fi
echo
[ $FAIL = 0 ] && echo "ALL SAME" || { echo "SOME DIFFERENT"; exit 1; }
