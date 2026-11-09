#!/bin/sh
# Tests how scripts/install.sh turns --ref into a commit, against a fake GitHub API: a fake curl (or
# wget) first on PATH answers each commit lookup from a table and logs every URL it is asked for.
# Run it from anywhere: scripts/tests/install-ref.sh

set -eu

here=$(cd "$(dirname "$0")" && pwd)
install=$here/../install.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
sh_bin=$(command -v sh)
fails=0

A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	fails=$((fails + 1))
}

# main runs on the script's last line; everything before it is functions the tests can call.
[ "$(tail -n 1 "$install")" = 'main "$@"' ] || fail "install.sh no longer ends with main \"\$@\""
sed '$d' "$install" >"$work/lib.sh"
mkdir "$work/tmp" "$work/curl-bin" "$work/wget-bin" "$work/e2e-bin"

# The fake answers `commits/<name>` from $FAKE_TABLE, whose lines are `<name> <status> <body>`; a
# name that isn't listed gets 422, which is what GitHub says for a ref it doesn't have. A status of
# `net` is a transport failure with no HTTP answer.
cat >"$work/curl-bin/curl" <<'EOF'
#!/bin/sh
out= url=
while [ $# -gt 0 ]; do
	case $1 in
	-o) out=$2 && shift ;;
	-w | -H | --proto) shift ;;
	-*) ;;
	*) url=$1 ;;
	esac
	shift
done
printf '%s\n' "$url" >>"$FAKE_LOG"
case $url in
https://api.github.com/repos/*/commits/*)
	name=${url#*/commits/}
	status=422 body=
	while read -r key st sha; do
		if [ "$key" = "$name" ]; then
			status=$st body=$sha
		fi
	done <"$FAKE_TABLE"
	[ "$status" != net ] || exit 6
	printf '%s' "$body" >"$out"
	printf '%s' "$status"
	;;
https://codeload.github.com/*) exit 22 ;;
esac
EOF
cat >"$work/wget-bin/wget" <<'EOF'
#!/bin/sh
out= url=
while [ $# -gt 0 ]; do
	case $1 in
	-O) out=$2 && shift ;;
	--header=* | -*) ;;
	*) url=$1 ;;
	esac
	shift
done
printf '%s\n' "$url" >>"$FAKE_LOG"
name=${url#*/commits/}
status=422 body=
while read -r key st sha; do
	if [ "$key" = "$name" ]; then
		status=$st body=$sha
	fi
done <"$FAKE_TABLE"
[ "$status" != net ] || exit 4
printf '  HTTP/1.1 %s Whatever\n' "$status" >&2
[ "$status" = 200 ] || exit 8
printf '%s' "$body" >"$out"
EOF
# A wget-only machine: the PATH holds just the fake and what resolve_ref itself runs
for tool in sed cat tail; do
	ln -s "$(command -v "$tool")" "$work/wget-bin/$tool"
done
# cc and rustup are the machine-wide parts of install.sh, so the end-to-end runs fake them
cp "$work/curl-bin/curl" "$work/e2e-bin/curl"
printf '#!/bin/sh\nexit 0\n' >"$work/e2e-bin/cc"
cp "$work/e2e-bin/cc" "$work/e2e-bin/rustup"
chmod +x "$work/curl-bin/curl" "$work/wget-bin/wget" "$work/e2e-bin/curl" "$work/e2e-bin/cc" "$work/e2e-bin/rustup"

# table LINE...: the API's answers for the next run, and an empty request log
table() {
	: >"$work/table"
	for line in "$@"; do
		printf '%s\n' "$line" >>"$work/table"
	done
	: >"$work/log"
}

# resolve TOOL REF [early]: runs resolve_ref with the fake TOOL; sets $status and fills $work/out
resolve() {
	tool=$1 ref=$2 early=${3:-}
	status=0
	if [ "$tool" = wget ]; then
		path=$work/wget-bin
	else
		path=$work/curl-bin:$PATH
	fi
	# shellcheck disable=SC2016 # the script is for the inner shell to expand
	FAKE_LOG=$work/log FAKE_TABLE=$work/table PATH=$path "$sh_bin" -c \
		'. "$1"; TMP=$2; REF=$3; COMMIT=; resolve_ref $4; printf "COMMIT=%s\n" "$COMMIT"' \
		sh "$work/lib.sh" "$work/tmp" "$ref" "$early" >"$work/out" 2>&1 || status=$?
}

# Each check names what it expects; $name is the case's label
ok_commit() {
	[ "$status" -eq 0 ] || fail "$name: exited $status: $(cat "$work/out")"
	grep -qx "COMMIT=$1" "$work/out" || fail "$name: wanted COMMIT=$1, got: $(cat "$work/out")"
}
dies() {
	[ "$status" -eq 1 ] || fail "$name: wanted exit 1, got $status: $(cat "$work/out")"
	grep -q "$1" "$work/out" || fail "$name: message lacks '$1': $(cat "$work/out")"
	if grep -q '^COMMIT=' "$work/out"; then fail "$name: kept going after the error"; fi
}
# looked_up URL...: the requests that were made, exactly and in order
looked_up() {
	: >"$work/want"
	for name_ in "$@"; do
		printf 'https://api.github.com/repos/DaSonOfPoseidon/OBDCracker/commits/%s\n' "$name_" >>"$work/want"
	done
	cmp -s "$work/want" "$work/log" || fail "$name: wanted lookups '$*', got: $(tr '\n' ' ' <"$work/log")"
}

for tool in curl wget; do
	name="$tool tag only"
	table "refs/tags/v1 200 $A"
	resolve "$tool" v1
	ok_commit "$A"
	looked_up refs/tags/v1 refs/heads/v1

	name="$tool branch only"
	table "refs/heads/dev 200 $B"
	resolve "$tool" dev
	ok_commit "$B"
	looked_up refs/tags/dev refs/heads/dev

	name="$tool both a tag and a branch"
	table "refs/tags/v1 200 $A" "refs/heads/v1 200 $B"
	resolve "$tool" v1
	dies 'refs/tags/v1'
	dies 'refs/heads/v1'
	dies 'commit hash'

	name="$tool a 404 counts as not found"
	table "refs/tags/v1 404" "refs/heads/v1 200 $B"
	resolve "$tool" v1
	ok_commit "$B"

	name="$tool neither, so a short hash"
	table "abc1234 200 $B"
	resolve "$tool" abc1234
	ok_commit "$B"
	looked_up refs/tags/abc1234 refs/heads/abc1234 abc1234

	name="$tool neither and not a hash"
	table
	resolve "$tool" nonsense
	dies "couldn't find"
	looked_up refs/tags/nonsense refs/heads/nonsense nonsense

	name="$tool server error on the tag lookup"
	table "refs/tags/v1 500" "refs/heads/v1 200 $B"
	resolve "$tool" v1
	dies 'HTTP 500'
	looked_up refs/tags/v1

	name="$tool rate limit on the branch lookup"
	table "refs/tags/v1 200 $A" "refs/heads/v1 403"
	resolve "$tool" v1
	dies 'HTTP 403'
	looked_up refs/tags/v1 refs/heads/v1

	name="$tool server error on the fallback lookup"
	table "abc1234 502"
	resolve "$tool" abc1234
	dies 'HTTP 502'

	name="$tool a full tag ref"
	table "refs/tags/v1 200 $A" "refs/heads/v1 200 $B"
	resolve "$tool" refs/tags/v1
	ok_commit "$A"
	looked_up refs/tags/v1

	name="$tool a full branch ref"
	table "refs/tags/v1 200 $A" "refs/heads/v1 200 $B"
	resolve "$tool" refs/heads/v1
	ok_commit "$B"
	looked_up refs/heads/v1

	name="$tool a full ref that doesn't exist"
	table "v1 200 $A"
	resolve "$tool" refs/tags/v1
	dies "couldn't find"
	looked_up refs/tags/v1

	name="$tool a full commit hash"
	table
	resolve "$tool" "$A"
	ok_commit "$A"
	looked_up

	name="$tool a 40-character hash in upper case still goes through the lookups"
	upper=$(printf '%s' "$A" | tr a-f A-F)
	table "$upper 200 $A"
	resolve "$tool" "$upper"
	ok_commit "$A"
	looked_up "refs/tags/$upper" "refs/heads/$upper" "$upper"

	for len in 39 41; do
		name="$tool a $len-character hash"
		hash=$(printf '%s' "${A}a" | cut -c1-"$len")
		table
		resolve "$tool" "$hash"
		dies "couldn't find"
		looked_up "refs/tags/$hash" "refs/heads/$hash" "$hash"
	done

	name="$tool no answer at all, early"
	table "refs/tags/v1 net"
	resolve "$tool" v1 early
	ok_commit ''
	looked_up refs/tags/v1

	name="$tool no answer at all, not early"
	table "refs/tags/v1 net"
	resolve "$tool" v1
	dies "couldn't look up"

	name="$tool server error, early"
	table "refs/tags/v1 500"
	resolve "$tool" v1 early
	dies 'HTTP 500'

	name="$tool an answer that isn't a hash"
	table "refs/tags/v1 200 not-a-hash"
	resolve "$tool" v1
	dies "isn't a commit hash"
done

# The whole script, with a fake cc and rustup so the machine isn't touched: it stops at the download
if [ "$(uname -s)" = Linux ]; then
	e2e() {
		status=0
		mkdir -p "$work/home" "$work/src"
		: >"$work/src/Cargo.toml"
		: >"$work/src/rust-toolchain.toml"
		HOME=$work/home XDG_DATA_HOME=$work/data CARGO_HOME=$work/cargo FAKE_LOG=$work/log \
			FAKE_TABLE=$work/table PATH=$work/e2e-bin:$PATH "$sh_bin" "$install" "$@" >"$work/out" 2>&1 || status=$?
	}

	name="install.sh --ref builds the commit it resolved"
	table "refs/heads/dev 200 $B"
	e2e --ref dev --dir "$work/data"
	dies "couldn't download commit $B of dev"
	grep -qx "https://codeload.github.com/DaSonOfPoseidon/OBDCracker/tar.gz/$B" "$work/log" || fail "$name: no download of $B"
	[ "$(grep -c 'api.github.com' "$work/log")" -eq 2 ] || fail "$name: the lookup ran more than once: $(cat "$work/log")"

	name="install.sh with a commit hash makes no lookup"
	table
	e2e --ref $A --dir "$work/data"
	dies "couldn't download commit $A"
	! grep -q 'api.github.com' "$work/log" || fail "$name: asked the API: $(cat "$work/log")"

	name="install.sh --source makes no lookup"
	table
	e2e --source "$work/src" --dir "$work/data"
	dies "toolchain channel"
	! grep -q 'api.github.com' "$work/log" || fail "$name: asked the API: $(cat "$work/log")"

	name="install.sh refuses a ref that is both"
	table "refs/tags/v1 200 $A" "refs/heads/v1 200 $B"
	e2e --ref v1 --dir "$work/data"
	dies 'refs/heads/v1'
	! grep -q 'codeload' "$work/log" || fail "$name: downloaded anyway: $(cat "$work/log")"
fi

if [ "$fails" -ne 0 ]; then
	printf '%s check(s) failed\n' "$fails" >&2
	exit 1
fi
echo "install-ref: all checks passed"
