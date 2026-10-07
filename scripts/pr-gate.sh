#!/bin/sh
# Run before opening a PR, with the PR's milestone if it has one: `scripts/pr-gate.sh M2`.
# Fails if an open issue blocks it: one tagged with an area this branch touches whose milestone is
# the PR's, an earlier one, or none. Issues tagged with the PR's milestone block it in any area.
# Issues for later milestones wait for their own milestone. Issues this branch's commits fix
# (`fixes #N`) don't count; they close when the PR merges.
set -e
cd "$(dirname "$0")/.."
repo=DaSonOfPoseidon/OBDCracker
base=${BASE:-origin/main}

# Reads paths on stdin and prints the area each one belongs to.
areas_of() {
	while read -r path; do
		# Each kind of area is matched on its own, so a path gets every area it belongs to
		# (a crate's README.md is both its crate and docs).
		case $path in
		crates/obdcracker-core/*) echo core ;;
		crates/obdcracker-safety/*) echo safety ;;
		crates/obdcracker-transport/*) echo transport ;;
		crates/obdcracker-sim/*) echo sim ;;
		crates/obdcracker-cli/*) echo cli ;;
		crates/obdcracker/*) echo facade ;;
		esac
		case $path in
		*.md | docs/*) echo docs ;;
		esac
		case $path in
		.github/* | scripts/* | *.toml | Cargo.lock) echo ci ;;
		esac
	done | sort -u
}

# `--areas-of <path>...` prints the areas for those paths, to check the mapping.
if [ "$1" = --areas-of ]; then
	shift
	printf '%s\n' "$@" | areas_of | tr '\n' ' '
	echo
	exit 0
fi

git fetch -q origin
# --no-renames lists a moved file at both its old and new paths, so both areas count.
areas=$(git diff --name-only --no-renames "$base"...HEAD | areas_of)

# `fixes #N` as a whole word, so "prefixes #3" doesn't count.
fixed=$(git log --format=%s "$base"..HEAD | grep -oiE '(^|[^[:alnum:]_])fixes #[0-9]+' | grep -oE '#[0-9]+' | tr -d '#' | sort -u | tr '\n' ',' | sed 's/,$//')
milestone=$(echo "${1:-}" | tr -d 'Mm')
case $milestone in
'' | *[!0-9]*) [ -n "$1" ] && { echo "usage: $0 [M<n>]" >&2; exit 2; } ;;
esac
echo "Areas touched: $(echo $areas | tr ' ' ',')${1:+; milestone M$milestone}${fixed:+; fixed here: #$(echo "$fixed" | sed "s/,/, #/g")}"

open=$(gh issue list -R "$repo" --state open --limit 500 --json number,title,labels --jq "
	(\"$(echo $areas)\" | split(\" \") | map(\"area:\" + .)) as \$areas
	| ${milestone:-0} as \$m
	| [${fixed}] as \$fixed
	| .[]
	| select(.number | IN(\$fixed[]) | not)
	| ([.labels[].name] ) as \$names
	| ([\$names[] | select(startswith(\"milestone:M\")) | ltrimstr(\"milestone:M\") | tonumber] | min) as \$due
	| select(
		(\$m > 0 and \$due == \$m)
		or (([\$names[] | select(IN(\$areas[]))] | length > 0)
			and (\$due == null or (\$m > 0 and \$due <= \$m)))
	)
	| \"#\\(.number) [\\(\$names | map(select(startswith(\"area:\") or startswith(\"milestone:\"))) | join(\", \"))] \\(.title)\"
")
if [ -n "$open" ]; then
	echo "Open issues block this PR:"
	echo "$open"
	exit 1
fi
echo "No open issues block this PR."
