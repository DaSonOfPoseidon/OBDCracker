#!/bin/sh
# Run before opening a PR. Lists open issues labelled with an area this branch touches, or with
# the milestone given as an argument (e.g. `scripts/pr-gate.sh M2`), and fails if there are any.
set -e
cd "$(dirname "$0")/.."
repo=DaSonOfPoseidon/OBDCracker
base=${BASE:-origin/main}

git fetch -q origin
areas=$(git diff --name-only "$base"...HEAD | while read -r path; do
	case $path in
	crates/obdcracker-core/*) echo core ;;
	crates/obdcracker-safety/*) echo safety ;;
	crates/obdcracker-transport/*) echo transport ;;
	crates/obdcracker-sim/*) echo sim ;;
	crates/obdcracker-cli/*) echo cli ;;
	crates/obdcracker/*) echo facade ;;
	*.md | docs/*) echo docs ;;
	.github/* | scripts/* | Cargo.toml | Cargo.lock | *.toml) echo ci ;;
	esac
done | sort -u)

labels=""
for area in $areas; do labels="$labels area:$area"; done
[ -n "$1" ] && labels="$labels milestone:$1"
if [ -z "$labels" ]; then
	echo "No areas touched and no milestone given; nothing to check."
	exit 0
fi

echo "Checking:$labels"
open=$(for label in $labels; do
	gh issue list -R "$repo" --state open --label "$label" --json number,title \
		--jq ".[] | \"#\\(.number) [$label] \\(.title)\""
done | sort -t' ' -k1,1 -u)
if [ -n "$open" ]; then
	echo "Open issues block this PR:"
	echo "$open"
	exit 1
fi
echo "No open issues for these labels."
