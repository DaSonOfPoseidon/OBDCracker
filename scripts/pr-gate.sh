#!/bin/sh
# Run before opening a PR, with the PR's milestone if it has one: `scripts/pr-gate.sh M2`.
# Fails if an issue this branch fixes (`fixes #N` in a commit subject) is blocked by an open issue
# (GitHub's "blocked by" link) that the branch doesn't fix too; the blocker's labels don't matter.
# Then lists, without failing, the ready issues that cite a file the branch changes and are due by
# the PR's milestone (or have none), so related fixes can go in the same PR.
set -e
cd "$(dirname "$0")/.."
repo=DaSonOfPoseidon/OBDCracker
base=${BASE:-origin/main}

milestone=$(echo "${1:-}" | tr -d 'Mm')
case $milestone in
'' | *[!0-9]*) [ -n "$1" ] && { echo "usage: $0 [M<n>]" >&2; exit 2; } ;;
esac

git fetch -q origin
# --no-renames lists a moved file at both its old and new paths, so both count.
changed=$(git diff --name-only --no-renames "$base"...HEAD)

# Issues the branch's commit subjects say they fix: the word "fixes" followed by a word that is
# exactly #N. Splitting into words means "prefixes #3", "fixes #3rd" and "fixes #5_more" don't
# count, and back-to-back references ("fixes #1 fixes #2") are all found.
fixed=$(git log --format=%s "$base"..HEAD | tr -c '[:alnum:]_#\n' ' ' |
	awk '{ for (i = 1; i < NF; i++) if (tolower($i) == "fixes" && $(i + 1) ~ /^#[0-9]+$/) print substr($(i + 1), 2) }' |
	sort -un | tr '\n' ',' | sed 's/,$//')
echo "Files changed: $(echo "$changed" | grep -c .)${1:+; milestone M$milestone}${fixed:+; fixed here: #$(echo "$fixed" | sed "s/,/, #/g")}"

blocked=$(for n in $(echo "$fixed" | tr ',' ' '); do
	gh api --paginate "repos/$repo/issues/$n/dependencies/blocked_by?per_page=100" --jq "
		[${fixed}] as \$fixed
		| .[]
		| select(.state == \"open\")
		| select(.number | IN(\$fixed[]) | not)
		| \"#\\(.number) blocks #$n: \\(.title)\"
	" || exit 1
done)

# Every open, ready issue due by the PR's milestone that cites a changed file (the issues API also
# lists PRs, which are skipped). A cited path is matched whole, without any `:line` or full stop
# after it.
related=
if [ -n "$changed" ]; then
	related=$(CHANGED=$changed gh api --paginate "repos/$repo/issues?state=open&per_page=100" --jq "
		(\$ENV.CHANGED | split(\"\\n\")) as \$changed
		| ${milestone:-0} as \$m
		| [${fixed}] as \$fixed
		| .[]
		| select(.pull_request | not)
		| select(.number | IN(\$fixed[]) | not)
		| ([.labels[].name]) as \$names
		| select(\"status:blocked\" | IN(\$names[]) | not)
		| select(\"milestone:later\" | IN(\$names[]) | not)
		| ([\$names[] | select(startswith(\"milestone:M\")) | ltrimstr(\"milestone:M\") | tonumber] | min) as \$due
		| select(\$due == null or (\$m > 0 and \$due <= \$m))
		| ([(.body // \"\") | scan(\"[A-Za-z0-9_./-]+\") | sub(\"\\\\.+$\"; \"\") | select(IN(\$changed[]))] | unique) as \$cited
		| select(\$cited | length > 0)
		| \"#\\(.number) [\\(\$cited | join(\", \"))] \\(.title)\"
	")
fi
if [ -n "$related" ]; then
	echo "Related open issues you could fold in:"
	echo "$related"
fi

if [ -n "$blocked" ]; then
	echo "Open issues block this PR:"
	echo "$blocked"
	exit 1
fi
echo "No open issues block this PR."
