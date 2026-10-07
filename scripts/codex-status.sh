#!/bin/sh
# Sets the `codex-review` commit status on a PR's head commit:
#   success  Codex completed a review of the head commit, and every Codex review thread is resolved
#   failure  a Codex thread is unresolved, or Codex's review failed
#   pending  no completed review of the head commit yet
# Resolve a thread once its finding is fixed, or answered with why it doesn't apply.
# Usage: scripts/codex-status.sh <pr>. With DRY_RUN=1 it prints the status instead of setting it.
# Needs `gh` (authenticated, or GH_TOKEN) and REPO (defaults to this repository).
set -eu
pr=$1
repo=${REPO:-DaSonOfPoseidon/OBDCracker}
bot='chatgpt-codex-connector[bot]'
owner=${repo%/*}
name=${repo#*/}

# HEAD_SHA checks another commit instead, for testing against past reviews with DRY_RUN=1.
head=${HEAD_SHA:-$(gh api "repos/$repo/pulls/$pr" --jq .head.sha)}
short=$(echo "$head" | cut -c1-7)

# Codex keeps one summary comment per PR and edits it as reviews run. Its Code Review row names
# the commit it reviewed and the status.
row=$(gh api --paginate "repos/$repo/issues/$pr/comments" \
	--jq ".[] | select(.user.login == \"$bot\") | select(.body | contains(\"codex-pull-request-review-summary\")) | .body" |
	grep 'Code Review' | grep -F "\`$short\`" || true)

# Unresolved review threads Codex started, on any commit. GraphQL drops the [bot] suffix.
findings=$(gh api graphql --paginate -F owner="$owner" -F name="$name" -F pr="$pr" -f query='
	query($owner: String!, $name: String!, $pr: Int!, $endCursor: String) {
		repository(owner: $owner, name: $name) {
			pullRequest(number: $pr) {
				reviewThreads(first: 100, after: $endCursor) {
					pageInfo { hasNextPage endCursor }
					nodes { isResolved comments(first: 1) { nodes { author { login } } } }
				}
			}
		}
	}' --jq '.data.repository.pullRequest.reviewThreads.nodes[]
		| select(.isResolved | not)
		| select(.comments.nodes[0].author.login == "chatgpt-codex-connector")
		| 1' | wc -l | tr -d ' ')

if [ "$findings" -gt 0 ]; then
	state=failure
	description="$findings unresolved Codex thread(s); fix or answer each, then resolve it"
elif echo "$row" | grep -q 'Completed'; then
	state=success
	description="Codex reviewed $short with no findings"
elif echo "$row" | grep -qiE 'Failed|Error'; then
	state=failure
	description="Codex's review of $short failed; ask for another with @codex review"
else
	state=pending
	description="Waiting for Codex to review $short"
fi

if [ "${DRY_RUN:-}" = 1 ]; then
	echo "$state: $description ($head)"
	exit 0
fi
gh api --silent "repos/$repo/statuses/$head" \
	-f state="$state" -f context=codex-review -f description="$description" \
	-f target_url="https://github.com/$repo/pull/$pr"
echo "$state: $description"
