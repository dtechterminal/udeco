#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# release-notes.sh TAG: prints CHANGELOG.md's section for TAG (from its
# "## TAG (" heading to the next "## " heading, both excluded) with the
# changelog's preamble about statuses dropped. Fails when the section is
# missing or empty, so a release can't go out without its notes.
set -eu
tag=${1:?usage: release-notes.sh TAG}
cd "$(dirname "$0")/.."
notes=$(awk -v h="## $tag (" '
	index($0, h) == 1 { on = 1; next }
	on && /^## / { exit }
	on { print }
' CHANGELOG.md)
if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
	echo "release-notes: CHANGELOG.md has no \"## $tag (YYYY-MM-DD)\" section" >&2
	exit 1
fi
printf '%s\n' "$notes"
