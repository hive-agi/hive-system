#!/usr/bin/env bash
set -euo pipefail
workflow="$(dirname "$0")/../.github/workflows/release.yml"
step_line() { grep -n -F -- "- name: $1" "$workflow" | head -1 | cut -d: -f1; }
tests=$(step_line 'Run tests')
bump=$(step_line 'Bump patch version')
deploy=$(step_line 'Deploy')
tag=$(step_line 'Commit and tag')
(( tests < bump && bump < deploy && deploy < tag ))
grep -Fq 'if git show-ref --verify --quiet "refs/tags/v$VER"; then' "$workflow"
grep -Fq 'test "$(git rev-parse "v$VER^{}")" = "$(git rev-parse HEAD)"' "$workflow"
grep -Fq 'if ! git diff --cached --quiet; then' "$workflow"
printf 'release workflow: 4 assertions passed\n'
