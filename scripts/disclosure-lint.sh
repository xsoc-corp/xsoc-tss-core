#!/usr/bin/env bash
set -euo pipefail
forbidden=".disclosure-lint/forbidden.txt"
fail=0
while IFS= read -r term; do
  [ -z "$term" ] && continue
  case "$term" in \#*) continue ;; esac
  if grep -RInF -- "$term" src docs README.md 2>/dev/null; then
    echo "disclosure-lint: forbidden term present: $term"
    fail=1
  fi
done < "$forbidden"
exit $fail