#!/usr/bin/env bash

#
# 1. List all releases and tags
# 2. Select the ones older than the last 10 entries
# 3. Iterate the list to delete them sequentially
#

last_error_code=0

for t in $(gh release list --json tagName --jq .[].tagName | tail -n+11); do
    echo "[*] Delete release and tag: ${t}";
    if ! gh release delete "${t}" --cleanup-tag --yes; then
        last_error_code=$?
    fi
done

exit $last_error_code