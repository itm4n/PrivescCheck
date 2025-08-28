#!/usr/bin/env bash

#
# USAGE:
#    ./commit_and_push.sh <GH_USER_ID> <GH_USER_NAME>
#
# EXIT CODES:
#    0  - Success
#    1  - Invalid number of arguments
#    2  - Not a git repository
#    3  - Nothing to commit
#    4  - Failed to commit changes
#    5  - Failed to push changes
#

if [[ $# -lt 2 ]]; then
    echo "[-] Not enough arguments."
    exit 1
fi

github_id=$1
github_name=$2

echo "[*] Current status of the repository:"
if ! git status -b -s; then
    echo "[-] No a git repository."
    exit 2
fi

if [[ -n "$(git diff)" ]]; then
    echo "[*] Pending changes need to be committed and pushed."
    git config user.name "${github_name}"
    git config user.email "${github_id}+${github_name}@users.noreply.github.com"
    git add .
    if ! git commit -m "Update data files (job)"; then
        echo "[-] Failed to commit changes"
        exit 4
    fi
    if ! git push; then
        echo "[-] Failed to push changes"
        exit 5
    fi
else
    echo "[*] No pending changes."
    exit 3
fi
