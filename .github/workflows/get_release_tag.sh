#!/usr/bin/env bash

cur_date="$(date +%Y.%m.%d)"
echo "[*] Current date: ${cur_date}" >&2
latest_release_tag="$(gh release list --order desc --limit 1 --json tagName --jq .[].tagName)"
echo "[*] Latest release tag: ${latest_release_tag}" >&2
echo "${latest_release_tag}" | grep -q "${cur_date}"
if [ $? -eq 0 ]; then
    latest_release_tag_arr=(${latest_release_tag//-/ })
    iter=$((${latest_release_tag_arr[1]}+1))
else
    iter=1
fi
new_release_tag="${cur_date}-${iter}"
echo "[*] New release tag: ${new_release_tag}" >&2
echo -n "${new_release_tag}"