#!/usr/bin/env bash

cur_date="$(date +%Y.%m.%d)"
cur_tag="$(git tag -l --sort=-creatordate | head -n 1 | grep -s $cur_date)"
if [ $? -eq 0 ]; then
    cur_tag_arr=(${cur_tag//-/ })
    iter=$((${cur_tag_arr[1]}+1))
else
    iter=1
fi
echo -n "${cur_date}-${iter}"