#!/usr/bin/env bash
# Fail CI when a source change uses an outdated Go toolchain.
set -euo pipefail

latest="$(
  curl --fail --silent --show-error --location --retry 3 --max-time 20 \
    'https://go.dev/dl/?mode=json' \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)[0]["version"].removeprefix("go"))'
)"
if [[ ! "$latest" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::Unexpected Go release version: $latest"
  exit 1
fi

declared="$(sed -n 's/^go \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$/\1/p' go.mod)"
builder="$(sed -n 's/^FROM golang:\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)-alpine AS build$/\1/p' Dockerfile)"

if [[ "$declared" != "$latest" || "$builder" != "$latest" ]]; then
  echo "::error::Latest stable Go is $latest, but go.mod=$declared and Dockerfile=$builder."
  echo "Update both go.mod and Dockerfile to Go $latest before merging code changes."
  exit 1
fi

echo "Go toolchain is current: $latest"
