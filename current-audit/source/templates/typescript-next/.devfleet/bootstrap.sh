#!/usr/bin/env bash
set -Eeuo pipefail
npm ci || npm install
