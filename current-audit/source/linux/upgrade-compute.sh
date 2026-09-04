#!/usr/bin/env bash
set -Eeuo pipefail
sudo bash "${1:?payload}/linux/bootstrap-compute.sh" "$1"
