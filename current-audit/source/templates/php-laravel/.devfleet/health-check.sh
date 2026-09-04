#!/usr/bin/env bash
set -Eeuo pipefail
test -d .devfleet
./.devfleet/smoke-test.sh
