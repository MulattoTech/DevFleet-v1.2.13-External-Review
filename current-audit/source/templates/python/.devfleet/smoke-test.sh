#!/usr/bin/env bash
set -Eeuo pipefail
test -f README.md
test -f compose.yaml
test -f .devcontainer/devcontainer.json
test -f .devfleet/project.json -o -f .devfleet/template.json
echo "Template smoke test passed."
