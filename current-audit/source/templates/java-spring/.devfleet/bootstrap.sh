#!/usr/bin/env bash
set -Eeuo pipefail
mvn -B -ntp dependency:go-offline
