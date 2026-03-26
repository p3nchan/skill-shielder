#!/usr/bin/env bash
# weather.sh — Fetch weather for a city using wttr.in
set -euo pipefail

CITY="${1:-Tokyo}"
curl -s "https://wttr.in/${CITY}?format=3"
