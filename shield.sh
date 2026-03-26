#!/usr/bin/env bash
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  Skill Shielder — Security audit for Claude Code skills and repos       ║
# ║  https://github.com/penchan-co/skill-shielder                          ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
#
# Usage:
#   shield.sh <local-path>           Audit a local directory
#   shield.sh <github-url>           Clone and audit a GitHub repo
#
# Options:
#   --verbose, -v                    Show detailed scanner output
#   --json                           Output as JSON (for programmatic use)
#   --no-repo-check                  Skip GitHub reputation check
#
# Exit codes:
#   0 = PASS    No issues found
#   1 = WARN    Non-critical issues found, review recommended
#   2 = FAIL    Critical issues found, do not install
#   3 = Error   Tool error (missing deps, bad URL, etc.)
#
# Compatible with bash 3.2+ (macOS default)

set -euo pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCANNERS_DIR="$SCRIPT_DIR/scanners"
TODAY="$(date +%Y-%m-%d)"

# ── Arguments ─────────────────────────────────────────────────────────────────
VERBOSE=0
JSON_OUTPUT=0
NO_REPO_CHECK=0
TARGET=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verbose|-v)       VERBOSE=1; shift ;;
    --json)             JSON_OUTPUT=1; shift ;;
    --no-repo-check)    NO_REPO_CHECK=1; shift ;;
    --version)          echo "Skill Shielder v${VERSION}"; exit 0 ;;
    --help|-h)
      echo "Usage: shield.sh [options] <local-path|github-url>"
      echo ""
      echo "Options:"
      echo "  --verbose, -v      Show detailed scanner output"
      echo "  --json             Output as JSON"
      echo "  --no-repo-check    Skip GitHub reputation check"
      echo "  --version          Show version"
      echo "  --help, -h         Show this help"
      exit 0
      ;;
    http*|git@*)        TARGET="$1"; shift ;;
    *)                  TARGET="$1"; shift ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Error: No target specified." >&2
  echo "Usage: shield.sh [options] <local-path|github-url>" >&2
  exit 3
fi

log() { [[ $VERBOSE -eq 1 ]] && echo "[shield] $*" >&2 || true; }

# ── Dependency checks ─────────────────────────────────────────────────────────
for cmd in grep find; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: Required command '$cmd' not found." >&2
    exit 3
  fi
done

# ── Determine mode: local vs GitHub URL ───────────────────────────────────────
IS_URL=0
SCAN_DIR=""
WORK_DIR=""
REPO_NAME=""
REPO_PATH=""

if [[ "$TARGET" == http* || "$TARGET" == git@* ]]; then
  IS_URL=1

  for cmd in git jq; do
    if ! command -v "$cmd" &>/dev/null; then
      echo "Error: '$cmd' required for URL mode." >&2
      exit 3
    fi
  done

  REPO_PATH="$(echo "$TARGET" | sed -E 's|https?://github\.com/||; s|\.git$||; s|/$||')"
  REPO_NAME="$(basename "$REPO_PATH")"

  if [[ -z "$REPO_NAME" || "$REPO_NAME" == "." ]]; then
    echo "Error: Could not parse repo from URL: $TARGET" >&2
    exit 3
  fi

  WORK_DIR="$(mktemp -d /tmp/skill-shielder-XXXXXX)"
  trap 'rm -rf "$WORK_DIR"' EXIT

  echo "Cloning ${TARGET} ..." >&2
  git clone --depth=1 --quiet "$TARGET" "$WORK_DIR/$REPO_NAME" 2>/dev/null || {
    echo "Error: Failed to clone repository." >&2
    exit 3
  }
  SCAN_DIR="$WORK_DIR/$REPO_NAME"
else
  if [[ ! -d "$TARGET" ]]; then
    echo "Error: Directory does not exist: $TARGET" >&2
    exit 3
  fi
  SCAN_DIR="$(cd "$TARGET" && pwd)"
  REPO_NAME="$(basename "$SCAN_DIR")"
fi

# ── Counters ──────────────────────────────────────────────────────────────────
TOTAL_CRITICAL=0
TOTAL_WARN=0
TOTAL_INFO=0
ALL_FINDINGS=()

# Scanner results — use indexed arrays parallel to SCANNERS
# Index: 0=prompt-injection, 1=script-safety, 2=supply-chain, 3=permissions
SC_CRITICAL=(0 0 0 0)
SC_WARN=(0 0 0 0)
SC_INFO=(0 0 0 0)

collect_findings() {
  local scanner_idx="$1"
  local output="$2"

  local crit=0 warn=0 info=0

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    ALL_FINDINGS+=("${line}")
    case "$line" in
      \[CRITICAL\]*) (( crit++ )) || true ;;
      \[WARN\]*)     (( warn++ )) || true ;;
      \[INFO\]*)     (( info++ )) || true ;;
    esac
  done <<< "$output"

  SC_CRITICAL[$scanner_idx]=$crit
  SC_WARN[$scanner_idx]=$warn
  SC_INFO[$scanner_idx]=$info

  (( TOTAL_CRITICAL += crit )) || true
  (( TOTAL_WARN += warn )) || true
  (( TOTAL_INFO += info )) || true
}

# ── File counts ───────────────────────────────────────────────────────────────
TOTAL_FILES="$(find "$SCAN_DIR" -type f ! -path '*/.git/*' ! -path '*/node_modules/*' | wc -l | tr -d ' ')"
CONTENT_FILES="$(find "$SCAN_DIR" -type f ! -path '*/.git/*' \
  \( -name '*.md' -o -name '*.json' -o -name '*.txt' -o -name '*.yaml' -o -name '*.yml' \) | wc -l | tr -d ' ')"
SCRIPT_FILES="$(find "$SCAN_DIR" -type f ! -path '*/.git/*' \
  \( -name '*.sh' -o -name '*.bash' -o -name '*.py' -o -name '*.js' -o -name '*.ts' \) | wc -l | tr -d ' ')"

log "Files: $TOTAL_FILES total, $CONTENT_FILES content, $SCRIPT_FILES scripts"

# ══════════════════════════════════════════════════════════════════════════════
# GitHub Reputation Check (URL mode only)
# ══════════════════════════════════════════════════════════════════════════════
REPO_STARS="" REPO_FORKS="" REPO_AGE="" REPO_CONTRIBUTORS=""
REPO_LAST_COMMIT="" REPO_LICENSE="" REPO_OWNER_TYPE="" REPO_IS_FORK=""
REPO_DESCRIPTION="" REPO_OPEN_ISSUES=""

if [[ "$IS_URL" -eq 1 && "$NO_REPO_CHECK" -eq 0 ]] && command -v gh &>/dev/null; then
  echo "Checking repo reputation..." >&2

  REPO_JSON="$(gh api "repos/${REPO_PATH}" 2>/dev/null)" || REPO_JSON=""

  if [[ -n "$REPO_JSON" ]]; then
    REPO_STARS="$(echo "$REPO_JSON" | jq -r '.stargazers_count')"
    REPO_FORKS="$(echo "$REPO_JSON" | jq -r '.forks_count')"
    REPO_LICENSE="$(echo "$REPO_JSON" | jq -r '.license.spdx_id // "None"')"
    REPO_OWNER_TYPE="$(echo "$REPO_JSON" | jq -r '.owner.type')"
    REPO_IS_FORK="$(echo "$REPO_JSON" | jq -r '.fork')"
    REPO_DESCRIPTION="$(echo "$REPO_JSON" | jq -r '.description // "(none)"')"
    REPO_OPEN_ISSUES="$(echo "$REPO_JSON" | jq -r '.open_issues_count')"

    CREATED_AT="$(echo "$REPO_JSON" | jq -r '.created_at')"
    PUSHED_AT="$(echo "$REPO_JSON" | jq -r '.pushed_at')"

    CREATED_EPOCH="$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$CREATED_AT" "+%s" 2>/dev/null \
      || date -d "$CREATED_AT" "+%s" 2>/dev/null || echo 0)"
    NOW_EPOCH="$(date "+%s")"
    REPO_AGE=$(( (NOW_EPOCH - CREATED_EPOCH) / 86400 ))

    PUSHED_EPOCH="$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$PUSHED_AT" "+%s" 2>/dev/null \
      || date -d "$PUSHED_AT" "+%s" 2>/dev/null || echo 0)"
    STALE_DAYS=$(( (NOW_EPOCH - PUSHED_EPOCH) / 86400 ))
    REPO_LAST_COMMIT="$(echo "$PUSHED_AT" | cut -c1-10)"

    CONTRIBUTORS_JSON="$(gh api "repos/${REPO_PATH}/contributors?per_page=100&anon=false" 2>/dev/null || echo "[]")"
    REPO_CONTRIBUTORS="$(echo "$CONTRIBUTORS_JSON" | jq 'length')"

    SECURITY_ISSUES="$(gh api "repos/${REPO_PATH}/issues?state=open&labels=security,malware,compromised&per_page=10" 2>/dev/null | jq 'length' 2>/dev/null || echo 0)"

    if [[ "$REPO_AGE" -lt 7 && "$REPO_STARS" -eq 0 ]]; then
      ALL_FINDINGS+=("[INFO] REPO  Less than 7 days old with 0 stars — unproven")
      (( TOTAL_INFO++ )) || true
    fi
    if [[ "$REPO_CONTRIBUTORS" -le 1 ]]; then
      ALL_FINDINGS+=("[WARN] REPO  Single contributor — higher supply chain risk")
      (( TOTAL_WARN++ )) || true
    fi
    if [[ "$STALE_DAYS" -gt 365 ]]; then
      ALL_FINDINGS+=("[WARN] REPO  Last commit ${STALE_DAYS} days ago — possibly abandoned")
      (( TOTAL_WARN++ )) || true
    fi
    if [[ "$SECURITY_ISSUES" -gt 0 ]]; then
      ALL_FINDINGS+=("[CRITICAL] REPO  ${SECURITY_ISSUES} open issue(s) tagged security/malware/compromised")
      (( TOTAL_CRITICAL++ )) || true
    fi
    if [[ "$REPO_IS_FORK" == "true" ]]; then
      ALL_FINDINGS+=("[INFO] REPO  This is a fork — verify changes from upstream")
      (( TOTAL_INFO++ )) || true
    fi
    if [[ "$REPO_LICENSE" == "None" || "$REPO_LICENSE" == "null" ]]; then
      ALL_FINDINGS+=("[INFO] REPO  No license detected")
      (( TOTAL_INFO++ )) || true
    fi
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# Run Scanners
# ══════════════════════════════════════════════════════════════════════════════
SCANNERS=("prompt-injection" "script-safety" "supply-chain" "permissions")

idx=0
for scanner in "${SCANNERS[@]}"; do
  scanner_script="$SCANNERS_DIR/${scanner}.sh"

  if [[ ! -x "$scanner_script" ]]; then
    log "Scanner not found or not executable: $scanner_script"
    (( idx++ )) || true
    continue
  fi

  echo "Running ${scanner} scanner..." >&2

  scanner_output=""
  scanner_output="$("$scanner_script" "$SCAN_DIR" 2>/dev/null)" || true

  if [[ -n "$scanner_output" ]]; then
    collect_findings "$idx" "$scanner_output"
  fi

  (( idx++ )) || true
done

# ══════════════════════════════════════════════════════════════════════════════
# Determine Verdict
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$TOTAL_CRITICAL" -gt 0 ]]; then
  VERDICT="FAIL"
  EXIT_CODE=2
elif [[ "$TOTAL_WARN" -gt 0 ]]; then
  VERDICT="WARN"
  EXIT_CODE=1
else
  VERDICT="PASS"
  EXIT_CODE=0
fi

# ══════════════════════════════════════════════════════════════════════════════
# Output Report
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$JSON_OUTPUT" -eq 1 ]]; then
  findings_json="["
  first=1
  for finding in "${ALL_FINDINGS[@]+"${ALL_FINDINGS[@]}"}"; do
    severity=$(echo "$finding" | sed -E 's/^\[([A-Z]+)\].*/\1/')
    message=$(echo "$finding" | sed -E 's/^\[[A-Z]+\]\s*//')
    [[ $first -eq 0 ]] && findings_json+=","
    findings_json+="{\"severity\":\"$severity\",\"message\":\"$(echo "$message" | sed 's/"/\\"/g')\"}"
    first=0
  done
  findings_json+="]"

  cat <<JSONEOF
{
  "version": "$VERSION",
  "date": "$TODAY",
  "target": "$TARGET",
  "name": "$REPO_NAME",
  "verdict": "$VERDICT",
  "summary": {
    "critical": $TOTAL_CRITICAL,
    "warn": $TOTAL_WARN,
    "info": $TOTAL_INFO
  },
  "files": {
    "total": $TOTAL_FILES,
    "content": $CONTENT_FILES,
    "scripts": $SCRIPT_FILES
  },
  "findings": $findings_json
}
JSONEOF

else
  echo ""
  echo "# Skill Shielder Report"
  echo ""
  echo "**Target**: ${REPO_NAME} (${TARGET})"
  echo "**Date**: ${TODAY}"
  echo "**Verdict**: **${VERDICT}**"
  echo ""

  echo "## Summary"
  echo ""
  echo "| Scanner | CRITICAL | WARN | INFO |"
  echo "|---------|----------|------|------|"
  idx=0
  for scanner in "${SCANNERS[@]}"; do
    printf "| %-15s | %-8s | %-4s | %-4s |\n" \
      "$scanner" \
      "${SC_CRITICAL[$idx]}" \
      "${SC_WARN[$idx]}" \
      "${SC_INFO[$idx]}"
    (( idx++ )) || true
  done
  echo ""
  echo "**Total**: ${TOTAL_CRITICAL} CRITICAL | ${TOTAL_WARN} WARN | ${TOTAL_INFO} INFO"
  echo "**Files scanned**: ${TOTAL_FILES} total (${CONTENT_FILES} content, ${SCRIPT_FILES} scripts)"
  echo ""

  if [[ "$IS_URL" -eq 1 && -n "$REPO_STARS" ]]; then
    echo "## Repo Reputation"
    echo ""
    echo "| Metric | Value |"
    echo "|--------|-------|"
    echo "| Stars | ${REPO_STARS} |"
    echo "| Forks | ${REPO_FORKS} |"
    echo "| Age | ${REPO_AGE} days |"
    echo "| Contributors | ${REPO_CONTRIBUTORS} |"
    echo "| Last commit | ${REPO_LAST_COMMIT} |"
    echo "| License | ${REPO_LICENSE} |"
    echo "| Owner type | ${REPO_OWNER_TYPE} |"
    echo "| Is fork | ${REPO_IS_FORK} |"
    echo "| Description | ${REPO_DESCRIPTION} |"
    echo ""
  fi

  echo "## Findings"
  echo ""
  if [[ ${#ALL_FINDINGS[@]} -eq 0 ]]; then
    echo "No issues detected."
  else
    for finding in "${ALL_FINDINGS[@]}"; do
      echo "- ${finding}"
    done
  fi
  echo ""

  echo "## Recommendation"
  echo ""
  case "$VERDICT" in
    PASS) echo "No significant issues found. Safe to install." ;;
    WARN) echo "Non-critical issues detected. Review the WARN findings above before proceeding. Requires explicit user confirmation to install." ;;
    FAIL) echo "**CRITICAL issues detected. Do NOT install.** Review findings and contact the skill author for clarification." ;;
  esac

  echo ""
  echo "---"
  echo "_Generated by [Skill Shielder](https://github.com/penchan-co/skill-shielder) v${VERSION}_"
fi

exit "$EXIT_CODE"
