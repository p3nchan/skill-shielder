#!/usr/bin/env bash
# prompt-injection.sh — Scans content files for prompt injection and hidden instructions.
#
# Scans: .md, .json, .txt, .yaml, .yml
#
# Usage:
#   prompt-injection.sh [--flagged-only] <path|file>
#
# Output: [SEVERITY] relative/path:linenum  [pattern_id]  preview
# Exit:   0=clean, 1=WARN found, 2=CRITICAL found

set -euo pipefail

FLAGGED_ONLY=0
TARGET=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --flagged-only|-f) FLAGGED_ONLY=1; shift ;;
    *) TARGET="$1"; shift ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Usage: prompt-injection.sh [--flagged-only] <path|file>" >&2
  exit 1
fi

if [[ ! -e "$TARGET" ]]; then
  echo "Error: Path does not exist: $TARGET" >&2
  exit 1
fi

# ── Result tracking ─────────────────────────────────────────────────────────
CRITICAL_COUNT=0
WARN_COUNT=0
MAX_SEVERITY=0  # 0=clean, 1=warn, 2=critical

emit() {
  local severity="$1"
  local file="$2"
  local lineno="$3"
  local pattern_id="$4"
  local preview="$5"

  preview="${preview:0:120}"

  if [[ "$FLAGGED_ONLY" -eq 1 && "$severity" == "INFO" ]]; then
    return
  fi

  echo "[${severity}] ${file}:${lineno}  [${pattern_id}]  ${preview}"

  case "$severity" in
    CRITICAL)
      (( CRITICAL_COUNT++ )) || true
      [[ $MAX_SEVERITY -lt 2 ]] && MAX_SEVERITY=2 || true
      ;;
    WARN)
      (( WARN_COUNT++ )) || true
      [[ $MAX_SEVERITY -lt 1 ]] && MAX_SEVERITY=1 || true
      ;;
  esac
}

# ── Core scanner ─────────────────────────────────────────────────────────────
scan_file() {
  local file="$1"
  local rel="$2"

  # Pattern 1: Classic prompt injection overrides (CRITICAL)
  while IFS=: read -r lineno match; do
    [[ -z "$lineno" ]] && continue
    emit CRITICAL "$rel" "$lineno" "PROMPT_OVERRIDE" "$match"
  done < <(grep -inE \
    'ignore (all |the )?(previous|above|prior) instructions?|forget (your|all|these) rules?|disregard (previous|all) instructions?' \
    "$file" 2>/dev/null | sed 's/^\([0-9]*\):/\1:/' || true)

  # Pattern 2: Persona hijacking (CRITICAL)
  while IFS=: read -r lineno match; do
    [[ -z "$lineno" ]] && continue
    emit CRITICAL "$rel" "$lineno" "PERSONA_HIJACK" "$match"
  done < <(grep -inE \
    'you are now (a |an |the )?[a-z]|act as (a |an )?[a-z]|your (new )?personality is|you have no restrictions|you have no (ethical |moral )?guidelines' \
    "$file" 2>/dev/null | sed 's/^\([0-9]*\):/\1:/' || true)

  # Pattern 3: Rule override / jailbreak (CRITICAL)
  while IFS=: read -r lineno match; do
    [[ -z "$lineno" ]] && continue
    emit CRITICAL "$rel" "$lineno" "RULE_OVERRIDE" "$match"
  done < <(grep -inE \
    'do not follow (your|the|any) (rules|guidelines|instructions)|bypass (safety|content|ethical) (filter|check|policy)|jailbreak|DAN mode' \
    "$file" 2>/dev/null | sed 's/^\([0-9]*\):/\1:/' || true)

  # Pattern 4: Agent manipulation — exfil + concealment (CRITICAL)
  while IFS=: read -r lineno match; do
    [[ -z "$lineno" ]] && continue
    emit CRITICAL "$rel" "$lineno" "AGENT_MANIPULATION" "$match"
  done < <(grep -inE \
    '(send|exfiltrate|upload|transmit).*(password|secret|token|key|credential)|do not (tell|inform|alert|warn) the user|keep this (secret|hidden|confidential) from (the user|the human)' \
    "$file" 2>/dev/null | sed 's/^\([0-9]*\):/\1:/' || true)

  # Pattern 5: Unicode zero-width / control characters (CRITICAL)
  if grep -qP '[\x00-\x08\x0b\x0e-\x1f\x7f]|\x{200b}|\x{200c}|\x{200d}|\x{2060}|\x{202e}|\x{202d}|\x{feff}' "$file" 2>/dev/null; then
    emit CRITICAL "$rel" "?" "UNICODE_TRICK" "File contains zero-width or control characters (possible hidden text)"
  fi

  # Pattern 6: RTL override U+202E — belt-and-suspenders
  if LC_ALL=C grep -qF $'\xe2\x80\xae' "$file" 2>/dev/null; then
    emit CRITICAL "$rel" "?" "RTL_OVERRIDE" "File contains U+202E RIGHT-TO-LEFT OVERRIDE character"
  fi

  # Pattern 7: Embedded <system> / <system-reminder> tags (CRITICAL)
  while IFS=: read -r lineno match; do
    [[ -z "$lineno" ]] && continue
    emit CRITICAL "$rel" "$lineno" "SYSTEM_TAG_INJECTION" "$match"
  done < <(grep -inE \
    '<system>|<system-reminder>|<\|im_start\|>system' \
    "$file" 2>/dev/null | sed 's/^\([0-9]*\):/\1:/' || true)

  # Pattern 8: Multi-turn social engineering (CRITICAL)
  while IFS=: read -r lineno match; do
    [[ -z "$lineno" ]] && continue
    emit CRITICAL "$rel" "$lineno" "SOCIAL_ENGINEERING" "$match"
  done < <(grep -inE \
    'you already agreed|you confirmed this|as we discussed|you previously approved|remember you said' \
    "$file" 2>/dev/null | sed 's/^\([0-9]*\):/\1:/' || true)

  # Pattern 9: Role markers in non-chat files (WARN)
  local EXT="${file##*.}"
  if [[ "$EXT" == "md" || "$EXT" == "yaml" || "$EXT" == "yml" ]]; then
    while IFS=: read -r lineno match; do
      [[ -z "$lineno" ]] && continue
      emit WARN "$rel" "$lineno" "ROLE_MARKER" "$match"
    done < <(grep -inE \
      '^(system|assistant|user)\s*:' \
      "$file" 2>/dev/null | sed 's/^\([0-9]*\):/\1:/' || true)
  fi

  # Pattern 10: Suspiciously long HTML comments (WARN)
  while IFS=: read -r lineno match; do
    [[ -z "$lineno" ]] && continue
    emit WARN "$rel" "$lineno" "HIDDEN_COMMENT" "$match"
  done < <(grep -nE '<!--.{30,}-->' "$file" 2>/dev/null | head -20 || true)

  # Pattern 11: Large base64 blobs in content files (WARN)
  if [[ "$EXT" == "md" || "$EXT" == "yaml" || "$EXT" == "yml" || "$EXT" == "txt" ]]; then
    while IFS=: read -r lineno match; do
      [[ -z "$lineno" ]] && continue
      emit WARN "$rel" "$lineno" "BASE64_BLOB" "Large base64-like string (${#match} chars)"
    done < <(grep -nE '[A-Za-z0-9+/]{80,}={0,2}' "$file" 2>/dev/null | head -10 || true)
  fi

  # Pattern 12: Auto-approve / permission override instructions (WARN)
  while IFS=: read -r lineno match; do
    [[ -z "$lineno" ]] && continue
    emit WARN "$rel" "$lineno" "PERMISSION_OVERRIDE" "$match"
  done < <(grep -inE \
    'always (approve|allow|accept|permit)|auto.?approve|skip (confirm|review|approval)|without (asking|confirmation|permission)' \
    "$file" 2>/dev/null | sed 's/^\([0-9]*\):/\1:/' || true)

  # Pattern 13: postInstall references (INFO)
  while IFS=: read -r lineno match; do
    [[ -z "$lineno" ]] && continue
    emit INFO "$rel" "$lineno" "POST_INSTALL_HOOK" "$match"
  done < <(grep -inE \
    'postInstall|post_install|postinstall|after_install|on_install' \
    "$file" 2>/dev/null | sed 's/^\([0-9]*\):/\1:/' || true)
}

# ── Walk target path ─────────────────────────────────────────────────────────
if [[ -f "$TARGET" ]]; then
  scan_file "$TARGET" "$(basename "$TARGET")"
elif [[ -d "$TARGET" ]]; then
  while IFS= read -r -d '' file; do
    rel="${file#${TARGET}/}"
    scan_file "$file" "$rel"
  done < <(find "$TARGET" -type f ! -path '*/.git/*' \
    \( -name '*.md' -o -name '*.json' -o -name '*.txt' \
       -o -name '*.yaml' -o -name '*.yml' \) \
    -print0)
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo "" >&2
echo "Prompt injection scan: ${CRITICAL_COUNT} CRITICAL | ${WARN_COUNT} WARN" >&2

exit "$MAX_SEVERITY"
