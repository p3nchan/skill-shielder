#!/usr/bin/env bash
# permissions.sh — Analyzes what file paths and network endpoints a skill accesses.
#
# Compatible with bash 3.2+ (macOS default). Uses temp files instead of associative arrays.
#
# Usage:
#   permissions.sh <path>
#
# Output: [SEVERITY] description
# Exit:   0=clean, 1=WARN found, 2=CRITICAL found

set -euo pipefail

TARGET="${1:-}"

if [[ -z "$TARGET" || ! -d "$TARGET" ]]; then
  echo "Usage: permissions.sh <directory>" >&2
  exit 1
fi

CRITICAL_COUNT=0
WARN_COUNT=0
INFO_COUNT=0
MAX_SEVERITY=0
FINDINGS=()

# Temp files for deduplication
TMPDIR_PERM="$(mktemp -d /tmp/shielder-perm-XXXXXX)"
trap 'rm -rf "$TMPDIR_PERM"' EXIT

SEEN_PATHS_FILE="$TMPDIR_PERM/seen_paths"
SEEN_DOMAINS_FILE="$TMPDIR_PERM/seen_domains"
SENSITIVE_REPORT="$TMPDIR_PERM/sensitive_report"
DOMAIN_REPORT="$TMPDIR_PERM/domain_report"
touch "$SEEN_PATHS_FILE" "$SEEN_DOMAINS_FILE" "$SENSITIVE_REPORT" "$DOMAIN_REPORT"

flag() {
  local severity="$1"; shift
  local message="$*"
  FINDINGS+=("[${severity}] ${message}")
  case "$severity" in
    CRITICAL) (( CRITICAL_COUNT++ )) || true; [[ $MAX_SEVERITY -lt 2 ]] && MAX_SEVERITY=2 || true ;;
    WARN)     (( WARN_COUNT++ )) || true;     [[ $MAX_SEVERITY -lt 1 ]] && MAX_SEVERITY=1 || true ;;
    INFO)     (( INFO_COUNT++ )) || true ;;
  esac
}

# ── Sensitive path categories ────────────────────────────────────────────────
SENSITIVE_PATTERNS=(
  '~/.ssh|\$HOME/.ssh|/\.ssh/'
  '~/.aws|\$HOME/.aws|/\.aws/'
  '~/.gnupg|\$HOME/.gnupg|/\.gnupg/'
  '~/.config/gh|\$HOME/.config/gh'
  '~/.config/gcloud|\$HOME/.config/gcloud'
  '~/.config/azure|\$HOME/.config/azure'
  '~/Library/Keychains|\$HOME/Library/Keychains'
  '/etc/passwd|/etc/shadow'
  '~/.bash_history|~/.zsh_history|\$HOME/.*_history'
  '~/.gitconfig|\$HOME/.gitconfig|\.git/config'
  '~/.npmrc|\$HOME/.npmrc'
  '~/.pypirc|\$HOME/.pypirc'
  '~/.docker/config|\$HOME/.docker/config'
  '~/.kube/config|\$HOME/.kube/config'
  '\.env\b'
  'id_rsa|id_ed25519|id_ecdsa'
  'credentials\.json|service.account\.json'
  'wallet\.dat|keystore'
)

SENSITIVE_LABELS=(
  "SSH keys"
  "AWS credentials"
  "GPG keys"
  "GitHub CLI credentials"
  "Google Cloud credentials"
  "Azure credentials"
  "macOS Keychain"
  "System password files"
  "Shell history"
  "Git configuration"
  "npm credentials"
  "PyPI credentials"
  "Docker credentials"
  "Kubernetes config"
  "Environment variables (.env)"
  "SSH private keys"
  "Service account credentials"
  "Crypto wallet/keystore"
)

SAFE_DOMAINS="github.com|api.github.com|githubusercontent.com|pypi.org|registry.npmjs.org|api.openai.com|api.anthropic.com|generativelanguage.googleapis.com"

# ── Scan all files ───────────────────────────────────────────────────────────
HAS_NETWORK=0
HAS_SENSITIVE=0

while IFS= read -r -d '' file; do
  rel="${file#${TARGET}/}"

  # Check each sensitive pattern
  i=0
  for pattern in "${SENSITIVE_PATTERNS[@]}"; do
    label="${SENSITIVE_LABELS[$i]}"

    if grep -qE "$pattern" "$file" 2>/dev/null; then
      if ! grep -qF "$label" "$SEEN_PATHS_FILE" 2>/dev/null; then
        echo "$label" >> "$SEEN_PATHS_FILE"
        echo "${label}|${rel}" >> "$SENSITIVE_REPORT"
      else
        # Append file to existing entry
        sed -i.bak "s|^${label}|${label}|" "$SENSITIVE_REPORT" 2>/dev/null || true
      fi
      HAS_SENSITIVE=1
    fi

    (( i++ )) || true
  done

  # Extract URLs/domains
  while IFS= read -r url; do
    domain=$(echo "$url" | sed -E 's|https?://||; s|/.*||; s|:.*||; s|".*||')
    [[ -z "$domain" ]] && continue
    [[ "$domain" == "localhost" || "$domain" == "127.0.0.1" || "$domain" == "0.0.0.0" ]] && continue

    # Skip variable references
    case "$domain" in
      \$*) continue ;;
    esac

    if ! grep -qF "$domain" "$SEEN_DOMAINS_FILE" 2>/dev/null; then
      echo "$domain" >> "$SEEN_DOMAINS_FILE"
      echo "${domain}|${rel}" >> "$DOMAIN_REPORT"
      HAS_NETWORK=1
    fi
  done < <(grep -oE 'https?://[a-zA-Z0-9._/${}:@-]+' "$file" 2>/dev/null || true)

  # Check for network calls
  if grep -qE '\b(curl|wget)\b|requests\.(get|post|put)|axios\.|fetch\(' "$file" 2>/dev/null; then
    HAS_NETWORK=1
  fi

done < <(find "$TARGET" -type f ! -path '*/.git/*' ! -path '*/node_modules/*' \
  \( -name '*.sh' -o -name '*.bash' -o -name '*.py' -o -name '*.js' -o -name '*.ts' \
     -o -name '*.md' -o -name '*.json' -o -name '*.yaml' -o -name '*.yml' \) \
  -print0 2>/dev/null)

# ── Cross-reference: sensitive access + network = exfil risk ─────────────────
if [[ "$HAS_SENSITIVE" -eq 1 && "$HAS_NETWORK" -eq 1 ]]; then
  flag CRITICAL "EXFIL_RISK  Skill accesses sensitive paths AND makes network calls — potential exfiltration"
fi

# ── Report sensitive paths ───────────────────────────────────────────────────
if [[ -s "$SENSITIVE_REPORT" ]]; then
  while IFS='|' read -r label files; do
    flag WARN "SENSITIVE_PATH  ${label} — referenced in: ${files}"
  done < "$SENSITIVE_REPORT"
fi

# ── Report external domains ──────────────────────────────────────────────────
if [[ -s "$DOMAIN_REPORT" ]]; then
  while IFS='|' read -r domain files; do
    if echo "$domain" | grep -qE "^($SAFE_DOMAINS)$"; then
      flag INFO "NETWORK  ${domain} (known service) — in: ${files}"
    else
      flag WARN "NETWORK  ${domain} (unrecognized) — in: ${files}"
    fi
  done < "$DOMAIN_REPORT"
fi

# ── Output findings ──────────────────────────────────────────────────────────
for finding in "${FINDINGS[@]+"${FINDINGS[@]}"}"; do
  echo "$finding"
done

# ── Permission scope summary (to stdout, captured by shield.sh) ──────────────
# Only print scope summary when run standalone (not captured by shield.sh)
if [[ -t 1 ]]; then
  echo ""
  echo "## Permission Scope"
  echo ""

  if [[ -s "$SENSITIVE_REPORT" ]]; then
    echo "### Sensitive Paths Accessed"
    while IFS='|' read -r label files; do
      echo "- ${label}: ${files}"
    done < "$SENSITIVE_REPORT"
  else
    echo "### Sensitive Paths Accessed"
    echo "- None detected"
  fi

  echo ""

  if [[ -s "$DOMAIN_REPORT" ]]; then
    echo "### External Network Endpoints"
    while IFS='|' read -r domain files; do
      safe_marker=""
      if echo "$domain" | grep -qE "^($SAFE_DOMAINS)$"; then
        safe_marker=" (known)"
      else
        safe_marker=" (REVIEW)"
      fi
      echo "- ${domain}${safe_marker}: ${files}"
    done < "$DOMAIN_REPORT"
  else
    echo "### External Network Endpoints"
    echo "- None detected"
  fi
fi

echo "" >&2
echo "Permission scan: ${CRITICAL_COUNT} CRITICAL | ${WARN_COUNT} WARN | ${INFO_COUNT} INFO" >&2

exit "$MAX_SEVERITY"
