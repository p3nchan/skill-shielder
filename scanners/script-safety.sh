#!/usr/bin/env bash
# script-safety.sh — Scans executable files for dangerous patterns.
#
# Scans: .sh, .bash, .py, .js, .ts
#
# Usage:
#   script-safety.sh <path|file>
#
# Output: [SEVERITY] relative/path  [pattern_id]  description
# Exit:   0=clean, 1=WARN found, 2=CRITICAL found

set -euo pipefail

TARGET="${1:-}"

if [[ -z "$TARGET" || ! -e "$TARGET" ]]; then
  echo "Usage: script-safety.sh <path|file>" >&2
  exit 1
fi

CRITICAL_COUNT=0
WARN_COUNT=0
INFO_COUNT=0
MAX_SEVERITY=0
FINDINGS=()

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

scan_file() {
  local file="$1"
  local rel="$2"

  # ── CRITICAL ────────────────────────────────────────────────────────────

  # Destructive deletion
  if grep -qE 'rm\s+-rf\s+[/~]|rm\s+-rf\s+\$HOME|rm\s+-rf\s+\$\{?HOME\}?' "$file" 2>/dev/null; then
    flag CRITICAL "$rel  [DESTRUCTIVE_DELETE]  rm -rf targeting root/home directory"
  fi

  # Disk operations
  if grep -qE 'dd\s+if=.*of=/dev/|mkfs\s+.*\s+/dev/' "$file" 2>/dev/null; then
    flag CRITICAL "$rel  [DISK_OPERATION]  dd/mkfs targeting block device"
  fi

  # Pipe-to-shell (remote code execution)
  if grep -qE '(curl|wget)\s+.+\|\s*(ba)?sh' "$file" 2>/dev/null; then
    flag CRITICAL "$rel  [PIPE_TO_SHELL]  curl/wget piped to sh/bash"
  fi
  if grep -qE '(curl|wget)\s+.+\|\s*(python|node|perl|ruby)' "$file" 2>/dev/null; then
    flag CRITICAL "$rel  [PIPE_TO_INTERPRETER]  curl/wget piped to interpreter"
  fi

  # Credential exfiltration via POST
  if grep -qE 'curl\s+.*-X\s+POST.*\.(ssh|aws|gnupg|env|config/gh|config/gcloud)' "$file" 2>/dev/null; then
    flag CRITICAL "$rel  [CREDENTIAL_EXFIL]  curl POST with credential path reference"
  fi
  if grep -qE 'curl\s+.*\.(ssh|gnupg|aws|env).*-X\s+POST' "$file" 2>/dev/null; then
    flag CRITICAL "$rel  [CREDENTIAL_EXFIL]  curl POST with credential path reference"
  fi
  if grep -qE 'base64\s+.*\.(ssh|gnupg|aws).*\|\s*curl' "$file" 2>/dev/null; then
    flag CRITICAL "$rel  [CREDENTIAL_EXFIL]  base64 encode credentials then curl"
  fi

  # Obfuscated execution
  if grep -qE 'eval\s*\(.*base64|eval\s+\$\(.*base64' "$file" 2>/dev/null; then
    flag CRITICAL "$rel  [OBFUSCATED_EVAL]  eval with base64 decode"
  fi
  if grep -qE 'exec\s*\(.*base64' "$file" 2>/dev/null; then
    flag CRITICAL "$rel  [OBFUSCATED_EXEC]  exec with base64 decode"
  fi
  if grep -qE '\$\(.*base64\s+-d.*\)' "$file" 2>/dev/null; then
    flag CRITICAL "$rel  [INLINE_BASE64]  inline base64 decode and execute"
  fi
  if grep -qE 'python.*exec\s*\(.*__import__' "$file" 2>/dev/null; then
    flag CRITICAL "$rel  [PYTHON_DYNAMIC_IMPORT]  exec with dynamic __import__"
  fi

  # Reverse shell patterns
  if grep -qE 'bash\s+-i\s+>&\s*/dev/tcp|/dev/tcp/[0-9]|python.*socket.*connect.*exec|nc\s+.*-e\s+/bin/(ba)?sh' "$file" 2>/dev/null; then
    flag CRITICAL "$rel  [REVERSE_SHELL]  reverse shell pattern detected"
  fi

  # ── WARN ────────────────────────────────────────────────────────────────

  # Privilege escalation
  if grep -qE '\bsudo\b' "$file" 2>/dev/null; then
    flag WARN "$rel  [SUDO]  sudo usage — verify necessity"
  fi
  if grep -qE 'chmod\s+(a\+w|[0-9]*7[0-9][0-9]|777)' "$file" 2>/dev/null; then
    flag WARN "$rel  [WORLD_WRITABLE]  world-writable chmod"
  fi
  if grep -qE 'chmod\s+[ug]\+s' "$file" 2>/dev/null; then
    flag WARN "$rel  [SETUID]  setuid/setgid chmod"
  fi

  # Network listeners
  if grep -qE '\bnc\s+-l\b|\bncat\s+-l\b' "$file" 2>/dev/null; then
    flag WARN "$rel  [NET_LISTENER]  netcat listener (possible backdoor)"
  fi
  if grep -qE 'python.*http\.server|python.*SimpleHTTPServer' "$file" 2>/dev/null; then
    flag WARN "$rel  [HTTP_SERVER]  Python HTTP server (exposes local files)"
  fi
  if grep -qE 'socat\s+.*LISTEN' "$file" 2>/dev/null; then
    flag WARN "$rel  [SOCAT_LISTENER]  socat listener"
  fi

  # Credential path access (without POST = access only, not exfil)
  if grep -qE '~/\.ssh/|\$HOME/\.ssh/' "$file" 2>/dev/null; then
    flag WARN "$rel  [CRED_ACCESS]  references ~/.ssh/"
  fi
  if grep -qE '~/\.aws/|\$HOME/\.aws/' "$file" 2>/dev/null; then
    flag WARN "$rel  [CRED_ACCESS]  references ~/.aws/"
  fi
  if grep -qE '~/\.gnupg/|\$HOME/\.gnupg/' "$file" 2>/dev/null; then
    flag WARN "$rel  [CRED_ACCESS]  references ~/.gnupg/"
  fi
  if grep -qE '~/\.config/(gh|gcloud|azure)|\$HOME/\.config/(gh|gcloud|azure)' "$file" 2>/dev/null; then
    flag WARN "$rel  [CRED_ACCESS]  references cloud CLI credentials"
  fi
  if grep -qE '~/Library/Keychains|\$HOME/Library/Keychains' "$file" 2>/dev/null; then
    flag WARN "$rel  [CRED_ACCESS]  references macOS Keychain"
  fi
  if grep -qE '\.env\b' "$file" 2>/dev/null; then
    flag WARN "$rel  [DOTENV]  references .env file"
  fi

  # Outbound POST (not already flagged as credential exfil)
  if grep -qE 'curl\s+.*-X\s+POST|curl\s+.*--data\b' "$file" 2>/dev/null \
     && ! grep -qE '\.(ssh|aws|gnupg|env)' "$file" 2>/dev/null; then
    flag WARN "$rel  [OUTBOUND_POST]  curl POST — verify destination URL"
  fi
  if grep -qE 'requests\.post\(' "$file" 2>/dev/null; then
    flag WARN "$rel  [OUTBOUND_POST]  Python requests.post — verify endpoint"
  fi
  if grep -qE 'axios\.post\(|fetch.*method.*POST' "$file" 2>/dev/null; then
    flag WARN "$rel  [OUTBOUND_POST]  JS fetch/axios POST — verify endpoint"
  fi

  # Environment variable harvesting (exclude shebang lines and PATH references)
  if grep -v '^#!' "$file" 2>/dev/null | grep -qE '\bprintenv\b|\bos\.environ\b|process\.env\b.*[Oo]bject|export\s+.*\|' 2>/dev/null \
     && grep -qE 'curl|wget|requests\.post|fetch' "$file" 2>/dev/null; then
    flag WARN "$rel  [ENV_HARVEST]  environment variable access combined with network call"
  fi

  # ── INFO ────────────────────────────────────────────────────────────────

  # General network downloads (not pipe-to-shell)
  if grep -qE '\b(curl|wget)\b' "$file" 2>/dev/null \
     && ! grep -qE '(curl|wget)\s+.+\|\s*(ba)?sh' "$file" 2>/dev/null; then
    flag INFO "$rel  [NETWORK_DOWNLOAD]  curl/wget usage — review destination"
  fi
}

# ── Walk target ──────────────────────────────────────────────────────────────
if [[ -f "$TARGET" ]]; then
  scan_file "$TARGET" "$(basename "$TARGET")"
elif [[ -d "$TARGET" ]]; then
  while IFS= read -r -d '' file; do
    rel="${file#${TARGET}/}"
    scan_file "$file" "$rel"
  done < <(find "$TARGET" -type f ! -path '*/.git/*' \
    \( -name '*.sh' -o -name '*.bash' -o -name '*.py' -o -name '*.js' -o -name '*.ts' \) \
    -print0)
fi

# ── Output ────────────────────────────────────────────────────────────────────
for finding in "${FINDINGS[@]+"${FINDINGS[@]}"}"; do
  echo "$finding"
done

echo "" >&2
echo "Script safety scan: ${CRITICAL_COUNT} CRITICAL | ${WARN_COUNT} WARN | ${INFO_COUNT} INFO" >&2

exit "$MAX_SEVERITY"
