#!/usr/bin/env bash
# supply-chain.sh — Scans for supply chain attack vectors.
#
# Checks: .pth files, setup.py cmdclass, package.json hooks,
#          requirements.txt unpinned deps, pyproject.toml, inline script deps
#
# Usage:
#   supply-chain.sh <path>
#
# Output: [SEVERITY] relative/path  [pattern_id]  description
# Exit:   0=clean, 1=WARN found, 2=CRITICAL found

set -euo pipefail

TARGET="${1:-}"

if [[ -z "$TARGET" || ! -d "$TARGET" ]]; then
  echo "Usage: supply-chain.sh <directory>" >&2
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

# ══════════════════════════════════════════════════════════════════════════════
# 1. .pth FILE SCANNING — the litellm attack vector
# ══════════════════════════════════════════════════════════════════════════════
while IFS= read -r -d '' pth_file; do
  rel="${pth_file#${TARGET}/}"

  # Any .pth file in a skill repo is suspicious by default
  flag WARN "$rel  [PTH_FILE]  .pth file found — Python path config files can auto-execute code"

  # Check for executable content inside .pth (CRITICAL)
  if grep -qiE 'import\s|base64|exec\(|eval\(|subprocess|os\.system|urllib|requests|http\.client|socket' "$pth_file" 2>/dev/null; then
    flag CRITICAL "$rel  [PTH_EXECUTABLE]  .pth file contains executable code (import/exec/eval/network)"
  fi
  if grep -qE '__import__|compile\(|codecs\.decode' "$pth_file" 2>/dev/null; then
    flag CRITICAL "$rel  [PTH_OBFUSCATED]  .pth file contains obfuscated execution pattern"
  fi
done < <(find "$TARGET" -type f -name '*.pth' ! -path '*/.git/*' -print0 2>/dev/null)

# ══════════════════════════════════════════════════════════════════════════════
# 2. setup.py / setup.cfg — CUSTOM INSTALL COMMANDS
# ══════════════════════════════════════════════════════════════════════════════
while IFS= read -r -d '' setup_file; do
  rel="${setup_file#${TARGET}/}"

  # Check for cmdclass overrides (custom install/develop commands)
  if grep -qE 'cmdclass|install_requires.*subprocess|install_requires.*os\.' "$setup_file" 2>/dev/null; then
    flag CRITICAL "$rel  [SETUP_CMDCLASS]  setup.py overrides install commands — code runs on pip install"
  fi

  # Check for __import__ / exec in setup.py
  if grep -qE 'exec\s*\(|__import__|subprocess\.(call|run|Popen)|os\.system' "$setup_file" 2>/dev/null; then
    flag CRITICAL "$rel  [SETUP_EXEC]  setup.py contains dynamic execution"
  fi

  # Check for network calls in setup.py
  if grep -qE 'urllib|requests\.|http\.client|socket\.connect|curl|wget' "$setup_file" 2>/dev/null; then
    flag CRITICAL "$rel  [SETUP_NETWORK]  setup.py makes network calls during install"
  fi
done < <(find "$TARGET" -type f \( -name 'setup.py' -o -name 'setup.cfg' \) ! -path '*/.git/*' -print0 2>/dev/null)

# ══════════════════════════════════════════════════════════════════════════════
# 3. pyproject.toml — BUILD SYSTEM HOOKS
# ══════════════════════════════════════════════════════════════════════════════
while IFS= read -r -d '' pyproject; do
  rel="${pyproject#${TARGET}/}"

  # Check for custom build backends or build hooks
  if grep -qE 'build-backend|hatch.*hooks|setuptools\.build_meta' "$pyproject" 2>/dev/null; then
    flag INFO "$rel  [BUILD_BACKEND]  custom build backend — review build process"
  fi

  # Check for scripts that run on install
  if grep -qE '\[project\.scripts\]|\[tool\.setuptools\..*\]' "$pyproject" 2>/dev/null; then
    flag INFO "$rel  [PROJECT_SCRIPTS]  defines installable scripts — review entry points"
  fi

  flag INFO "$rel  [PYTHON_DEPS]  Python dependency file — review pinned versions and sources"
done < <(find "$TARGET" -type f -name 'pyproject.toml' ! -path '*/.git/*' -print0 2>/dev/null)

# ══════════════════════════════════════════════════════════════════════════════
# 4. requirements.txt — UNPINNED OR SUSPICIOUS DEPS
# ══════════════════════════════════════════════════════════════════════════════
while IFS= read -r -d '' req_file; do
  rel="${req_file#${TARGET}/}"

  # Count unpinned dependencies (no == version)
  unpinned_count=$(grep -cE '^[a-zA-Z]' "$req_file" 2>/dev/null | head -1 || echo 0)
  pinned_count=$(grep -cE '==' "$req_file" 2>/dev/null | head -1 || echo 0)

  if [[ "$unpinned_count" -gt 0 && "$pinned_count" -eq 0 ]]; then
    flag WARN "$rel  [UNPINNED_DEPS]  all ${unpinned_count} dependencies are unpinned — vulnerable to version substitution"
  elif [[ "$unpinned_count" -gt "$pinned_count" ]]; then
    flag WARN "$rel  [MOSTLY_UNPINNED]  ${unpinned_count} unpinned vs ${pinned_count} pinned — prefer pinned versions"
  fi

  # Check for --index-url pointing to non-PyPI sources
  if grep -qiE '^\s*--index-url|--extra-index-url' "$req_file" 2>/dev/null; then
    flag WARN "$rel  [CUSTOM_INDEX]  custom package index URL — verify it's trusted"
  fi

  # Check for git+https dependencies
  if grep -qE 'git\+https?://' "$req_file" 2>/dev/null; then
    flag WARN "$rel  [GIT_DEP]  git-based dependency — verify repo and commit hash"
  fi

  flag INFO "$rel  [PYTHON_DEPS]  Python dependency file — review packages before installing"
done < <(find "$TARGET" -type f -name 'requirements*.txt' ! -path '*/.git/*' -print0 2>/dev/null)

# ══════════════════════════════════════════════════════════════════════════════
# 5. package.json — NPM LIFECYCLE SCRIPTS
# ══════════════════════════════════════════════════════════════════════════════
while IFS= read -r -d '' pkg_json; do
  rel="${pkg_json#${TARGET}/}"

  # Check for lifecycle hooks
  for hook in preinstall install postinstall prepare prepack postpack; do
    if grep -q "\"$hook\"" "$pkg_json" 2>/dev/null; then
      # Check if the hook runs something dangerous
      hook_content=$(grep -A1 "\"$hook\"" "$pkg_json" 2>/dev/null | tail -1 || true)
      if echo "$hook_content" | grep -qiE 'curl|wget|node\s+-e|eval|base64' 2>/dev/null; then
        flag CRITICAL "$rel  [NPM_HOOK_EXEC]  $hook script contains dynamic execution"
      else
        flag WARN "$rel  [NPM_HOOK]  $hook lifecycle script found — review: $hook_content"
      fi
    fi
  done

  flag INFO "$rel  [NODE_DEPS]  Node dependency file — review packages before installing"
done < <(find "$TARGET" -type f -name 'package.json' ! -path '*/.git/*' ! -path '*/node_modules/*' -print0 2>/dev/null)

# ══════════════════════════════════════════════════════════════════════════════
# 6. INLINE SCRIPT DEPENDENCIES (uv run / PEP 723)
# ══════════════════════════════════════════════════════════════════════════════
while IFS= read -r -d '' py_file; do
  rel="${py_file#${TARGET}/}"

  # Check for PEP 723 inline metadata (# /// script)
  if grep -q '# /// script' "$py_file" 2>/dev/null; then
    flag WARN "$rel  [INLINE_DEPS]  PEP 723 inline dependencies — packages auto-install on 'uv run'"
    # Check if any of the inline deps look suspicious
    if sed -n '/# \/\/\/ script/,/# \/\/\//p' "$py_file" 2>/dev/null | grep -qiE 'subprocess|ctypes|cffi'; then
      flag WARN "$rel  [INLINE_DEPS_NATIVE]  inline deps include native code packages"
    fi
  fi
done < <(find "$TARGET" -type f -name '*.py' ! -path '*/.git/*' -print0 2>/dev/null)

# ══════════════════════════════════════════════════════════════════════════════
# 7. Makefile — INSTALL TARGETS WITH NETWORK
# ══════════════════════════════════════════════════════════════════════════════
while IFS= read -r -d '' makefile; do
  rel="${makefile#${TARGET}/}"

  if grep -qE '(curl|wget)' "$makefile" 2>/dev/null; then
    flag WARN "$rel  [MAKEFILE_NETWORK]  Makefile downloads from network — review URLs"
  fi
  if grep -qE 'sudo|chmod\s+777' "$makefile" 2>/dev/null; then
    flag WARN "$rel  [MAKEFILE_PRIV]  Makefile uses sudo or world-writable chmod"
  fi
done < <(find "$TARGET" -type f \( -name 'Makefile' -o -name 'makefile' -o -name 'GNUmakefile' \) ! -path '*/.git/*' -print0 2>/dev/null)

# ══════════════════════════════════════════════════════════════════════════════
# 8. __init__.py — OBFUSCATED INIT FILES
# ══════════════════════════════════════════════════════════════════════════════
while IFS= read -r -d '' init_file; do
  rel="${init_file#${TARGET}/}"

  # Check for obfuscated code in __init__.py
  if grep -qE 'exec\s*\(|eval\s*\(|__import__|base64\.b64decode|codecs\.decode' "$init_file" 2>/dev/null; then
    flag CRITICAL "$rel  [INIT_OBFUSCATED]  __init__.py contains obfuscated execution"
  fi
  if grep -qE 'subprocess|os\.system|os\.popen' "$init_file" 2>/dev/null; then
    flag WARN "$rel  [INIT_SUBPROCESS]  __init__.py runs system commands on import"
  fi
done < <(find "$TARGET" -type f -name '__init__.py' ! -path '*/.git/*' -print0 2>/dev/null)

# ── Output ────────────────────────────────────────────────────────────────────
for finding in "${FINDINGS[@]+"${FINDINGS[@]}"}"; do
  echo "$finding"
done

echo "" >&2
echo "Supply chain scan: ${CRITICAL_COUNT} CRITICAL | ${WARN_COUNT} WARN | ${INFO_COUNT} INFO" >&2

exit "$MAX_SEVERITY"
