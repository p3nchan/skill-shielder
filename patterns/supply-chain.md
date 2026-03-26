# Supply Chain Patterns

Canonical reference for the supply chain scanner. Covers dependency poisoning, install hooks, and auto-execution vectors.

---

## The .pth Attack Vector

Python `.pth` files in `site-packages/` are processed on every interpreter startup. Each line is either:
- A path to add to `sys.path`, OR
- A line starting with `import` that gets **executed automatically**

This is how the **litellm 1.82.8 attack** (2026-03-25) worked:
1. Poisoned PyPI release included `litellm_init.pth`
2. The `.pth` file contained base64-encoded instructions
3. On any Python startup, it automatically exfiltrated SSH keys, AWS/GCP/Azure credentials, Kubernetes configs, git credentials, env vars, shell history, crypto wallets, SSL private keys, CI/CD secrets, and database passwords
4. It also self-replicated to other installed packages

### .pth Detection Patterns

| Pattern | Severity | Notes |
|:--------|:---------|:------|
| Any `.pth` file in a skill repo | WARN | Skills shouldn't need .pth files |
| `.pth` with `import` statements | CRITICAL | Auto-execution on Python startup |
| `.pth` with `base64` / `exec` / `eval` | CRITICAL | Obfuscated payload |
| `.pth` with `urllib` / `requests` / `http` / `socket` | CRITICAL | Network activity on startup |
| `.pth` with `os.system` / `subprocess` | CRITICAL | Command execution on startup |
| `.pth` with `codecs.decode` / `__import__` | CRITICAL | Obfuscation techniques |

---

## setup.py / setup.cfg Attacks

`setup.py` runs arbitrary Python during `pip install`. Attack vectors:

| Pattern | Severity | Notes |
|:--------|:---------|:------|
| `cmdclass` override | CRITICAL | Custom install/develop/build commands |
| `exec()` / `eval()` / `__import__()` in setup.py | CRITICAL | Dynamic execution |
| Network calls (`urllib`, `requests`, `socket`) in setup.py | CRITICAL | Downloads during install |
| `subprocess.call/run/Popen` / `os.system` in setup.py | CRITICAL | Shell commands during install |

---

## package.json Lifecycle Scripts

npm/bun/yarn execute lifecycle scripts automatically:

| Hook | When It Runs |
|:-----|:-------------|
| `preinstall` | Before `npm install` |
| `install` | During `npm install` |
| `postinstall` | After `npm install` |
| `prepare` | After install, before pack/publish |
| `prepack` | Before `npm pack` |

Any lifecycle script with `curl | bash`, `node -e`, `eval`, or `base64` is **CRITICAL**.

---

## Python Inline Dependencies (PEP 723)

Scripts using `uv run` can declare inline dependencies:
```python
# /// script
# dependencies = ["requests", "some-malicious-package"]
# ///
```

These packages auto-install when the script is run with `uv run`. A skill could pull in arbitrary packages this way.

---

## Dependency File Risks

| File | Risk |
|:-----|:-----|
| `requirements.txt` with no pinned versions (`==`) | Version substitution attack |
| `requirements.txt` with `--index-url` or `--extra-index-url` | Custom package index (could be malicious mirror) |
| `requirements.txt` with `git+https://` | Unreviewed git dependency |
| `pyproject.toml` with custom `build-backend` | Custom build code runs during install |

---

## Known Compromised Packages

This list is maintained by the community. Submit PRs to add entries.

| Package | Version | Date | Attack Type | CVE/Reference |
|:--------|:--------|:-----|:------------|:-------------|
| litellm | 1.82.8 | 2026-03-25 | .pth file credential exfiltration | [Source](https://x.com/hnykda/status/1904891424660091310) |

---

## __init__.py Risks

`__init__.py` runs on `import`. Obfuscated `__init__.py` files are a red flag:

| Pattern | Severity |
|:--------|:---------|
| `exec()` / `eval()` / `__import__()` in `__init__.py` | CRITICAL |
| `base64.b64decode` / `codecs.decode` in `__init__.py` | CRITICAL |
| `subprocess` / `os.system` / `os.popen` in `__init__.py` | WARN |

---

## Contributing

When reporting a new compromised package:
1. Include package name, exact version, date discovered
2. Describe the attack mechanism
3. Link to the source/advisory
4. Submit a PR to this file AND add detection to `scanners/supply-chain.sh`
