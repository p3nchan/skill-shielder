---
name: skill-shielder
description: |
  Security audit tool for Claude Code skills and repositories. Scans for prompt injection,
  dangerous scripts, supply chain attacks, and permission scope issues before you install
  or trust a skill.

  Use when: (1) evaluating a new skill or MCP before installing, (2) auditing a GitHub
  repo for safety, (3) reviewing downloaded code for hidden threats, (4) checking if a
  skill is safe to use.

  Trigger phrases: "audit this skill", "is this safe", "scan this repo", "security check",
  "skill check", "shield this", "evaluate this skill"
metadata:
  author: penchan-co
  version: "1.0.0"
  license: MIT
---

# Skill Shielder

Security audit for Claude Code skills and repos. Scans before you install, so you don't have to trust blindly.

## Quick Start

```bash
# Audit a local directory
bash shield.sh /path/to/skill

# Audit a GitHub repo
bash shield.sh https://github.com/user/repo

# Verbose mode
bash shield.sh --verbose /path/to/skill

# JSON output (for programmatic use)
bash shield.sh --json /path/to/skill
```

## What It Scans

| Scanner | What It Checks |
|:--------|:---------------|
| **Prompt Injection** | Hidden instructions, persona hijacking, unicode tricks, system tag injection in `.md`/`.json`/`.yaml` |
| **Script Safety** | Destructive commands, pipe-to-shell, credential exfiltration, reverse shells, privilege escalation in `.sh`/`.py`/`.js`/`.ts` |
| **Supply Chain** | `.pth` file attacks (litellm-style), setup.py hooks, npm lifecycle scripts, unpinned dependencies, inline script deps |
| **Permissions** | Sensitive path access (`.ssh`, `.aws`, `.env`), outbound network endpoints, cross-referencing access + network for exfiltration patterns |

## Verdicts

| Verdict | Meaning | Action |
|:--------|:--------|:-------|
| **PASS** | No issues found | Safe to install |
| **WARN** | Non-critical issues | Present findings to user, require explicit confirmation |
| **FAIL** | Critical issues | **Do NOT install.** Block and explain findings |

## Workflow

1. User asks to evaluate a skill/repo
2. Run `shield.sh` with the target path or URL
3. Present the report to the user
4. **PASS** → proceed with installation
5. **WARN** → show findings, ask user to confirm
6. **FAIL** → block installation, explain risks

## Important

- Never auto-approve WARN or FAIL results
- Always present the full findings report to the user
- For GitHub URLs: reputation data (stars, age, contributors) provides context but is not conclusive
- This tool has zero external dependencies — it cannot be a supply chain risk itself

## Pattern References

For detailed pattern documentation, read:
- `patterns/prompt-injection.md` — full prompt injection pattern catalog
- `patterns/script-safety.md` — script danger patterns
- `patterns/supply-chain.md` — supply chain attack signatures and known compromised packages
