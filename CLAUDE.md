# Skill Shielder

This is a security audit tool for Claude Code skills and repositories.

## Usage

Run `shield.sh` to audit a skill before installing it:

```bash
# Local directory
bash shield.sh /path/to/downloaded-skill

# GitHub repo
bash shield.sh https://github.com/user/skill-repo
```

## Rules

- Always present the full report to the user before proceeding
- **PASS**: safe to install
- **WARN**: show findings, require explicit user confirmation before installing
- **FAIL**: do NOT install — explain the critical findings
- Never silently skip or downplay findings
- Never auto-approve results

## Files

- `shield.sh` — main orchestrator
- `scanners/` — individual scanner modules
- `patterns/` — threat pattern references (community-maintained)
- `SKILL.md` — CC skill definition
