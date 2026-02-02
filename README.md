# 🔍 Skill Scanner

A security scanner that detects red flags in SKILL.md files — identifying potential phishing, malware, and social engineering attacks disguised as legitimate AI skill definitions.

## Why?

Malicious actors are creating fake "skill files" that trick users into:
- Downloading malware (password-protected ZIPs to evade antivirus)
- Running executables that steal crypto wallets
- Exposing private keys and seed phrases

This scanner catches these threats **before** you fall for them.

## Quick Start

```bash
python3 skill_scanner.py path/to/SKILL.md
```

## What It Detects

| Category | Severity | Examples |
|----------|----------|----------|
| **Suspicious Downloads** | 🔴 HIGH | `.exe`, `.zip`, `.dmg` links |
| **Untrusted Sources** | 🔴 HIGH | GitHub repos from unknown users |
| **Executable Instructions** | 🔴 HIGH | "Run PolymarketAuthTool.exe" |
| **Password-Protected Archives** | 🔴 HIGH | "Archive password: `poly`" |
| **Social Engineering** | 🟠 MEDIUM | "Required", "Without this you cannot..." |
| **Sensitive Credentials** | 🟠 MEDIUM | `PRIVATE_KEY`, `WALLET`, `MNEMONIC` |
| **Reassurance Tactics** | 🟠 MEDIUM | "Signs locally without exposing keys" |
| **Deceptive Imagery** | 🟡 LOW | Fake balance screenshots |

## Example Output

```
══════════════════════════════════════════════════════════════════════
  🔍 SKILL.md SECURITY SCAN REPORT
══════════════════════════════════════════════════════════════════════

  📄 File: SKILL.md
  📊 Risk Score: 280 (🔴 CRITICAL)
  🚨 Findings: 16

──────────────────────────────────────────────────────────────────────
  🔴 HIGH SEVERITY
──────────────────────────────────────────────────────────────────────

  [SUSPICIOUS_DOWNLOAD]
    ⚠️  Links to downloadable artifact with '.zip' extension
    📎 https://github.com/Aslaep123/PolymarketAuthTool/releases/...

  [UNTRUSTED_SOURCE]
    ⚠️  GitHub repo owned by untrusted user/org: 'aslaep123'
    📎 https://github.com/Aslaep123/...

══════════════════════════════════════════════════════════════════════
  📋 RECOMMENDATION
══════════════════════════════════════════════════════════════════════

  🚫 DO NOT USE THIS SKILL FILE
  ...
```

## Risk Scoring

| Score | Level | Action |
|-------|-------|--------|
| 0 | ✅ CLEAN | Safe to use |
| 1-29 | 🟢 LOW | Review findings |
| 30-59 | 🟡 MEDIUM | Proceed with caution |
| 60-99 | 🟠 HIGH | Manual verification needed |
| 100+ | 🔴 CRITICAL | Do not use |

## Exit Codes

- `0` — Low risk (score < 60)
- `1` — High risk (score ≥ 60)

Use in CI/CD pipelines:

```bash
python3 skill_scanner.py skills/*.md || echo "⚠️ Suspicious skill detected!"
```

## Requirements

- Python 3.7+
- No external dependencies (stdlib only)

## License

MIT
