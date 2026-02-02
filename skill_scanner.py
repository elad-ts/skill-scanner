#!/usr/bin/env python3
"""
SKILL.md Security Scanner
Detects red flags in skill definition files that may indicate malicious intent.
"""

import re
import sys
from pathlib import Path
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import List, Tuple

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_EXTENSIONS = (".exe", ".zip", ".dmg", ".pkg", ".msi", ".bat", ".cmd", ".ps1", ".scr")

TRUSTED_GITHUB_OWNERS = {
    "polymarket", "polymarket-clob", "polymarketofficial",
    "microsoft", "google", "apple", "github", "openai", "anthropic",
}

SOCIAL_ENGINEERING_PATTERNS = [
    (r"\bcritical\b", "Uses 'critical' urgency language"),
    (r"\brequired\b.*\b(tool|download|install)", "Marks download as 'required'"),
    (r"without this.*cannot", "Claims functionality impossible without tool"),
    (r"must\s+(download|install|run)", "Demands user must download/install/run"),
    (r"before using this skill", "Gates skill behind prerequisite action"),
    (r"cannot\s+(sign|access|use)\b", "Claims access impossible without action"),
    (r"⚠️.*required", "Uses warning emoji with 'required'"),
    (r"extract.*and\s+(open|run)", "Instructs to extract and execute"),
]

SENSITIVE_ENV_PATTERNS = [
    (r"\bPRIVATE_KEY\b", "References private key"),
    (r"\bSEED\b", "References seed phrase"),
    (r"\bMNEMONIC\b", "References mnemonic"),
    (r"\bWALLET\b", "References wallet"),
    (r"\bSECRET\b", "References secret"),
    (r"\bAUTH_TOOL_PATH\b", "References auth tool path"),
    (r"\bAPI_KEY\b", "References API key"),
]

REASSURANCE_PATTERNS = [
    (r"signs?\s+locally.*without exposing.*private key", "Claims local signing (reassurance tactic)"),
    (r"never\s+(leaves?|exposes?|sends?).*key", "Claims keys never leave device"),
    (r"secure.*local", "Emphasizes 'secure local' processing"),
]


# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    category: str
    severity: str  # HIGH, MEDIUM, LOW
    description: str
    evidence: str


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def find_suspicious_downloads(markdown: str) -> List[Finding]:
    """Detect suspicious download links and artifacts."""
    findings = []
    urls = re.findall(r"https?://[^\s\)\]>]+", markdown)
    
    for url in urls:
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        
        # Check for suspicious file extensions
        for ext in SUSPICIOUS_EXTENSIONS:
            if path_lower.endswith(ext):
                findings.append(Finding(
                    category="SUSPICIOUS_DOWNLOAD",
                    severity="HIGH",
                    description=f"Links to downloadable artifact with '{ext}' extension",
                    evidence=url
                ))
                break
        
        # Check for unofficial GitHub repos
        if "github.com/" in url:
            match = re.search(r"github\.com/([^/]+)/", url)
            if match:
                owner = match.group(1).lower()
                if owner not in TRUSTED_GITHUB_OWNERS:
                    findings.append(Finding(
                        category="UNTRUSTED_SOURCE",
                        severity="HIGH",
                        description=f"GitHub repo owned by untrusted user/org: '{owner}'",
                        evidence=url
                    ))
    
    return findings


def find_archive_password_hints(markdown: str) -> List[Finding]:
    """Detect password-protected archive indicators."""
    findings = []
    
    patterns = [
        (r"archive\s+password\s*[:\-]?\s*[`'\"]?(\w+)[`'\"]?", "Archive password specified"),
        (r"password\s*[:\-]\s*[`'\"]?(\w+)[`'\"]?", "Password hint found"),
        (r"password.protected", "Mentions password protection"),
    ]
    
    for pattern, desc in patterns:
        match = re.search(pattern, markdown, re.IGNORECASE)
        if match:
            findings.append(Finding(
                category="PASSWORD_PROTECTED_ARCHIVE",
                severity="HIGH",
                description=desc,
                evidence=match.group(0)
            ))
    
    return findings


def find_exe_instructions(markdown: str) -> List[Finding]:
    """Detect instructions to run executable files."""
    findings = []
    
    patterns = [
        (r"(open|run|execute|launch|start)\s+\w*\.exe", "Instructions to run .exe file"),
        (r"\.exe\b", "References .exe file"),
        (r"double[- ]?click.*\.exe", "Instructions to double-click .exe"),
    ]
    
    for pattern, desc in patterns:
        matches = re.findall(pattern, markdown, re.IGNORECASE)
        if matches:
            findings.append(Finding(
                category="EXECUTABLE_INSTRUCTION",
                severity="HIGH",
                description=desc,
                evidence=str(matches[:3])  # First 3 matches
            ))
    
    return findings


def find_social_engineering(markdown: str) -> List[Finding]:
    """Detect social engineering language patterns."""
    findings = []
    
    for pattern, desc in SOCIAL_ENGINEERING_PATTERNS:
        if re.search(pattern, markdown, re.IGNORECASE | re.DOTALL):
            match = re.search(pattern, markdown, re.IGNORECASE | re.DOTALL)
            findings.append(Finding(
                category="SOCIAL_ENGINEERING",
                severity="MEDIUM",
                description=desc,
                evidence=match.group(0)[:80] if match else ""
            ))
    
    return findings


def find_crypto_secret_risks(markdown: str) -> List[Finding]:
    """Detect references to sensitive crypto credentials."""
    findings = []
    
    # Check for sensitive environment variables
    for pattern, desc in SENSITIVE_ENV_PATTERNS:
        if re.search(pattern, markdown, re.IGNORECASE):
            findings.append(Finding(
                category="SENSITIVE_CREDENTIAL",
                severity="MEDIUM",
                description=desc,
                evidence=pattern.strip(r"\b")
            ))
    
    # Check for reassurance language (often used to lower guard)
    for pattern, desc in REASSURANCE_PATTERNS:
        if re.search(pattern, markdown, re.IGNORECASE | re.DOTALL):
            findings.append(Finding(
                category="REASSURANCE_TACTIC",
                severity="MEDIUM",
                description=desc,
                evidence=re.search(pattern, markdown, re.IGNORECASE | re.DOTALL).group(0)[:60]
            ))
    
    return findings


def find_deceptive_imagery(markdown: str) -> List[Finding]:
    """Detect potentially deceptive images (fake balances, screenshots)."""
    findings = []
    
    # Look for images with suspicious names
    image_patterns = [
        (r"!\[.*balance.*\]", "Image labeled as 'balance' (potential fake screenshot)"),
        (r"!\[.*proof.*\]", "Image labeled as 'proof'"),
        (r"!\[.*success.*\]", "Image labeled as 'success'"),
        (r"raw\.githubusercontent\.com.*\.(jpg|png|gif)", "Raw GitHub image (could be anything)"),
    ]
    
    for pattern, desc in image_patterns:
        if re.search(pattern, markdown, re.IGNORECASE):
            match = re.search(pattern, markdown, re.IGNORECASE)
            findings.append(Finding(
                category="DECEPTIVE_IMAGERY",
                severity="LOW",
                description=desc,
                evidence=match.group(0)[:80] if match else ""
            ))
    
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

def scan_skill_file(content: str) -> List[Finding]:
    """Run all detection functions on the content."""
    all_findings = []
    
    all_findings.extend(find_suspicious_downloads(content))
    all_findings.extend(find_archive_password_hints(content))
    all_findings.extend(find_exe_instructions(content))
    all_findings.extend(find_social_engineering(content))
    all_findings.extend(find_crypto_secret_risks(content))
    all_findings.extend(find_deceptive_imagery(content))
    
    return all_findings


def calculate_risk_score(findings: List[Finding]) -> Tuple[int, str]:
    """Calculate overall risk score."""
    score = 0
    for f in findings:
        if f.severity == "HIGH":
            score += 30
        elif f.severity == "MEDIUM":
            score += 15
        else:
            score += 5
    
    if score >= 100:
        level = "🔴 CRITICAL"
    elif score >= 60:
        level = "🟠 HIGH"
    elif score >= 30:
        level = "🟡 MEDIUM"
    elif score > 0:
        level = "🟢 LOW"
    else:
        level = "✅ CLEAN"
    
    return score, level


def print_report(filepath: str, findings: List[Finding]):
    """Print a formatted risk report."""
    score, level = calculate_risk_score(findings)
    
    print("\n" + "═" * 70)
    print("  🔍 SKILL.md SECURITY SCAN REPORT")
    print("═" * 70)
    print(f"\n  📄 File: {filepath}")
    print(f"  📊 Risk Score: {score} ({level})")
    print(f"  🚨 Findings: {len(findings)}")
    
    if not findings:
        print("\n  ✅ No red flags detected.\n")
        return
    
    # Group by severity
    high = [f for f in findings if f.severity == "HIGH"]
    medium = [f for f in findings if f.severity == "MEDIUM"]
    low = [f for f in findings if f.severity == "LOW"]
    
    if high:
        print("\n" + "─" * 70)
        print("  🔴 HIGH SEVERITY")
        print("─" * 70)
        for f in high:
            print(f"\n  [{f.category}]")
            print(f"    ⚠️  {f.description}")
            print(f"    📎 {f.evidence[:70]}{'...' if len(f.evidence) > 70 else ''}")
    
    if medium:
        print("\n" + "─" * 70)
        print("  🟠 MEDIUM SEVERITY")
        print("─" * 70)
        for f in medium:
            print(f"\n  [{f.category}]")
            print(f"    ⚠️  {f.description}")
            print(f"    📎 {f.evidence[:70]}{'...' if len(f.evidence) > 70 else ''}")
    
    if low:
        print("\n" + "─" * 70)
        print("  🟡 LOW SEVERITY")
        print("─" * 70)
        for f in low:
            print(f"\n  [{f.category}]")
            print(f"    ℹ️  {f.description}")
            print(f"    📎 {f.evidence[:70]}{'...' if len(f.evidence) > 70 else ''}")
    
    print("\n" + "═" * 70)
    print("  📋 RECOMMENDATION")
    print("═" * 70)
    
    if score >= 60:
        print("""
  🚫 DO NOT USE THIS SKILL FILE

  This file contains multiple indicators of a potential phishing/malware
  attack disguised as a legitimate skill definition. The combination of:
  
    • External executable downloads
    • Password-protected archives (to evade antivirus)
    • Requests for wallet/key access
    • Social engineering language
  
  ...is a CLASSIC pattern for cryptocurrency theft malware.
""")
    elif score >= 30:
        print("""
  ⚠️  PROCEED WITH CAUTION

  This file has some suspicious elements. Manually verify:
    • Any external downloads come from official sources
    • No unexpected executables are involved
    • Credential requests are legitimate
""")
    else:
        print("""
  ✅ LOW RISK

  Minor findings detected. Review the items above but this file
  does not show obvious signs of malicious intent.
""")
    
    print("═" * 70 + "\n")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print("Usage: python skill_scanner.py <path-to-skill.md>")
        print("       python skill_scanner.py SKILL.md")
        sys.exit(1)
    
    filepath = sys.argv[1]
    path = Path(filepath)
    
    if not path.exists():
        print(f"❌ Error: File not found: {filepath}")
        sys.exit(1)
    
    content = path.read_text(encoding="utf-8")
    findings = scan_skill_file(content)
    print_report(filepath, findings)
    
    # Exit with non-zero if high risk
    score, _ = calculate_risk_score(findings)
    sys.exit(1 if score >= 60 else 0)


if __name__ == "__main__":
    main()
