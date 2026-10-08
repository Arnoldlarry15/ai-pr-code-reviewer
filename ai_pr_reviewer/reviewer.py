import re
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class SecurityFinding:
    severity: str
    category: str
    file_path: str
    line_number: Optional[int]
    issue: str
    suggested_fix: str

@dataclass
class ReviewReport:
    verdict: str
    risk_score: str
    summary: str
    findings: List[SecurityFinding] = field(default_factory=list)

    def to_markdown(self) -> str:
        icons = {'APPROVE': 'PASS', 'COMMENT': 'WARN', 'REQUEST_CHANGES': 'FAIL'}
        md = [
            f"### AI Code Review & Security Audit Report",
            f"**Verdict:** `{self.verdict}` | **Security Risk:** `{self.risk_score}`\n",
            f"{self.summary}\n",
            "#### Detected Findings:"
        ]
        if not self.findings:
            md.append("No security vulnerabilities or architectural regressions detected.")
        else:
            for f in self.findings:
                badge = {"CRITICAL": "[CRITICAL]", "WARNING": "[WARNING]", "NOTE": "[NOTE]"}.get(f.severity, "[INFO]")
                loc = f"`{f.file_path}`" + (f":{f.line_number}" if f.line_number else "")
                md.append(f"- **{badge} {f.category}** at {loc}")
                md.append(f"  - **Issue:** {f.issue}")
                md.append(f"  - **Suggested Fix:** {f.suggested_fix}")
        return "\n".join(md)

class AIPrReviewer:
    """Analyzes git diffs for OWASP Top 10 security flaws and code quality issues."""

    SECRET_PATTERNS = [
        (r'''(?i)(api[_-]?key|secret|token|password|auth_token)\s*=\s*['"][A-Za-z0-9_\-]{16,}['"]''', "Hardcoded API secret or credential detected"),
        (r'''(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}''', "Hardcoded Bearer authentication token exposed"),
        (r'''(?i)private[_-]?key\s*=\s*['"][A-Za-z0-9_\-]{16,}['"]''', "Hardcoded Private Key credential exposed"),
    ]

    INJECTION_PATTERNS = [
        (r'''(?i)execute\s*\(\s*f['"].*?\{.*?\}''', "Potential SQL Injection: unescaped string formatting in SQL execute()"),
        (r'''(?i)eval\s*\(.*?\)''', "Dangerous use of eval(): arbitrary code execution hazard"),
        (r'''(?i)dangerouslySetInnerHTML''', "Potential Cross-Site Scripting (XSS): un-sanitized DOM injection"),
    ]

    ASYNC_ERROR_PATTERNS = [
        (r"(?i)except\s*:\s*pass", "Silent exception swallow detected: masks critical runtime failures"),
    ]

    def review_diff(self, diff_text: str) -> ReviewReport:
        findings: List[SecurityFinding] = []
        current_file = "unknown"
        line_num = 0

        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                current_file = line.replace("+++ b/", "").strip()
                line_num = 0
                continue
            elif line.startswith("@@"):
                m = re.search(r"\+(\d+)", line)
                if m:
                    line_num = int(m.group(1))
                continue

            if line.startswith("+") and not line.startswith("+++"):
                line_num += 1
                added_code = line[1:].strip()

                for pattern, desc in self.SECRET_PATTERNS:
                    if re.search(pattern, added_code):
                        findings.append(SecurityFinding(
                            severity="CRITICAL",
                            category="SECURITY",
                            file_path=current_file,
                            line_number=line_num,
                            issue=desc,
                            suggested_fix="Store credential in environment variables or a secure secrets manager."
                        ))

                for pattern, desc in self.INJECTION_PATTERNS:
                    if re.search(pattern, added_code):
                        findings.append(SecurityFinding(
                            severity="CRITICAL",
                            category="SECURITY",
                            file_path=current_file,
                            line_number=line_num,
                            issue=desc,
                            suggested_fix="Use parameterized queries or framework-level sanitizers."
                        ))

                for pattern, desc in self.ASYNC_ERROR_PATTERNS:
                    if re.search(pattern, added_code):
                        findings.append(SecurityFinding(
                            severity="WARNING",
                            category="RELIABILITY",
                            file_path=current_file,
                            line_number=line_num,
                            issue=desc,
                            suggested_fix="Implement structured logging and explicit error handling."
                        ))

        criticals = sum(1 for f in findings if f.severity == "CRITICAL")
        warnings = sum(1 for f in findings if f.severity == "WARNING")

        if criticals > 0:
            verdict = "REQUEST_CHANGES"
            risk = "CRITICAL" if criticals > 1 else "HIGH"
            summary = f"Detected {criticals} critical security vulnerabilities that must be resolved prior to merging."
        elif warnings > 0:
            verdict = "COMMENT"
            risk = "MEDIUM"
            summary = f"Detected {warnings} non-blocking reliability optimizations for review."
        else:
            verdict = "APPROVE"
            risk = "LOW"
            summary = "Clean PR diff. No critical OWASP vulnerabilities or unhandled async exceptions detected."

        return ReviewReport(verdict=verdict, risk_score=risk, summary=summary, findings=findings)
