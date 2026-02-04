"""
CodeHawks submission formatter.

CodeHawks format requirements:
- Markdown report format
- Sections: Description, Impact, Proof of Concept, Recommended Mitigation
- Severity labels: High, Medium, Low, Informational, Gas
- Supports competitive audits similar to Code4rena
"""

from ..finding import Finding, Severity
from .base import BaseFormatter, FormattedFinding


class CodeHawksFormatter(BaseFormatter):
    """Formatter for CodeHawks submissions."""

    platform = "codehawks"

    severity_map = {
        Severity.CRITICAL: "High",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFORMATIONAL: "Informational",
        Severity.GAS: "Gas",
    }

    def format_finding(self, finding: Finding) -> FormattedFinding:
        """Format finding for CodeHawks submission."""
        severity_label = self.severity_label(finding.severity)

        # Title with severity prefix
        title = f"[{severity_label}] {finding.title}"

        # Build body sections
        sections = []

        # Description/Summary
        sections.append("## Description\n")
        sections.append(finding.description)
        sections.append("")

        # Location
        if finding.file_path:
            sections.append("## Location\n")
            location = self.format_location(finding)
            sections.append(f"- File: `{finding.file_path}`")
            if finding.contract_name:
                sections.append(f"- Contract: `{finding.contract_name}`")
            if finding.function_name:
                sections.append(f"- Function: `{finding.function_name}`")
            if finding.line_start:
                sections.append(f"- Lines: {finding.line_start}" +
                              (f"-{finding.line_end}" if finding.line_end else ""))
            sections.append("")

        # Vulnerable Code
        if finding.code_snippet:
            sections.append("## Vulnerable Code\n")
            sections.append(self.format_code_block(finding.code_snippet))
            sections.append("")

        # Impact
        sections.append("## Impact\n")
        if finding.impact:
            sections.append(finding.impact)
        else:
            sections.append(self._generate_impact(finding))
        sections.append("")

        # Proof of Concept
        if finding.proof_of_concept:
            sections.append("## Proof of Concept\n")
            sections.append("The following test demonstrates the vulnerability:\n")
            sections.append(self.format_code_block(finding.proof_of_concept))
            sections.append("")
        else:
            sections.append("## Proof of Concept\n")
            sections.append("A proof of concept can be created by implementing a test that demonstrates the vulnerability.")
            sections.append("")

        # Recommended Mitigation
        sections.append("## Recommended Mitigation\n")
        if finding.recommendation:
            sections.append(finding.recommendation)
        else:
            sections.append("Implement appropriate security controls to address this vulnerability.")
        sections.append("")

        # References
        if finding.references:
            sections.append("## References\n")
            for ref in finding.references:
                sections.append(f"- {ref}")
            sections.append("")

        body = "\n".join(sections)

        return FormattedFinding(
            title=title,
            body=body,
            severity=severity_label,
            category=finding.vulnerability_type,
            labels=[severity_label],
            metadata={
                "finding_id": finding.id,
                "vulnerability_type": finding.vulnerability_type,
            },
        )

    def _generate_impact(self, finding: Finding) -> str:
        """Generate impact description based on severity."""
        impacts = {
            Severity.CRITICAL: "This is a critical vulnerability that could result in complete loss of user funds or protocol compromise. Immediate action required.",
            Severity.HIGH: "High severity issue that could lead to significant financial loss or major protocol malfunction.",
            Severity.MEDIUM: "Medium severity issue that could affect protocol functionality or cause conditional fund loss.",
            Severity.LOW: "Low severity issue with limited direct impact but should be addressed for improved security posture.",
            Severity.INFORMATIONAL: "Informational finding that could improve code quality and maintainability.",
            Severity.GAS: "Gas optimization opportunity that could reduce transaction costs for users.",
        }
        return impacts.get(finding.severity, "Impact to be determined.")

    def format_report_header(self, contest_name: str, auditor: str = "Hound") -> str:
        """Format a report header for a full audit report."""
        return f"""# {contest_name} - Security Audit Report

**Auditor:** {auditor}
**Date:** {self._get_current_date()}

---

## Table of Contents

- [High Severity Findings](#high-severity-findings)
- [Medium Severity Findings](#medium-severity-findings)
- [Low Severity Findings](#low-severity-findings)
- [Informational Findings](#informational-findings)
- [Gas Optimizations](#gas-optimizations)

---
"""

    def format_full_report(self, contest_name: str, findings: list[Finding], auditor: str = "Hound") -> str:
        """Format a complete audit report with all findings."""
        sections = [self.format_report_header(contest_name, auditor)]

        # Group findings by severity
        by_severity = {
            Severity.CRITICAL: [],
            Severity.HIGH: [],
            Severity.MEDIUM: [],
            Severity.LOW: [],
            Severity.INFORMATIONAL: [],
            Severity.GAS: [],
        }

        for finding in findings:
            by_severity[finding.severity].append(finding)

        # High (including critical)
        high_findings = by_severity[Severity.CRITICAL] + by_severity[Severity.HIGH]
        if high_findings:
            sections.append("## High Severity Findings\n")
            for i, finding in enumerate(high_findings, 1):
                formatted = self.format_finding(finding)
                sections.append(f"### H-{i:02d}: {finding.title}\n")
                sections.append(formatted.body)
                sections.append("---\n")

        # Medium
        if by_severity[Severity.MEDIUM]:
            sections.append("## Medium Severity Findings\n")
            for i, finding in enumerate(by_severity[Severity.MEDIUM], 1):
                formatted = self.format_finding(finding)
                sections.append(f"### M-{i:02d}: {finding.title}\n")
                sections.append(formatted.body)
                sections.append("---\n")

        # Low
        if by_severity[Severity.LOW]:
            sections.append("## Low Severity Findings\n")
            for i, finding in enumerate(by_severity[Severity.LOW], 1):
                formatted = self.format_finding(finding)
                sections.append(f"### L-{i:02d}: {finding.title}\n")
                sections.append(formatted.body)
                sections.append("---\n")

        # Informational
        if by_severity[Severity.INFORMATIONAL]:
            sections.append("## Informational Findings\n")
            for i, finding in enumerate(by_severity[Severity.INFORMATIONAL], 1):
                sections.append(f"### I-{i:02d}: {finding.title}\n")
                sections.append(finding.description)
                if finding.recommendation:
                    sections.append(f"\n**Recommendation:** {finding.recommendation}")
                sections.append("\n---\n")

        # Gas
        if by_severity[Severity.GAS]:
            sections.append("## Gas Optimizations\n")
            for i, finding in enumerate(by_severity[Severity.GAS], 1):
                sections.append(f"### G-{i:02d}: {finding.title}\n")
                sections.append(finding.description)
                if finding.recommendation:
                    sections.append(f"\n**Optimization:** {finding.recommendation}")
                sections.append("\n---\n")

        return "\n".join(sections)

    def _get_current_date(self) -> str:
        """Get current date in readable format."""
        from datetime import datetime
        return datetime.now().strftime("%B %d, %Y")
