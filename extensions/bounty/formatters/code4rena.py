"""
Code4rena submission formatter.

Code4rena format requirements:
- Title: [Severity]-[N] Brief description
- Sections: Summary, Vulnerability Detail, Impact, Proof of Concept, Recommended Mitigation
- Code blocks with line references
- GitHub-style links for file references
"""

from ..finding import Finding, Severity
from .base import BaseFormatter, FormattedFinding


class Code4renaFormatter(BaseFormatter):
    """Formatter for Code4rena submissions."""

    platform = "code4rena"

    severity_map = {
        Severity.CRITICAL: "H",  # Code4rena uses H for critical/high
        Severity.HIGH: "H",
        Severity.MEDIUM: "M",
        Severity.LOW: "L",
        Severity.INFORMATIONAL: "NC",  # Non-critical
        Severity.GAS: "G",
    }

    def format_finding(self, finding: Finding) -> FormattedFinding:
        """Format finding for Code4rena submission."""
        severity_label = self.severity_label(finding.severity)

        # Build title
        title = f"[{severity_label}] {finding.title}"

        # Build body sections
        sections = []

        # Lines of code (if available)
        if finding.file_path:
            sections.append("## Lines of code\n")
            location = self.format_location(finding)
            # Code4rena expects GitHub links - placeholder for repo URL
            sections.append(f"- {location}\n")

        # Vulnerability details
        sections.append("## Vulnerability details\n")
        sections.append(finding.description)
        sections.append("")

        # Code snippet if available
        if finding.code_snippet:
            sections.append("### Vulnerable code\n")
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
            sections.append(self.format_code_block(finding.proof_of_concept))
            sections.append("")

        # Recommended Mitigation
        sections.append("## Recommended Mitigation\n")
        if finding.recommendation:
            sections.append(finding.recommendation)
        else:
            sections.append("Consider implementing appropriate security controls for this vulnerability.")
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
            labels=[severity_label, finding.vulnerability_type] if finding.vulnerability_type else [severity_label],
            metadata={
                "finding_id": finding.id,
                "contract": finding.contract_name,
                "function": finding.function_name,
            },
        )

    def _generate_impact(self, finding: Finding) -> str:
        """Generate impact description based on severity."""
        impacts = {
            Severity.CRITICAL: "This vulnerability could lead to complete loss of funds or protocol compromise.",
            Severity.HIGH: "This vulnerability could result in significant financial loss or protocol malfunction.",
            Severity.MEDIUM: "This vulnerability could cause moderate impact to protocol functionality or user funds.",
            Severity.LOW: "This vulnerability has limited impact but should be addressed for code quality.",
            Severity.INFORMATIONAL: "This is an informational finding that could improve code quality.",
            Severity.GAS: "This optimization could reduce gas costs for users.",
        }
        return impacts.get(finding.severity, "Impact analysis pending.")

    def format_qa_report(self, findings: list[Finding]) -> str:
        """Format multiple low/NC findings into a single QA report."""
        sections = ["# QA Report\n"]

        low_findings = [f for f in findings if f.severity == Severity.LOW]
        nc_findings = [f for f in findings if f.severity in [Severity.INFORMATIONAL]]

        if low_findings:
            sections.append("## Low Risk Issues\n")
            for i, finding in enumerate(low_findings, 1):
                sections.append(f"### [L-{i:02d}] {finding.title}\n")
                sections.append(finding.description)
                if finding.recommendation:
                    sections.append(f"\n**Recommendation:** {finding.recommendation}")
                sections.append("")

        if nc_findings:
            sections.append("## Non-Critical Issues\n")
            for i, finding in enumerate(nc_findings, 1):
                sections.append(f"### [NC-{i:02d}] {finding.title}\n")
                sections.append(finding.description)
                if finding.recommendation:
                    sections.append(f"\n**Recommendation:** {finding.recommendation}")
                sections.append("")

        return "\n".join(sections)

    def format_gas_report(self, findings: list[Finding]) -> str:
        """Format gas optimization findings into a single report."""
        gas_findings = [f for f in findings if f.severity == Severity.GAS]

        sections = ["# Gas Optimizations Report\n"]

        for i, finding in enumerate(gas_findings, 1):
            sections.append(f"### [G-{i:02d}] {finding.title}\n")
            sections.append(finding.description)
            if finding.code_snippet:
                sections.append("\n**Current code:**")
                sections.append(self.format_code_block(finding.code_snippet))
            if finding.recommendation:
                sections.append(f"\n**Recommended change:** {finding.recommendation}")
            sections.append("")

        return "\n".join(sections)
