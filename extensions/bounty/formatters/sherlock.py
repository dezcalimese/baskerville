"""
Sherlock submission formatter.

Sherlock format requirements:
- Title format: Protocol - Brief description
- Sections: Summary, Vulnerability Detail, Impact, Code Snippet, Tool used, Recommendation
- Severity in separate field
- Markdown with specific structure
"""

from ..finding import Finding, Severity
from .base import BaseFormatter, FormattedFinding


class SherlockFormatter(BaseFormatter):
    """Formatter for Sherlock submissions."""

    platform = "sherlock"

    severity_map = {
        Severity.CRITICAL: "High",  # Sherlock typically uses High as top severity
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFORMATIONAL: "Informational",
        Severity.GAS: "Gas",
    }

    def format_finding(self, finding: Finding) -> FormattedFinding:
        """Format finding for Sherlock submission."""
        severity_label = self.severity_label(finding.severity)

        # Sherlock title format: usually just the vulnerability description
        title = finding.title

        # Build body sections
        sections = []

        # Summary
        sections.append("## Summary\n")
        summary = finding.description.split('\n')[0] if finding.description else finding.title
        sections.append(summary)
        sections.append("")

        # Vulnerability Detail
        sections.append("## Vulnerability Detail\n")
        sections.append(finding.description)
        sections.append("")

        # Root Cause (if identifiable)
        if finding.vulnerability_type:
            sections.append("## Root Cause\n")
            sections.append(f"The root cause is a {finding.vulnerability_type} vulnerability.")
            sections.append("")

        # Code snippet
        if finding.code_snippet:
            sections.append("## Code Snippet\n")
            location = self.format_location(finding)
            sections.append(f"Location: `{location}`\n")
            sections.append(self.format_code_block(finding.code_snippet))
            sections.append("")

        # Impact
        sections.append("## Impact\n")
        if finding.impact:
            sections.append(finding.impact)
        else:
            sections.append(self._generate_impact(finding))
        sections.append("")

        # Likelihood (Sherlock uses impact + likelihood for severity)
        if finding.likelihood:
            sections.append("## Likelihood\n")
            sections.append(finding.likelihood)
            sections.append("")

        # Proof of Concept
        if finding.proof_of_concept:
            sections.append("## Proof of Concept\n")
            sections.append(self.format_code_block(finding.proof_of_concept, "solidity"))
            sections.append("")

        # Tool used
        sections.append("## Tool used\n")
        sections.append("Manual Review, Hound AI-assisted analysis")
        sections.append("")

        # Recommendation
        sections.append("## Recommendation\n")
        if finding.recommendation:
            sections.append(finding.recommendation)
        else:
            sections.append("Implement appropriate security measures to mitigate this vulnerability.")
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
            labels=[finding.vulnerability_type] if finding.vulnerability_type else None,
            metadata={
                "finding_id": finding.id,
                "contract": finding.contract_name,
                "function": finding.function_name,
                "file": finding.file_path,
            },
        )

    def _generate_impact(self, finding: Finding) -> str:
        """Generate impact description based on severity."""
        impacts = {
            Severity.CRITICAL: "Critical impact - could result in direct loss of funds or complete protocol compromise.",
            Severity.HIGH: "High impact - significant financial loss or major protocol malfunction possible.",
            Severity.MEDIUM: "Medium impact - could affect protocol functionality or cause limited fund loss under specific conditions.",
            Severity.LOW: "Low impact - minor issues that don't directly affect funds but should be fixed.",
            Severity.INFORMATIONAL: "Informational - code quality or best practice suggestions.",
            Severity.GAS: "Gas optimization - no security impact but could save gas costs.",
        }
        return impacts.get(finding.severity, "Impact assessment pending.")

    def format_duplicate_report(self, primary: Finding, duplicates: list[Finding]) -> str:
        """Format a finding with its duplicates (Sherlock groups similar issues)."""
        sections = [f"# {primary.title}\n"]

        # Primary finding
        formatted = self.format_finding(primary)
        sections.append(formatted.body)

        # Duplicates section
        if duplicates:
            sections.append("---\n")
            sections.append("## Duplicate Submissions\n")
            sections.append(f"This issue has {len(duplicates)} duplicate(s):\n")
            for dup in duplicates:
                sections.append(f"- **{dup.id}**: {dup.title}")
            sections.append("")

        return "\n".join(sections)
