"""
Immunefi submission formatter.

Immunefi format requirements:
- Bug bounty specific format
- Clear proof of concept is essential
- Severity based on impact categories (Critical/High/Medium/Low)
- Specific sections: Vulnerability, Impact, Steps to Reproduce, Fix Recommendation
- KYC compliance notes if applicable
"""

from ..finding import Finding, Severity
from .base import BaseFormatter, FormattedFinding


class ImmunefiFormatter(BaseFormatter):
    """Formatter for Immunefi bug bounty submissions."""

    platform = "immunefi"

    severity_map = {
        Severity.CRITICAL: "Critical",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFORMATIONAL: "Informational",
        Severity.GAS: "Low",  # Immunefi typically treats gas as low
    }

    # Immunefi impact categories
    IMPACT_CATEGORIES = {
        "smart_contract": [
            "Direct theft of any user funds",
            "Permanent freezing of funds",
            "Protocol insolvency",
            "Theft of unclaimed yield",
            "Theft of governance tokens",
            "Governance voting manipulation",
            "Temporary freezing of funds",
            "Griefing (no profit)",
            "Contract fails to deliver promised returns",
        ],
        "websites_apps": [
            "Execute arbitrary system commands",
            "Retrieve sensitive data",
            "Impersonate other users",
            "Redirect users to malicious websites",
            "Injection attacks",
        ],
    }

    def format_finding(self, finding: Finding) -> FormattedFinding:
        """Format finding for Immunefi submission."""
        severity_label = self.severity_label(finding.severity)

        # Immunefi prefers descriptive titles
        title = finding.title

        # Build body sections
        sections = []

        # Bug Description
        sections.append("## Bug Description\n")
        sections.append(finding.description)
        sections.append("")

        # Affected Component
        sections.append("## Affected Component\n")
        if finding.file_path:
            sections.append(f"**File:** `{finding.file_path}`")
        if finding.contract_name:
            sections.append(f"**Contract:** `{finding.contract_name}`")
        if finding.function_name:
            sections.append(f"**Function:** `{finding.function_name}`")
        if finding.line_start:
            lines = str(finding.line_start)
            if finding.line_end and finding.line_end != finding.line_start:
                lines += f"-{finding.line_end}"
            sections.append(f"**Lines:** {lines}")
        sections.append("")

        # Vulnerable Code
        if finding.code_snippet:
            sections.append("## Vulnerable Code\n")
            sections.append(self.format_code_block(finding.code_snippet))
            sections.append("")

        # Impact
        sections.append("## Impact\n")
        sections.append(f"**Severity:** {severity_label}\n")
        if finding.impact:
            sections.append(finding.impact)
        else:
            sections.append(self._generate_impact(finding))

        # Add impact category suggestion
        impact_cat = self._suggest_impact_category(finding)
        if impact_cat:
            sections.append(f"\n**Impact Category:** {impact_cat}")
        sections.append("")

        # Steps to Reproduce / Proof of Concept
        sections.append("## Proof of Concept\n")
        if finding.proof_of_concept:
            sections.append("### Test Code\n")
            sections.append(self.format_code_block(finding.proof_of_concept))
        else:
            sections.append("### Steps to Reproduce\n")
            sections.append(self._generate_reproduction_steps(finding))
        sections.append("")

        # Attack Scenario
        sections.append("## Attack Scenario\n")
        sections.append(self._generate_attack_scenario(finding))
        sections.append("")

        # Recommended Fix
        sections.append("## Recommended Fix\n")
        if finding.recommendation:
            sections.append(finding.recommendation)
        else:
            sections.append("Implement appropriate security measures to mitigate this vulnerability. "
                         "See references for best practices.")
        sections.append("")

        # References
        if finding.references:
            sections.append("## References\n")
            for ref in finding.references:
                sections.append(f"- {ref}")
            sections.append("")

        # Tool used
        sections.append("## Tool Used\n")
        sections.append("Manual review with Hound AI-assisted security analysis")
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
                "vulnerability_type": finding.vulnerability_type,
                "impact_category": impact_cat,
                "requires_kyc": self._check_kyc_requirement(finding),
            },
        )

    def _generate_impact(self, finding: Finding) -> str:
        """Generate impact description based on severity."""
        impacts = {
            Severity.CRITICAL: (
                "This vulnerability could lead to direct theft of user funds or complete protocol compromise. "
                "An attacker could exploit this to drain funds from the protocol or affected users."
            ),
            Severity.HIGH: (
                "This vulnerability could result in significant financial loss or major protocol disruption. "
                "Exploitation could affect multiple users or lead to substantial fund loss."
            ),
            Severity.MEDIUM: (
                "This vulnerability could cause moderate impact under specific conditions. "
                "While not immediately critical, it could be combined with other issues or exploited in edge cases."
            ),
            Severity.LOW: (
                "This vulnerability has limited direct impact but represents a deviation from security best practices. "
                "It should be addressed to improve the overall security posture."
            ),
            Severity.INFORMATIONAL: (
                "This is an informational finding that could improve code quality or security practices."
            ),
            Severity.GAS: (
                "This optimization could reduce gas costs for users interacting with the protocol."
            ),
        }
        return impacts.get(finding.severity, "Impact assessment pending review.")

    def _suggest_impact_category(self, finding: Finding) -> str | None:
        """Suggest an Immunefi impact category based on the vulnerability."""
        vuln_type = finding.vulnerability_type.lower() if finding.vulnerability_type else ""
        description = finding.description.lower() if finding.description else ""

        # Map vulnerability types to impact categories
        if any(kw in vuln_type or kw in description for kw in ["theft", "drain", "steal"]):
            return "Direct theft of any user funds"
        elif any(kw in vuln_type or kw in description for kw in ["freeze", "lock", "dos"]):
            return "Permanent freezing of funds"
        elif any(kw in vuln_type or kw in description for kw in ["governance", "vote", "voting"]):
            return "Governance voting manipulation"
        elif any(kw in vuln_type or kw in description for kw in ["yield", "reward"]):
            return "Theft of unclaimed yield"
        elif any(kw in vuln_type or kw in description for kw in ["insolvency", "bad debt"]):
            return "Protocol insolvency"
        elif any(kw in vuln_type or kw in description for kw in ["grief", "griefing"]):
            return "Griefing (no profit)"

        return None

    def _generate_reproduction_steps(self, finding: Finding) -> str:
        """Generate reproduction steps when no PoC is available."""
        steps = []
        steps.append("1. Deploy the vulnerable contract to a test network")

        if finding.function_name:
            steps.append(f"2. Call the `{finding.function_name}` function with malicious parameters")
        else:
            steps.append("2. Interact with the affected functionality")

        steps.append("3. Observe the unintended behavior demonstrating the vulnerability")
        steps.append("4. Verify the impact matches the described severity")

        return "\n".join(steps)

    def _generate_attack_scenario(self, finding: Finding) -> str:
        """Generate an attack scenario description."""
        vuln_type = finding.vulnerability_type or "vulnerability"

        return f"""
1. **Attacker Preparation:** The attacker identifies the {vuln_type} in the target contract
2. **Attack Execution:** The attacker crafts a transaction to exploit the vulnerability
3. **Impact:** The vulnerability is triggered, resulting in the described impact
4. **Outcome:** Depending on severity, this could result in fund loss, protocol disruption, or other negative effects
""".strip()

    def _check_kyc_requirement(self, finding: Finding) -> bool:
        """Check if the bounty likely requires KYC (based on severity)."""
        # Higher severity bounties often require KYC for payout
        return finding.severity in [Severity.CRITICAL, Severity.HIGH]

    def format_submission_notes(self, finding: Finding) -> str:
        """Generate additional notes for Immunefi submission."""
        notes = []

        if self._check_kyc_requirement(finding):
            notes.append("**Note:** This submission may require KYC verification for payout due to severity level.")

        notes.append("\n**Disclosure Timeline:**")
        notes.append("- This vulnerability was discovered and reported responsibly through Immunefi's platform.")
        notes.append("- No public disclosure will be made until the project team confirms the fix.")

        return "\n".join(notes)
