"""
Finding model with state machine.

State Machine:
    DETECTED → TRIAGED → ACCEPTED → REFINED → EXPORTED
                      ↘ REJECTED
                         ↓
                      ARCHIVED
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class FindingState(Enum):
    """Finding lifecycle states."""
    DETECTED = "detected"      # Raw finding from Hound
    TRIAGED = "triaged"        # Initial severity/validity assessment
    ACCEPTED = "accepted"      # Human confirmed as valid
    REJECTED = "rejected"      # Human marked as false positive
    REFINED = "refined"        # Polished for submission
    EXPORTED = "exported"      # Formatted for platform
    ARCHIVED = "archived"      # Final state


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    GAS = "gas"


# Valid state transitions
FINDING_STATE_TRANSITIONS = {
    FindingState.DETECTED: [FindingState.TRIAGED, FindingState.ARCHIVED],
    FindingState.TRIAGED: [FindingState.ACCEPTED, FindingState.REJECTED],
    FindingState.ACCEPTED: [FindingState.REFINED, FindingState.REJECTED, FindingState.ARCHIVED],
    FindingState.REJECTED: [FindingState.ACCEPTED, FindingState.ARCHIVED],  # Can un-reject
    FindingState.REFINED: [FindingState.EXPORTED, FindingState.ACCEPTED, FindingState.ARCHIVED],
    FindingState.EXPORTED: [FindingState.REFINED, FindingState.ARCHIVED],  # Can go back to refine
    FindingState.ARCHIVED: [],
}


class FindingError(Exception):
    """Finding-related error."""
    pass


class InvalidFindingTransition(FindingError):
    """Invalid state transition attempted."""
    pass


@dataclass
class Finding:
    """A security finding from an audit."""

    # Identity
    id: str
    contest_id: str

    # Core content
    title: str
    description: str
    severity: Severity

    # Location
    file_path: str = ""
    line_start: int | None = None
    line_end: int | None = None
    function_name: str = ""
    contract_name: str = ""

    # State
    state: FindingState = FindingState.DETECTED
    state_history: list[tuple[str, str]] = field(default_factory=list)

    # Classification
    vulnerability_type: str = ""  # reentrancy, access-control, etc.
    category: str = ""  # From Solodit checklist categories

    # Evidence
    code_snippet: str = ""
    proof_of_concept: str = ""
    impact: str = ""
    likelihood: str = ""

    # Remediation
    recommendation: str = ""
    references: list[str] = field(default_factory=list)

    # Source tracking
    source: str = "hound"  # hound, manual, imported
    hypothesis_id: str = ""  # Link to original Hound hypothesis
    confidence: float = 0.0  # Hound's confidence score

    # Review tracking
    reviewer_notes: str = ""
    rejection_reason: str = ""

    # Timestamps
    detected_at: datetime = field(default_factory=datetime.now)
    triaged_at: datetime | None = None
    accepted_at: datetime | None = None
    refined_at: datetime | None = None
    exported_at: datetime | None = None

    # Platform submission
    platform_id: str = ""  # ID assigned by platform after submission
    submission_url: str = ""

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def transition_to(self, new_state: FindingState) -> None:
        """Transition to a new state.

        Args:
            new_state: The state to transition to

        Raises:
            InvalidFindingTransition: If the transition is not valid
        """
        valid_transitions = FINDING_STATE_TRANSITIONS.get(self.state, [])

        if new_state not in valid_transitions:
            raise InvalidFindingTransition(
                f"Cannot transition from {self.state.value} to {new_state.value}. "
                f"Valid transitions: {[s.value for s in valid_transitions]}"
            )

        self.state_history.append((self.state.value, datetime.now().isoformat()))
        self.state = new_state

        # Update timestamps based on state
        now = datetime.now()
        if new_state == FindingState.TRIAGED:
            self.triaged_at = now
        elif new_state == FindingState.ACCEPTED:
            self.accepted_at = now
        elif new_state == FindingState.REFINED:
            self.refined_at = now
        elif new_state == FindingState.EXPORTED:
            self.exported_at = now

    def can_transition_to(self, new_state: FindingState) -> bool:
        """Check if a transition is valid."""
        return new_state in FINDING_STATE_TRANSITIONS.get(self.state, [])

    def accept(self, notes: str = "") -> None:
        """Accept the finding as valid."""
        if self.state == FindingState.DETECTED:
            self.transition_to(FindingState.TRIAGED)
        self.transition_to(FindingState.ACCEPTED)
        if notes:
            self.reviewer_notes = notes

    def reject(self, reason: str) -> None:
        """Reject the finding as false positive."""
        if self.state == FindingState.DETECTED:
            self.transition_to(FindingState.TRIAGED)
        self.transition_to(FindingState.REJECTED)
        self.rejection_reason = reason

    def refine(self, **updates) -> None:
        """Refine the finding with updates."""
        if self.state != FindingState.ACCEPTED:
            raise FindingError("Must accept finding before refining")

        # Apply updates
        for key, value in updates.items():
            if hasattr(self, key):
                setattr(self, key, value)

        self.transition_to(FindingState.REFINED)

    @property
    def is_actionable(self) -> bool:
        """Check if finding is in an actionable state."""
        return self.state in [
            FindingState.DETECTED,
            FindingState.TRIAGED,
            FindingState.ACCEPTED,
            FindingState.REFINED,
        ]

    @property
    def is_exportable(self) -> bool:
        """Check if finding can be exported."""
        return self.state in [FindingState.REFINED, FindingState.EXPORTED]

    @property
    def severity_rank(self) -> int:
        """Get numeric severity rank for sorting (lower = more severe)."""
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4,
            Severity.GAS: 5,
        }.get(self.severity, 99)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "contest_id": self.contest_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "function_name": self.function_name,
            "contract_name": self.contract_name,
            "state": self.state.value,
            "state_history": self.state_history,
            "vulnerability_type": self.vulnerability_type,
            "category": self.category,
            "code_snippet": self.code_snippet,
            "proof_of_concept": self.proof_of_concept,
            "impact": self.impact,
            "likelihood": self.likelihood,
            "recommendation": self.recommendation,
            "references": self.references,
            "source": self.source,
            "hypothesis_id": self.hypothesis_id,
            "confidence": self.confidence,
            "reviewer_notes": self.reviewer_notes,
            "rejection_reason": self.rejection_reason,
            "detected_at": self.detected_at.isoformat(),
            "triaged_at": self.triaged_at.isoformat() if self.triaged_at else None,
            "accepted_at": self.accepted_at.isoformat() if self.accepted_at else None,
            "refined_at": self.refined_at.isoformat() if self.refined_at else None,
            "exported_at": self.exported_at.isoformat() if self.exported_at else None,
            "platform_id": self.platform_id,
            "submission_url": self.submission_url,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            contest_id=data["contest_id"],
            title=data["title"],
            description=data["description"],
            severity=Severity(data.get("severity", "medium")),
            file_path=data.get("file_path", ""),
            line_start=data.get("line_start"),
            line_end=data.get("line_end"),
            function_name=data.get("function_name", ""),
            contract_name=data.get("contract_name", ""),
            state=FindingState(data.get("state", "detected")),
            state_history=data.get("state_history", []),
            vulnerability_type=data.get("vulnerability_type", ""),
            category=data.get("category", ""),
            code_snippet=data.get("code_snippet", ""),
            proof_of_concept=data.get("proof_of_concept", ""),
            impact=data.get("impact", ""),
            likelihood=data.get("likelihood", ""),
            recommendation=data.get("recommendation", ""),
            references=data.get("references", []),
            source=data.get("source", "hound"),
            hypothesis_id=data.get("hypothesis_id", ""),
            confidence=data.get("confidence", 0.0),
            reviewer_notes=data.get("reviewer_notes", ""),
            rejection_reason=data.get("rejection_reason", ""),
            detected_at=datetime.fromisoformat(data["detected_at"]) if data.get("detected_at") else datetime.now(),
            triaged_at=datetime.fromisoformat(data["triaged_at"]) if data.get("triaged_at") else None,
            accepted_at=datetime.fromisoformat(data["accepted_at"]) if data.get("accepted_at") else None,
            refined_at=datetime.fromisoformat(data["refined_at"]) if data.get("refined_at") else None,
            exported_at=datetime.fromisoformat(data["exported_at"]) if data.get("exported_at") else None,
            platform_id=data.get("platform_id", ""),
            submission_url=data.get("submission_url", ""),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_hypothesis(cls, hypothesis: dict, contest_id: str) -> "Finding":
        """Create a Finding from a Hound hypothesis."""
        # Map Hound severity to our severity
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFORMATIONAL,
            "informational": Severity.INFORMATIONAL,
            "gas": Severity.GAS,
        }

        severity_str = hypothesis.get("severity", "medium").lower()
        severity = severity_map.get(severity_str, Severity.MEDIUM)

        return cls(
            id=f"finding-{hypothesis.get('id', 'unknown')}",
            contest_id=contest_id,
            title=hypothesis.get("title", "Untitled Finding"),
            description=hypothesis.get("description", ""),
            severity=severity,
            file_path=hypothesis.get("location", {}).get("file", ""),
            line_start=hypothesis.get("location", {}).get("line_start"),
            line_end=hypothesis.get("location", {}).get("line_end"),
            function_name=hypothesis.get("location", {}).get("function", ""),
            contract_name=hypothesis.get("location", {}).get("contract", ""),
            vulnerability_type=hypothesis.get("vulnerability_type", ""),
            code_snippet=hypothesis.get("evidence", {}).get("code", ""),
            impact=hypothesis.get("impact", ""),
            recommendation=hypothesis.get("recommendation", ""),
            source="hound",
            hypothesis_id=hypothesis.get("id", ""),
            confidence=hypothesis.get("confidence", 0.0),
        )

    def __str__(self) -> str:
        return f"Finding({self.id}, {self.severity.value}, state={self.state.value})"
