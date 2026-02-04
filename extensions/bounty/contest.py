"""
Contest model with state machine.

State Machine:
    DISCOVERED → SCOPED → AUDITING → REVIEW → EXPORTED → SUBMITTED
                    ↑__________|  (can go back to review)
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ContestState(Enum):
    """Contest lifecycle states."""
    DISCOVERED = "discovered"  # Found via scraper, not yet started
    SCOPED = "scoped"          # Scope downloaded, project created
    AUDITING = "auditing"      # Hound running, findings accumulating
    REVIEW = "review"          # Human reviewing findings
    EXPORTED = "exported"      # Formatted for platform submission
    SUBMITTED = "submitted"    # User confirmed manual submission
    ARCHIVED = "archived"      # Contest ended, archived


# Valid state transitions
STATE_TRANSITIONS = {
    ContestState.DISCOVERED: [ContestState.SCOPED, ContestState.ARCHIVED],
    ContestState.SCOPED: [ContestState.AUDITING, ContestState.ARCHIVED],
    ContestState.AUDITING: [ContestState.REVIEW, ContestState.ARCHIVED],
    ContestState.REVIEW: [ContestState.EXPORTED, ContestState.AUDITING, ContestState.ARCHIVED],
    ContestState.EXPORTED: [ContestState.SUBMITTED, ContestState.REVIEW, ContestState.ARCHIVED],
    ContestState.SUBMITTED: [ContestState.ARCHIVED],
    ContestState.ARCHIVED: [],
}


class ContestError(Exception):
    """Contest-related error."""
    pass


class InvalidStateTransition(ContestError):
    """Invalid state transition attempted."""
    pass


@dataclass
class Contest:
    """An audit contest."""

    # Identity
    id: str
    platform: str  # code4rena, sherlock, codehawks, immunefi
    name: str
    url: str

    # State
    state: ContestState = ContestState.DISCOVERED
    state_history: list[tuple[str, str]] = field(default_factory=list)  # [(state, timestamp), ...]

    # Timeline
    start_date: datetime | None = None
    end_date: datetime | None = None
    created_at: datetime = field(default_factory=datetime.now)

    # Scope
    repo_url: str = ""
    contracts: list[str] = field(default_factory=list)
    known_issues: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    docs_url: str = ""

    # Rewards
    prize_pool: str = ""
    severity_rewards: dict[str, str] = field(default_factory=dict)

    # Project link
    project_name: str = ""  # Hound project name
    project_path: str = ""  # Path to project directory

    # Findings
    finding_ids: list[str] = field(default_factory=list)

    # Submission tracking
    exported_at: datetime | None = None
    submitted_at: datetime | None = None
    submission_notes: str = ""

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def transition_to(self, new_state: ContestState) -> None:
        """Transition to a new state.

        Args:
            new_state: The state to transition to

        Raises:
            InvalidStateTransition: If the transition is not valid
        """
        valid_transitions = STATE_TRANSITIONS.get(self.state, [])

        if new_state not in valid_transitions:
            raise InvalidStateTransition(
                f"Cannot transition from {self.state.value} to {new_state.value}. "
                f"Valid transitions: {[s.value for s in valid_transitions]}"
            )

        self.state_history.append((self.state.value, datetime.now().isoformat()))
        self.state = new_state

        # Update timestamps based on state
        if new_state == ContestState.EXPORTED:
            self.exported_at = datetime.now()
        elif new_state == ContestState.SUBMITTED:
            self.submitted_at = datetime.now()

    def can_transition_to(self, new_state: ContestState) -> bool:
        """Check if a transition is valid."""
        return new_state in STATE_TRANSITIONS.get(self.state, [])

    @property
    def is_active(self) -> bool:
        """Check if contest is still active (not archived/submitted)."""
        return self.state not in [ContestState.SUBMITTED, ContestState.ARCHIVED]

    @property
    def is_in_progress(self) -> bool:
        """Check if contest deadline has not passed."""
        if self.end_date is None:
            return True
        return datetime.now() < self.end_date

    @property
    def time_remaining(self) -> str:
        """Get human-readable time remaining."""
        if self.end_date is None:
            return "Unknown"

        delta = self.end_date - datetime.now()
        if delta.total_seconds() < 0:
            return "Ended"

        days = delta.days
        hours = delta.seconds // 3600

        if days > 0:
            return f"{days}d {hours}h"
        elif hours > 0:
            return f"{hours}h"
        else:
            minutes = delta.seconds // 60
            return f"{minutes}m"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "platform": self.platform,
            "name": self.name,
            "url": self.url,
            "state": self.state.value,
            "state_history": self.state_history,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "created_at": self.created_at.isoformat(),
            "repo_url": self.repo_url,
            "contracts": self.contracts,
            "known_issues": self.known_issues,
            "out_of_scope": self.out_of_scope,
            "docs_url": self.docs_url,
            "prize_pool": self.prize_pool,
            "severity_rewards": self.severity_rewards,
            "project_name": self.project_name,
            "project_path": self.project_path,
            "finding_ids": self.finding_ids,
            "exported_at": self.exported_at.isoformat() if self.exported_at else None,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
            "submission_notes": self.submission_notes,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Contest":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            platform=data["platform"],
            name=data["name"],
            url=data["url"],
            state=ContestState(data.get("state", "discovered")),
            state_history=data.get("state_history", []),
            start_date=datetime.fromisoformat(data["start_date"]) if data.get("start_date") else None,
            end_date=datetime.fromisoformat(data["end_date"]) if data.get("end_date") else None,
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            repo_url=data.get("repo_url", ""),
            contracts=data.get("contracts", []),
            known_issues=data.get("known_issues", []),
            out_of_scope=data.get("out_of_scope", []),
            docs_url=data.get("docs_url", ""),
            prize_pool=data.get("prize_pool", ""),
            severity_rewards=data.get("severity_rewards", {}),
            project_name=data.get("project_name", ""),
            project_path=data.get("project_path", ""),
            finding_ids=data.get("finding_ids", []),
            exported_at=datetime.fromisoformat(data["exported_at"]) if data.get("exported_at") else None,
            submitted_at=datetime.fromisoformat(data["submitted_at"]) if data.get("submitted_at") else None,
            submission_notes=data.get("submission_notes", ""),
            metadata=data.get("metadata", {}),
        )

    def __str__(self) -> str:
        return f"Contest({self.platform}/{self.name}, state={self.state.value})"
