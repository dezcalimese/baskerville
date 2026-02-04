"""
Bounty storage for persisting contest and finding state.

Stores data in ~/.hound/bounty/ with the following structure:
    ~/.hound/bounty/
        contests/
            {contest_id}.json
        findings/
            {contest_id}/
                {finding_id}.json
        index.json  # Quick lookup of all contests
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Iterator

from .contest import Contest, ContestState
from .finding import Finding, FindingState


class BountyStorage:
    """Persistent storage for bounty workflow data."""

    def __init__(self, base_dir: Path | None = None):
        """Initialize storage.

        Args:
            base_dir: Base directory for bounty data. Defaults to ~/.hound/bounty
        """
        if base_dir is None:
            base_dir = Path.home() / ".hound" / "bounty"

        self.base_dir = base_dir
        self.contests_dir = base_dir / "contests"
        self.findings_dir = base_dir / "findings"
        self.index_path = base_dir / "index.json"

        # Ensure directories exist
        self.contests_dir.mkdir(parents=True, exist_ok=True)
        self.findings_dir.mkdir(parents=True, exist_ok=True)

        # Load or create index
        self._index = self._load_index()

    def _load_index(self) -> dict:
        """Load the contest index."""
        if self.index_path.exists():
            try:
                return json.loads(self.index_path.read_text())
            except Exception:
                pass
        return {"contests": {}, "updated_at": datetime.now().isoformat()}

    def _save_index(self) -> None:
        """Save the contest index."""
        self._index["updated_at"] = datetime.now().isoformat()
        self.index_path.write_text(json.dumps(self._index, indent=2))

    # Contest operations

    def save_contest(self, contest: Contest) -> None:
        """Save a contest to storage."""
        contest_path = self.contests_dir / f"{contest.id}.json"
        contest_path.write_text(json.dumps(contest.to_dict(), indent=2))

        # Update index
        self._index["contests"][contest.id] = {
            "platform": contest.platform,
            "name": contest.name,
            "state": contest.state.value,
            "end_date": contest.end_date.isoformat() if contest.end_date else None,
            "updated_at": datetime.now().isoformat(),
        }
        self._save_index()

    def load_contest(self, contest_id: str) -> Contest | None:
        """Load a contest from storage."""
        contest_path = self.contests_dir / f"{contest_id}.json"
        if not contest_path.exists():
            return None

        try:
            data = json.loads(contest_path.read_text())
            return Contest.from_dict(data)
        except Exception as e:
            print(f"[!] Failed to load contest {contest_id}: {e}")
            return None

    def delete_contest(self, contest_id: str) -> bool:
        """Delete a contest and all its findings."""
        # Delete contest file
        contest_path = self.contests_dir / f"{contest_id}.json"
        if contest_path.exists():
            contest_path.unlink()

        # Delete findings directory
        findings_dir = self.findings_dir / contest_id
        if findings_dir.exists():
            for finding_file in findings_dir.glob("*.json"):
                finding_file.unlink()
            findings_dir.rmdir()

        # Update index
        if contest_id in self._index["contests"]:
            del self._index["contests"][contest_id]
            self._save_index()
            return True

        return False

    def list_contests(
        self,
        platform: str | None = None,
        state: ContestState | None = None,
        active_only: bool = False,
    ) -> list[Contest]:
        """List contests with optional filters."""
        contests = []

        for contest_id in self._index.get("contests", {}):
            contest = self.load_contest(contest_id)
            if contest is None:
                continue

            # Apply filters
            if platform and contest.platform != platform:
                continue
            if state and contest.state != state:
                continue
            if active_only and not contest.is_active:
                continue

            contests.append(contest)

        # Sort by end date (soonest first)
        contests.sort(key=lambda c: c.end_date or datetime.max)
        return contests

    def get_contest_by_url(self, url: str) -> Contest | None:
        """Find a contest by its URL."""
        for contest_id in self._index.get("contests", {}):
            contest = self.load_contest(contest_id)
            if contest and contest.url == url:
                return contest
        return None

    def iter_contests(self) -> Iterator[Contest]:
        """Iterate over all contests."""
        for contest_id in self._index.get("contests", {}):
            contest = self.load_contest(contest_id)
            if contest:
                yield contest

    # Finding operations

    def save_finding(self, finding: Finding) -> None:
        """Save a finding to storage."""
        # Ensure contest findings directory exists
        contest_findings_dir = self.findings_dir / finding.contest_id
        contest_findings_dir.mkdir(parents=True, exist_ok=True)

        finding_path = contest_findings_dir / f"{finding.id}.json"
        finding_path.write_text(json.dumps(finding.to_dict(), indent=2))

        # Update contest's finding_ids list
        contest = self.load_contest(finding.contest_id)
        if contest and finding.id not in contest.finding_ids:
            contest.finding_ids.append(finding.id)
            self.save_contest(contest)

    def load_finding(self, contest_id: str, finding_id: str) -> Finding | None:
        """Load a finding from storage."""
        finding_path = self.findings_dir / contest_id / f"{finding_id}.json"
        if not finding_path.exists():
            return None

        try:
            data = json.loads(finding_path.read_text())
            return Finding.from_dict(data)
        except Exception as e:
            print(f"[!] Failed to load finding {finding_id}: {e}")
            return None

    def delete_finding(self, contest_id: str, finding_id: str) -> bool:
        """Delete a finding."""
        finding_path = self.findings_dir / contest_id / f"{finding_id}.json"
        if finding_path.exists():
            finding_path.unlink()

            # Update contest's finding_ids list
            contest = self.load_contest(contest_id)
            if contest and finding_id in contest.finding_ids:
                contest.finding_ids.remove(finding_id)
                self.save_contest(contest)
            return True

        return False

    def list_findings(
        self,
        contest_id: str,
        state: FindingState | None = None,
        severity: str | None = None,
    ) -> list[Finding]:
        """List findings for a contest with optional filters."""
        findings = []
        contest_findings_dir = self.findings_dir / contest_id

        if not contest_findings_dir.exists():
            return findings

        for finding_file in contest_findings_dir.glob("*.json"):
            finding = self.load_finding(contest_id, finding_file.stem)
            if finding is None:
                continue

            # Apply filters
            if state and finding.state != state:
                continue
            if severity and finding.severity.value != severity:
                continue

            findings.append(finding)

        # Sort by severity (most severe first)
        findings.sort(key=lambda f: f.severity_rank)
        return findings

    def iter_findings(self, contest_id: str) -> Iterator[Finding]:
        """Iterate over all findings for a contest."""
        contest_findings_dir = self.findings_dir / contest_id
        if not contest_findings_dir.exists():
            return

        for finding_file in contest_findings_dir.glob("*.json"):
            finding = self.load_finding(contest_id, finding_file.stem)
            if finding:
                yield finding

    def get_findings_by_state(self, contest_id: str, state: FindingState) -> list[Finding]:
        """Get all findings in a specific state."""
        return self.list_findings(contest_id, state=state)

    def get_exportable_findings(self, contest_id: str) -> list[Finding]:
        """Get all findings ready for export."""
        findings = []
        for finding in self.iter_findings(contest_id):
            if finding.is_exportable:
                findings.append(finding)
        findings.sort(key=lambda f: f.severity_rank)
        return findings

    # Statistics

    def contest_stats(self, contest_id: str) -> dict:
        """Get statistics for a contest."""
        findings = list(self.iter_findings(contest_id))

        by_state = {}
        by_severity = {}

        for finding in findings:
            state = finding.state.value
            severity = finding.severity.value

            by_state[state] = by_state.get(state, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1

        return {
            "total_findings": len(findings),
            "by_state": by_state,
            "by_severity": by_severity,
            "accepted": by_state.get("accepted", 0) + by_state.get("refined", 0) + by_state.get("exported", 0),
            "rejected": by_state.get("rejected", 0),
            "pending_review": by_state.get("detected", 0) + by_state.get("triaged", 0),
        }

    def global_stats(self) -> dict:
        """Get global bounty statistics."""
        contests = list(self.iter_contests())

        total_findings = 0
        total_accepted = 0
        total_exported = 0
        by_platform = {}
        by_state = {}

        for contest in contests:
            platform = contest.platform
            state = contest.state.value

            by_platform[platform] = by_platform.get(platform, 0) + 1
            by_state[state] = by_state.get(state, 0) + 1

            stats = self.contest_stats(contest.id)
            total_findings += stats["total_findings"]
            total_accepted += stats["accepted"]
            total_exported += stats.get("by_state", {}).get("exported", 0)

        return {
            "total_contests": len(contests),
            "total_findings": total_findings,
            "total_accepted": total_accepted,
            "total_exported": total_exported,
            "contests_by_platform": by_platform,
            "contests_by_state": by_state,
        }

    # Import/Export

    def import_hypotheses(self, contest_id: str, hypotheses_path: Path) -> list[Finding]:
        """Import Hound hypotheses as findings."""
        if not hypotheses_path.exists():
            return []

        try:
            data = json.loads(hypotheses_path.read_text())
        except Exception as e:
            print(f"[!] Failed to load hypotheses: {e}")
            return []

        findings = []
        hypotheses = data if isinstance(data, list) else data.get("hypotheses", [])

        for hyp in hypotheses:
            # Skip already imported
            finding_id = f"finding-{hyp.get('id', 'unknown')}"
            existing = self.load_finding(contest_id, finding_id)
            if existing:
                continue

            finding = Finding.from_hypothesis(hyp, contest_id)
            self.save_finding(finding)
            findings.append(finding)

        return findings

    def export_findings_json(self, contest_id: str, output_path: Path) -> int:
        """Export findings to JSON file."""
        findings = self.get_exportable_findings(contest_id)
        data = [f.to_dict() for f in findings]
        output_path.write_text(json.dumps(data, indent=2))
        return len(findings)
