"""
Local cache for Solodit data.

Caches findings and checklist data locally to reduce API calls
and enable offline access.
"""

import json
import sqlite3
import time
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import aiohttp

from .client import SoloditFinding


class SoloditCache:
    """SQLite-based cache for Solodit data."""

    # Checklist source
    CHECKLIST_URL = "https://raw.githubusercontent.com/Cyfrin/audit-checklist/main/checklist.json"
    CHECKLIST_TTL = timedelta(days=7)

    # Finding cache TTL
    FINDING_TTL = timedelta(days=1)

    def __init__(self, cache_dir: Path | None = None):
        """Initialize cache.

        Args:
            cache_dir: Directory for cache files. Defaults to ~/.hound/cache/solodit/
        """
        if cache_dir is None:
            cache_dir = Path.home() / ".hound" / "cache" / "solodit"
        cache_dir.mkdir(parents=True, exist_ok=True)

        self.cache_dir = cache_dir
        self.db_path = cache_dir / "solodit_cache.db"
        self.checklist_path = cache_dir / "checklist.json"

        self._init_db()

    def _init_db(self):
        """Initialize SQLite database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    slug TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    cached_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS searches (
                    query_hash TEXT PRIMARY KEY,
                    keywords TEXT NOT NULL,
                    results TEXT NOT NULL,
                    total_count INTEGER NOT NULL,
                    cached_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_cached
                ON findings(cached_at)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_searches_cached
                ON searches(cached_at)
            """)
            conn.commit()

    def _query_hash(self, keywords: str, page: int, severity: str | None) -> str:
        """Generate hash for search query."""
        import hashlib
        key = f"{keywords}|{page}|{severity or ''}"
        return hashlib.md5(key.encode()).hexdigest()

    def get_cached_search(
        self,
        keywords: str,
        page: int = 1,
        severity: str | None = None,
    ) -> tuple[list[SoloditFinding], int] | None:
        """Get cached search results if fresh.

        Returns:
            (findings, total_count) or None if not cached/expired
        """
        query_hash = self._query_hash(keywords, page, severity)
        cutoff = time.time() - self.FINDING_TTL.total_seconds()

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT results, total_count FROM searches WHERE query_hash = ? AND cached_at > ?",
                (query_hash, cutoff),
            ).fetchone()

            if row:
                results_data = json.loads(row[0])
                findings = [SoloditFinding.from_api_response(f) for f in results_data]
                return findings, row[1]

        return None

    def cache_search(
        self,
        keywords: str,
        page: int,
        severity: str | None,
        findings: list[SoloditFinding],
        total_count: int,
    ):
        """Cache search results."""
        query_hash = self._query_hash(keywords, page, severity)
        results_json = json.dumps([f.raw_data for f in findings])

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO searches (query_hash, keywords, results, total_count, cached_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (query_hash, keywords, results_json, total_count, time.time()),
            )
            conn.commit()

    def get_cached_finding(self, slug: str) -> SoloditFinding | None:
        """Get cached finding if fresh."""
        cutoff = time.time() - self.FINDING_TTL.total_seconds()

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT data FROM findings WHERE slug = ? AND cached_at > ?",
                (slug, cutoff),
            ).fetchone()

            if row:
                data = json.loads(row[0])
                return SoloditFinding.from_api_response(data)

        return None

    def cache_finding(self, finding: SoloditFinding):
        """Cache a finding."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO findings (slug, data, cached_at)
                VALUES (?, ?, ?)
                """,
                (finding.slug, json.dumps(finding.raw_data), time.time()),
            )
            conn.commit()

    async def get_checklist(self, force_refresh: bool = False) -> dict[str, Any]:
        """Get Solodit checklist, using cache if fresh.

        Args:
            force_refresh: Force download even if cache is fresh

        Returns:
            Checklist data as dict
        """
        # Check cache
        if not force_refresh and self.checklist_path.exists():
            # Check age
            mtime = datetime.fromtimestamp(self.checklist_path.stat().st_mtime)
            if datetime.now() - mtime < self.CHECKLIST_TTL:
                return json.loads(self.checklist_path.read_text())

        # Download fresh copy
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.CHECKLIST_URL) as response:
                    response.raise_for_status()
                    data = await response.json()
                    self.checklist_path.write_text(json.dumps(data, indent=2))
                    return data
        except Exception as e:
            # Fall back to cached version if available
            if self.checklist_path.exists():
                print(f"[!] Failed to refresh checklist, using cache: {e}")
                return json.loads(self.checklist_path.read_text())
            raise

    def get_checklist_sync(self, force_refresh: bool = False) -> dict[str, Any]:
        """Synchronous version of get_checklist."""
        import asyncio

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(self.get_checklist(force_refresh))

    def get_checklist_category(self, category: str) -> list[dict]:
        """Get checklist items for a specific category.

        Args:
            category: Category name (e.g., "reentrancy", "access-control")

        Returns:
            List of checklist items
        """
        # Try to read from cache file directly (avoids async issues)
        if self.checklist_path.exists():
            try:
                checklist = json.loads(self.checklist_path.read_text())
            except Exception:
                return []
        else:
            # No cached checklist available
            return []

        # Search for category (case-insensitive)
        category_lower = category.lower()
        for cat_name, cat_data in checklist.items():
            if category_lower in cat_name.lower():
                return cat_data.get("data", [])

        return []

    def cleanup_expired(self):
        """Remove expired cache entries."""
        finding_cutoff = time.time() - self.FINDING_TTL.total_seconds()

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM findings WHERE cached_at < ?", (finding_cutoff,))
            conn.execute("DELETE FROM searches WHERE cached_at < ?", (finding_cutoff,))
            conn.execute("VACUUM")
            conn.commit()

    def get_cache_stats(self) -> dict[str, int]:
        """Get cache statistics."""
        with sqlite3.connect(self.db_path) as conn:
            findings_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            searches_count = conn.execute("SELECT COUNT(*) FROM searches").fetchone()[0]

        checklist_size = (
            self.checklist_path.stat().st_size
            if self.checklist_path.exists()
            else 0
        )

        return {
            "cached_findings": findings_count,
            "cached_searches": searches_count,
            "checklist_size_bytes": checklist_size,
        }
