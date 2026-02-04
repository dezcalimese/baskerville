"""
Checklist loader for security auditing.

Hybrid approach:
- Imports Solodit's official checklist from GitHub/cache
- Merges with custom YAML checklists for protocol-specific checks
"""

import json
import yaml
import aiohttp
import asyncio
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterator


SOLODIT_CHECKLIST_URL = "https://raw.githubusercontent.com/Cyfrin/audit-checklist/main/checklist.json"
CACHE_TTL = timedelta(days=7)


@dataclass
class ChecklistItem:
    """A single checklist item."""
    id: str
    category: str
    subcategory: str
    question: str
    description: str
    remediation: str
    severity: str  # critical, high, medium, low, informational
    tags: list[str]
    references: list[str]
    source: str  # "solodit" or "custom"

    def matches(self, query: str) -> bool:
        """Check if item matches a search query."""
        query_lower = query.lower()
        return (
            query_lower in self.question.lower() or
            query_lower in self.description.lower() or
            query_lower in self.category.lower() or
            query_lower in self.subcategory.lower() or
            any(query_lower in tag.lower() for tag in self.tags)
        )


class ChecklistLoader:
    """Loads and queries security checklists from Solodit + custom sources."""

    def __init__(self, base_dir: Path | None = None):
        """Initialize loader.

        Args:
            base_dir: Path to knowledge base directory
        """
        if base_dir is None:
            base_dir = Path(__file__).parent

        self.checklists_dir = base_dir / "checklists"
        self.cache_path = base_dir / "checklists" / ".solodit_cache.json"

        self._items: list[ChecklistItem] = []
        self._by_category: dict[str, list[ChecklistItem]] = {}
        self._loaded = False

    async def _fetch_solodit_checklist(self) -> list[dict] | None:
        """Fetch Solodit checklist from GitHub."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(SOLODIT_CHECKLIST_URL, timeout=30) as resp:
                    if resp.status == 200:
                        # GitHub raw returns text/plain, so parse manually
                        text = await resp.text()
                        return json.loads(text)
        except Exception as e:
            print(f"[!] Failed to fetch Solodit checklist: {e}")
        return None

    def _load_cached_solodit(self) -> list[dict] | None:
        """Load cached Solodit checklist if fresh."""
        if not self.cache_path.exists():
            return None

        try:
            cache_data = json.loads(self.cache_path.read_text())
            cached_at = datetime.fromisoformat(cache_data.get("cached_at", ""))
            if datetime.now() - cached_at < CACHE_TTL:
                return cache_data.get("data", [])
        except Exception:
            pass
        return None

    def _save_solodit_cache(self, data: list[dict]) -> None:
        """Cache Solodit checklist."""
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_data = {
            "cached_at": datetime.now().isoformat(),
            "data": data,
        }
        self.cache_path.write_text(json.dumps(cache_data, indent=2))

    def _parse_solodit_checklist(self, data: list[dict]) -> list[ChecklistItem]:
        """Parse Solodit's nested checklist format."""
        items = []

        for category_block in data:
            category = category_block.get("category", "Unknown")

            # Handle nested structure
            for item_or_subcategory in category_block.get("data", []):
                if "data" in item_or_subcategory:
                    # It's a subcategory with nested items
                    subcategory = item_or_subcategory.get("category", "")
                    for item in item_or_subcategory.get("data", []):
                        items.append(self._parse_solodit_item(item, category, subcategory))
                else:
                    # It's a direct item
                    items.append(self._parse_solodit_item(item_or_subcategory, category, ""))

        return items

    def _parse_solodit_item(self, item: dict, category: str, subcategory: str) -> ChecklistItem:
        """Parse a single Solodit checklist item."""
        # Infer severity from ID or category
        item_id = item.get("id", "")
        severity = self._infer_severity(item_id, category)

        return ChecklistItem(
            id=item_id,
            category=category,
            subcategory=subcategory,
            question=item.get("question", ""),
            description=item.get("description", ""),
            remediation=item.get("remediation", ""),
            severity=severity,
            tags=item.get("tags", []),
            references=item.get("references", []),
            source="solodit",
        )

    def _infer_severity(self, item_id: str, category: str) -> str:
        """Infer severity from item ID or category."""
        category_lower = category.lower()

        # High severity categories
        if any(kw in category_lower for kw in ["reentrancy", "access control", "oracle", "flash"]):
            return "high"

        # Critical for certain attack types
        if "attack" in category_lower and any(kw in category_lower for kw in ["dos", "manipulation"]):
            return "high"

        return "medium"

    def _load_custom_checklists(self) -> list[ChecklistItem]:
        """Load custom YAML checklists."""
        items = []

        if not self.checklists_dir.exists():
            return items

        for yaml_file in self.checklists_dir.glob("*.yaml"):
            try:
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)

                if not data:
                    continue

                category = data.get("category", yaml_file.stem)

                for item_data in data.get("items", []):
                    items.append(ChecklistItem(
                        id=item_data.get("id", ""),
                        category=category,
                        subcategory=item_data.get("subcategory", ""),
                        question=item_data.get("question", ""),
                        description=item_data.get("description", ""),
                        remediation=item_data.get("remediation", ""),
                        severity=item_data.get("severity", "medium"),
                        tags=item_data.get("tags", []),
                        references=item_data.get("references", []),
                        source="custom",
                    ))
            except Exception as e:
                print(f"[!] Failed to load custom checklist {yaml_file}: {e}")

        return items

    def _load_sync(self) -> None:
        """Load all checklists synchronously."""
        if self._loaded:
            return

        self._items = []
        self._by_category = {}

        # Load Solodit checklist (from cache or fetch)
        solodit_data = self._load_cached_solodit()
        if solodit_data is None:
            # Try to fetch fresh
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            solodit_data = loop.run_until_complete(self._fetch_solodit_checklist())
            if solodit_data:
                self._save_solodit_cache(solodit_data)

        # Parse Solodit items
        if solodit_data:
            self._items.extend(self._parse_solodit_checklist(solodit_data))

        # Load custom checklists
        self._items.extend(self._load_custom_checklists())

        # Index by category
        for item in self._items:
            if item.category not in self._by_category:
                self._by_category[item.category] = []
            self._by_category[item.category].append(item)

        self._loaded = True

    async def load(self) -> None:
        """Load all checklists asynchronously."""
        if self._loaded:
            return

        self._items = []
        self._by_category = {}

        # Load Solodit checklist
        solodit_data = self._load_cached_solodit()
        if solodit_data is None:
            solodit_data = await self._fetch_solodit_checklist()
            if solodit_data:
                self._save_solodit_cache(solodit_data)

        if solodit_data:
            self._items.extend(self._parse_solodit_checklist(solodit_data))

        # Load custom checklists
        self._items.extend(self._load_custom_checklists())

        # Index by category
        for item in self._items:
            if item.category not in self._by_category:
                self._by_category[item.category] = []
            self._by_category[item.category].append(item)

        self._loaded = True

    def get_all(self) -> list[ChecklistItem]:
        """Get all checklist items."""
        self._load_sync()
        return self._items

    def get_by_category(self, category: str) -> list[ChecklistItem]:
        """Get checklist items by category (fuzzy match)."""
        self._load_sync()
        category_lower = category.lower()

        results = []
        for cat_name, items in self._by_category.items():
            if category_lower in cat_name.lower():
                results.extend(items)

        return results

    def get_categories(self) -> list[str]:
        """Get all available categories."""
        self._load_sync()
        return list(self._by_category.keys())

    def search(self, query: str, limit: int = 50) -> list[ChecklistItem]:
        """Search checklist items by query."""
        self._load_sync()
        matches = [item for item in self._items if item.matches(query)]
        return matches[:limit]

    def get_by_severity(self, severity: str) -> list[ChecklistItem]:
        """Get checklist items by severity level."""
        self._load_sync()
        return [item for item in self._items if item.severity.lower() == severity.lower()]

    def get_by_tags(self, tags: list[str]) -> list[ChecklistItem]:
        """Get checklist items matching any of the given tags."""
        self._load_sync()
        tags_lower = [t.lower() for t in tags]
        return [
            item for item in self._items
            if any(t.lower() in tags_lower for t in item.tags)
        ]

    def get_solodit_items(self) -> list[ChecklistItem]:
        """Get only Solodit checklist items."""
        self._load_sync()
        return [item for item in self._items if item.source == "solodit"]

    def get_custom_items(self) -> list[ChecklistItem]:
        """Get only custom checklist items."""
        self._load_sync()
        return [item for item in self._items if item.source == "custom"]

    def iter_items(self) -> Iterator[ChecklistItem]:
        """Iterate over all checklist items."""
        self._load_sync()
        yield from self._items

    def count(self) -> int:
        """Get total number of checklist items."""
        self._load_sync()
        return len(self._items)

    def stats(self) -> dict:
        """Get statistics about loaded checklists."""
        self._load_sync()
        return {
            "total": len(self._items),
            "solodit": len([i for i in self._items if i.source == "solodit"]),
            "custom": len([i for i in self._items if i.source == "custom"]),
            "categories": len(self._by_category),
        }
