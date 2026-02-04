"""
Solodit API client.

Accesses Solodit's vulnerability database via their official API.
Requires API key from environment variable SOLODIT_API_KEY.

API Spec: https://cyfrin.notion.site/Cyfrin-Solodit-Findings-API-Specification
Rate limits: 20 requests/minute, 60 second window
"""

import asyncio
import os
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Literal

import aiohttp


@dataclass
class SoloditFinding:
    """A vulnerability finding from Solodit."""

    id: str
    slug: str
    title: str
    content: str
    impact: str  # HIGH, MEDIUM, LOW, GAS
    quality_score: float
    rarity_score: float
    firm_name: str
    protocol_name: str
    report_date: str | None
    source_link: str | None
    tags: list[str]
    finders: list[str]
    raw_data: dict

    @classmethod
    def from_api_response(cls, data: dict) -> "SoloditFinding":
        """Create from API response data."""
        # Extract tags
        tags = []
        for tag_score in data.get("issues_issuetagscore", []):
            tag_info = tag_score.get("tags_tag", {})
            if tag_info.get("title"):
                tags.append(tag_info["title"])

        # Extract finders
        finders = []
        for finder in data.get("issues_issue_finders", []):
            warden = finder.get("wardens_warden", {})
            if warden.get("handle"):
                finders.append(warden["handle"])

        return cls(
            id=data.get("id", ""),
            slug=data.get("slug", ""),
            title=data.get("title", ""),
            content=data.get("content", ""),
            impact=data.get("impact", "MEDIUM"),
            quality_score=data.get("quality_score", 0),
            rarity_score=data.get("general_score", 0),
            firm_name=data.get("firm_name") or "",
            protocol_name=data.get("protocol_name") or "",
            report_date=data.get("report_date"),
            source_link=data.get("source_link"),
            tags=tags,
            finders=finders,
            raw_data=data,
        )

    @property
    def severity(self) -> str:
        """Map impact to severity for compatibility."""
        return {
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "GAS": "Gas",
        }.get(self.impact, "Medium")

    @property
    def url(self) -> str:
        """Get Solodit URL for this finding."""
        return f"https://solodit.cyfrin.io/issues/{self.slug}"

    def to_hypothesis_context(self) -> dict[str, Any]:
        """Convert to context for enriching a hypothesis."""
        return {
            "solodit_id": self.id,
            "solodit_title": self.title,
            "solodit_slug": self.slug,
            "solodit_severity": self.severity,
            "solodit_impact": self.impact,
            "solodit_protocol": self.protocol_name,
            "solodit_firm": self.firm_name,
            "solodit_tags": self.tags,
            "solodit_url": self.url,
            "solodit_quality": self.quality_score,
        }


class RateLimiter:
    """Sliding window rate limiter.

    Enforces rate limits by tracking request timestamps in a sliding window.
    """

    def __init__(self, max_requests: int = 20, window_seconds: float = 60.0):
        """Initialize rate limiter.

        Args:
            max_requests: Maximum requests allowed in window
            window_seconds: Window duration in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: deque[float] = deque(maxlen=max_requests)
        self._lock = asyncio.Lock()
        # Track server-reported limits
        self._server_remaining: int | None = None
        self._server_reset: float | None = None

    def update_from_headers(self, remaining: int, reset: float) -> None:
        """Update rate limit info from server response."""
        self._server_remaining = remaining
        self._server_reset = reset

    async def acquire(self) -> None:
        """Wait until a request slot is available."""
        async with self._lock:
            now = time.time()

            # If server told us we're out, wait for reset
            if self._server_remaining is not None and self._server_remaining <= 0:
                if self._server_reset and self._server_reset > now:
                    wait_time = self._server_reset - now
                    print(f"[!] Rate limit reached, waiting {wait_time:.1f}s...")
                    await asyncio.sleep(wait_time)
                    self._server_remaining = None

            # Remove expired timestamps
            while self._timestamps and (now - self._timestamps[0]) > self.window_seconds:
                self._timestamps.popleft()

            # If at capacity, wait for oldest to expire
            if len(self._timestamps) >= self.max_requests:
                wait_time = self.window_seconds - (now - self._timestamps[0])
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                    if self._timestamps:
                        self._timestamps.popleft()

            # Record this request
            self._timestamps.append(time.time())

    def remaining(self) -> int:
        """Get remaining requests in current window."""
        if self._server_remaining is not None:
            return self._server_remaining
        now = time.time()
        valid = sum(1 for t in self._timestamps if (now - t) <= self.window_seconds)
        return max(0, self.max_requests - valid)


# Type aliases for filters
ImpactLevel = Literal["HIGH", "MEDIUM", "LOW", "GAS"]
SortField = Literal["Recency", "Quality", "Rarity"]
SortDirection = Literal["Desc", "Asc"]


class SoloditClient:
    """Client for Solodit's official Findings API."""

    BASE_URL = "https://solodit.cyfrin.io/api/v1/solodit"

    def __init__(self, api_key: str | None = None, timeout: int = 30):
        """Initialize client.

        Args:
            api_key: Solodit API key. If None, reads from SOLODIT_API_KEY env var.
            timeout: Request timeout in seconds
        """
        self.api_key = api_key or os.environ.get("SOLODIT_API_KEY")
        self.timeout = timeout
        self._rate_limiter = RateLimiter(max_requests=20, window_seconds=60.0)

    def _check_api_key(self) -> bool:
        """Check if API key is configured."""
        if not self.api_key:
            print("[!] Solodit API key not configured. Set SOLODIT_API_KEY in .env")
            return False
        return True

    async def _request(self, endpoint: str, payload: dict) -> dict | None:
        """Make an authenticated, rate-limited POST request.

        Args:
            endpoint: API endpoint path
            payload: JSON request body

        Returns:
            JSON response or None on error
        """
        if not self._check_api_key():
            return None

        # Wait for rate limit slot
        await self._rate_limiter.acquire()

        url = f"{self.BASE_URL}/{endpoint.lstrip('/')}"
        headers = {
            "Content-Type": "application/json",
            "X-Cyfrin-API-Key": self.api_key,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as response:
                    # Update rate limit from response
                    if "rateLimit" in (data := await response.json()):
                        rl = data["rateLimit"]
                        self._rate_limiter.update_from_headers(
                            rl.get("remaining", 20),
                            rl.get("reset", 0),
                        )

                    if response.status == 429:
                        # Rate limited - wait and retry once
                        reset = data.get("rateLimit", {}).get("reset", time.time() + 60)
                        wait_time = max(1, reset - time.time())
                        print(f"[!] Rate limited, waiting {wait_time:.1f}s...")
                        await asyncio.sleep(wait_time)
                        return await self._request(endpoint, payload)

                    if response.status == 401:
                        print(f"[!] Solodit API: {data.get('message', 'Invalid API key')}")
                        return None

                    response.raise_for_status()
                    return data

        except aiohttp.ClientResponseError as e:
            print(f"[!] Solodit API error: {e.status} {e.message}")
            return None
        except Exception as e:
            print(f"[!] Solodit request error: {e}")
            return None

    async def search_findings(
        self,
        keywords: str | None = None,
        impact: list[ImpactLevel] | None = None,
        tags: list[str] | None = None,
        firms: list[str] | None = None,
        protocol: str | None = None,
        protocol_category: list[str] | None = None,
        languages: list[str] | None = None,
        quality_score: int = 1,
        rarity_score: int = 1,
        sort_field: SortField = "Recency",
        sort_direction: SortDirection = "Desc",
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[SoloditFinding], dict]:
        """Search for vulnerability findings.

        Args:
            keywords: Search in title and content
            impact: Filter by impact level (HIGH, MEDIUM, LOW, GAS)
            tags: Filter by vulnerability tags (Reentrancy, Oracle, etc.)
            firms: Filter by audit firms (Cyfrin, Sherlock, etc.)
            protocol: Protocol name (partial match)
            protocol_category: Protocol categories (DeFi, NFT, etc.)
            languages: Programming languages (Solidity, Rust, etc.)
            quality_score: Minimum quality score (0-5)
            rarity_score: Minimum rarity score (0-5)
            sort_field: Sort by Recency, Quality, or Rarity
            sort_direction: Desc or Asc
            page: Page number (1-indexed)
            page_size: Results per page (max 100)

        Returns:
            Tuple of (findings, metadata)
        """
        filters: dict[str, Any] = {
            "qualityScore": quality_score,
            "rarityScore": rarity_score,
            "sortField": sort_field,
            "sortDirection": sort_direction,
        }

        if keywords:
            filters["keywords"] = keywords
        if impact:
            filters["impact"] = impact
        if tags:
            filters["tags"] = [{"value": t} for t in tags]
        if firms:
            filters["firms"] = [{"value": f} for f in firms]
        if protocol:
            filters["protocol"] = protocol
        if protocol_category:
            filters["protocolCategory"] = [{"value": c} for c in protocol_category]
        if languages:
            filters["languages"] = [{"value": l} for l in languages]

        payload = {
            "page": page,
            "pageSize": min(page_size, 100),
            "filters": filters,
        }

        data = await self._request("findings", payload)

        if not data:
            return [], {"totalResults": 0, "currentPage": page}

        findings = [SoloditFinding.from_api_response(f) for f in data.get("findings", [])]
        metadata = data.get("metadata", {})
        metadata["rateLimit"] = data.get("rateLimit", {})

        return findings, metadata

    async def get_finding_by_slug(self, slug: str) -> SoloditFinding | None:
        """Get a specific finding by slug.

        Note: Uses search with exact slug match as there's no dedicated endpoint.
        """
        # Search for the specific finding
        findings, _ = await self.search_findings(keywords=slug, page_size=10)

        for f in findings:
            if f.slug == slug:
                return f
        return None

    async def search_by_category(
        self,
        category: str,
        limit: int = 20,
    ) -> list[SoloditFinding]:
        """Search findings by protocol category.

        Args:
            category: Protocol category (DeFi, NFT, Lending, DEX, etc.)
            limit: Maximum findings to return

        Returns:
            List of findings
        """
        findings, _ = await self.search_findings(
            protocol_category=[category],
            impact=["HIGH", "MEDIUM"],
            page_size=min(limit, 100),
        )
        return findings[:limit]

    async def search_by_tag(
        self,
        tag: str,
        impact: list[ImpactLevel] | None = None,
        limit: int = 20,
    ) -> list[SoloditFinding]:
        """Search findings by vulnerability tag.

        Args:
            tag: Vulnerability tag (Reentrancy, Oracle, Access Control, etc.)
            impact: Filter by impact levels
            limit: Maximum findings to return

        Returns:
            List of findings
        """
        findings, _ = await self.search_findings(
            tags=[tag],
            impact=impact or ["HIGH", "MEDIUM"],
            page_size=min(limit, 100),
        )
        return findings[:limit]

    async def search_similar_vulnerabilities(
        self,
        vulnerability_type: str,
        impact: list[ImpactLevel] | None = None,
        limit: int = 10,
    ) -> list[SoloditFinding]:
        """Search for vulnerabilities similar to a detected issue.

        Args:
            vulnerability_type: Type of vulnerability (maps to tags/keywords)
            impact: Filter by impact levels
            limit: Maximum findings to return

        Returns:
            List of similar findings
        """
        # Map common vulnerability types to Solodit tags
        tag_mapping = {
            "reentrancy": "Reentrancy",
            "access-control": "Access Control",
            "oracle": "Oracle",
            "flash-loan": "Flash Loan",
            "integer-overflow": "Integer Overflow/Underflow",
            "front-running": "Front-running",
            "dos": "DOS",
            "price-manipulation": "Price Manipulation",
            "logic": "Logic Error",
        }

        # Try tag search first
        tag = tag_mapping.get(vulnerability_type.lower())
        if tag:
            return await self.search_by_tag(tag, impact, limit)

        # Fall back to keyword search
        findings, _ = await self.search_findings(
            keywords=vulnerability_type,
            impact=impact or ["HIGH", "MEDIUM"],
            page_size=min(limit, 100),
        )
        return findings[:limit]

    def get_rate_limit_remaining(self) -> int:
        """Get remaining API requests in current window."""
        return self._rate_limiter.remaining()


# Synchronous wrapper for non-async contexts
class SoloditClientSync:
    """Synchronous wrapper for SoloditClient."""

    def __init__(self, api_key: str | None = None, timeout: int = 30):
        self._async_client = SoloditClient(api_key=api_key, timeout=timeout)

    def _run(self, coro):
        """Run async coroutine synchronously."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(coro)

    def search_findings(
        self,
        keywords: str | None = None,
        impact: list[ImpactLevel] | None = None,
        tags: list[str] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[SoloditFinding], dict]:
        """Search for vulnerability findings (sync)."""
        return self._run(
            self._async_client.search_findings(
                keywords=keywords,
                impact=impact,
                tags=tags,
                page=page,
                page_size=page_size,
            )
        )

    def get_finding_by_slug(self, slug: str) -> SoloditFinding | None:
        """Get finding by slug (sync)."""
        return self._run(self._async_client.get_finding_by_slug(slug))

    def search_similar_vulnerabilities(
        self,
        vulnerability_type: str,
        impact: list[ImpactLevel] | None = None,
        limit: int = 10,
    ) -> list[SoloditFinding]:
        """Search similar vulnerabilities (sync)."""
        return self._run(
            self._async_client.search_similar_vulnerabilities(
                vulnerability_type, impact, limit
            )
        )

    def get_rate_limit_remaining(self) -> int:
        """Get remaining API requests in current window."""
        return self._async_client.get_rate_limit_remaining()
