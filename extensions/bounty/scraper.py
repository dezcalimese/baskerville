"""
Multi-platform contest scraper.

Discovers active audit contests from:
- Code4rena
- Sherlock
- CodeHawks
- Immunefi (bug bounties)

Note: These scrapers use public APIs/pages and respect rate limits.
Always verify contest details manually before participating.
"""

import asyncio
import aiohttp
import re
from abc import ABC, abstractmethod
from datetime import datetime
from dataclasses import dataclass
from typing import Any
from bs4 import BeautifulSoup

from .contest import Contest, ContestState


@dataclass
class ScrapedContest:
    """Raw contest data from scraping."""
    platform: str
    name: str
    url: str
    start_date: datetime | None = None
    end_date: datetime | None = None
    prize_pool: str = ""
    repo_url: str = ""
    docs_url: str = ""
    metadata: dict[str, Any] | None = None

    def to_contest(self) -> Contest:
        """Convert to Contest model."""
        # Generate ID from platform and name
        slug = re.sub(r'[^a-z0-9]+', '-', self.name.lower()).strip('-')
        contest_id = f"{self.platform}-{slug}"

        return Contest(
            id=contest_id,
            platform=self.platform,
            name=self.name,
            url=self.url,
            state=ContestState.DISCOVERED,
            start_date=self.start_date,
            end_date=self.end_date,
            prize_pool=self.prize_pool,
            repo_url=self.repo_url,
            docs_url=self.docs_url,
            metadata=self.metadata or {},
        )


class BaseScraper(ABC):
    """Base class for platform scrapers."""

    platform: str = "unknown"

    def __init__(self, session: aiohttp.ClientSession | None = None):
        self._session = session
        self._owns_session = False

    async def __aenter__(self):
        if self._session is None:
            self._session = aiohttp.ClientSession()
            self._owns_session = True
        return self

    async def __aexit__(self, *args):
        if self._owns_session and self._session:
            await self._session.close()

    @property
    def session(self) -> aiohttp.ClientSession:
        if self._session is None:
            raise RuntimeError("Scraper not initialized. Use async with or call __aenter__")
        return self._session

    @abstractmethod
    async def scrape_active(self) -> list[ScrapedContest]:
        """Scrape currently active contests."""
        pass

    async def scrape_upcoming(self) -> list[ScrapedContest]:
        """Scrape upcoming contests. Override if platform supports it."""
        return []


class Code4renaScraper(BaseScraper):
    """Scraper for Code4rena contests."""

    platform = "code4rena"
    BASE_URL = "https://code4rena.com"
    API_URL = "https://code4rena.com/api/contests"

    async def scrape_active(self) -> list[ScrapedContest]:
        """Scrape active Code4rena contests."""
        contests = []

        try:
            async with self.session.get(self.API_URL, timeout=30) as resp:
                if resp.status != 200:
                    return contests

                data = await resp.json()

                for contest in data:
                    # Filter for active contests
                    status = contest.get("status", "").lower()
                    if status not in ["active", "upcoming"]:
                        continue

                    start_time = contest.get("start_time")
                    end_time = contest.get("end_time")

                    contests.append(ScrapedContest(
                        platform=self.platform,
                        name=contest.get("title", "Unknown"),
                        url=f"{self.BASE_URL}/audits/{contest.get('slug', '')}",
                        start_date=datetime.fromisoformat(start_time.replace('Z', '+00:00')) if start_time else None,
                        end_date=datetime.fromisoformat(end_time.replace('Z', '+00:00')) if end_time else None,
                        prize_pool=contest.get("total_award_pool", ""),
                        repo_url=contest.get("repo", ""),
                        docs_url=contest.get("docs_url", ""),
                        metadata={
                            "contest_id": contest.get("id"),
                            "status": status,
                            "type": contest.get("type"),
                        },
                    ))

        except Exception as e:
            print(f"[!] Code4rena scrape failed: {e}")

        return contests


class SherlockScraper(BaseScraper):
    """Scraper for Sherlock contests."""

    platform = "sherlock"
    BASE_URL = "https://audits.sherlock.xyz"
    API_URL = "https://mainnet-contest.sherlock.xyz/contests"

    async def scrape_active(self) -> list[ScrapedContest]:
        """Scrape active Sherlock contests."""
        contests = []

        try:
            async with self.session.get(self.API_URL, timeout=30) as resp:
                if resp.status != 200:
                    return contests

                data = await resp.json()

                for contest in data:
                    status = contest.get("status", "").lower()
                    if status not in ["active", "upcoming", "created"]:
                        continue

                    start_date = contest.get("starts_at") or contest.get("start_date")
                    end_date = contest.get("ends_at") or contest.get("end_date")

                    # Parse timestamps
                    start_dt = None
                    end_dt = None
                    if start_date:
                        try:
                            start_dt = datetime.fromtimestamp(int(start_date) / 1000)
                        except (ValueError, TypeError):
                            try:
                                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                            except (ValueError, AttributeError):
                                pass
                    if end_date:
                        try:
                            end_dt = datetime.fromtimestamp(int(end_date) / 1000)
                        except (ValueError, TypeError):
                            try:
                                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                            except (ValueError, AttributeError):
                                pass

                    contest_id = contest.get("id", "")
                    contests.append(ScrapedContest(
                        platform=self.platform,
                        name=contest.get("title", contest.get("name", "Unknown")),
                        url=f"{self.BASE_URL}/contests/{contest_id}",
                        start_date=start_dt,
                        end_date=end_dt,
                        prize_pool=str(contest.get("prize_pool", contest.get("total_prize_pool", ""))),
                        repo_url=contest.get("repo", contest.get("repo_url", "")),
                        docs_url=contest.get("docs_url", ""),
                        metadata={
                            "contest_id": contest_id,
                            "status": status,
                            "lead_watson": contest.get("lead_senior_watson"),
                        },
                    ))

        except Exception as e:
            print(f"[!] Sherlock scrape failed: {e}")

        return contests


class CodeHawksScraper(BaseScraper):
    """Scraper for CodeHawks contests."""

    platform = "codehawks"
    BASE_URL = "https://codehawks.com"
    # Note: CodeHawks doesn't have a public API, so we scrape the page

    async def scrape_active(self) -> list[ScrapedContest]:
        """Scrape active CodeHawks contests."""
        contests = []

        try:
            # Try to get contests from the main page
            async with self.session.get(f"{self.BASE_URL}/contests", timeout=30) as resp:
                if resp.status != 200:
                    return contests

                html = await resp.text()
                soup = BeautifulSoup(html, 'html.parser')

                # Look for contest cards (structure may change)
                contest_cards = soup.find_all('div', class_=re.compile(r'contest|audit', re.I))

                for card in contest_cards:
                    # Extract contest info from card
                    title_elem = card.find(['h2', 'h3', 'a'], class_=re.compile(r'title|name', re.I))
                    if not title_elem:
                        continue

                    title = title_elem.get_text(strip=True)
                    link = card.find('a', href=True)
                    url = link['href'] if link else ""
                    if url and not url.startswith('http'):
                        url = f"{self.BASE_URL}{url}"

                    # Try to find prize pool
                    prize_elem = card.find(string=re.compile(r'\$[\d,]+', re.I))
                    prize_pool = prize_elem.strip() if prize_elem else ""

                    contests.append(ScrapedContest(
                        platform=self.platform,
                        name=title,
                        url=url,
                        prize_pool=prize_pool,
                        metadata={"source": "page_scrape"},
                    ))

        except Exception as e:
            print(f"[!] CodeHawks scrape failed: {e}")

        return contests


class ImmunefiScraper(BaseScraper):
    """Scraper for Immunefi bug bounties."""

    platform = "immunefi"
    BASE_URL = "https://immunefi.com"
    API_URL = "https://immunefi.com/explore/"

    async def scrape_active(self) -> list[ScrapedContest]:
        """Scrape active Immunefi bounties."""
        contests = []

        try:
            # Immunefi uses a React app, try to get data from page
            headers = {
                "User-Agent": "Mozilla/5.0 (compatible; Hound/1.0; +https://github.com/scabench-org/baskerville)"
            }
            async with self.session.get(self.API_URL, headers=headers, timeout=30) as resp:
                if resp.status != 200:
                    return contests

                html = await resp.text()

                # Try to find Next.js data script
                soup = BeautifulSoup(html, 'html.parser')
                script_tag = soup.find('script', id='__NEXT_DATA__')

                if script_tag:
                    import json
                    try:
                        data = json.loads(script_tag.string)
                        bounties = data.get('props', {}).get('pageProps', {}).get('bounties', [])

                        for bounty in bounties[:50]:  # Limit to first 50
                            max_reward = bounty.get('maxBounty', 0)
                            if isinstance(max_reward, (int, float)):
                                prize_pool = f"${max_reward:,.0f}"
                            else:
                                prize_pool = str(max_reward)

                            contests.append(ScrapedContest(
                                platform=self.platform,
                                name=bounty.get('project', 'Unknown'),
                                url=f"{self.BASE_URL}/bounty/{bounty.get('id', '')}",
                                prize_pool=prize_pool,
                                metadata={
                                    "bounty_id": bounty.get('id'),
                                    "ecosystem": bounty.get('ecosystem'),
                                    "kyc_required": bounty.get('kycRequired'),
                                    "assets_in_scope": bounty.get('assetsInScope', []),
                                },
                            ))
                    except json.JSONDecodeError:
                        pass

        except Exception as e:
            print(f"[!] Immunefi scrape failed: {e}")

        return contests


class ContestScraper:
    """Unified contest scraper for all platforms."""

    SCRAPERS = {
        "code4rena": Code4renaScraper,
        "sherlock": SherlockScraper,
        "codehawks": CodeHawksScraper,
        "immunefi": ImmunefiScraper,
    }

    def __init__(self):
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    async def scrape_platform(self, platform: str) -> list[ScrapedContest]:
        """Scrape a specific platform."""
        if platform not in self.SCRAPERS:
            raise ValueError(f"Unknown platform: {platform}. Available: {list(self.SCRAPERS.keys())}")

        scraper_class = self.SCRAPERS[platform]
        async with scraper_class(self._session) as scraper:
            return await scraper.scrape_active()

    async def scrape_all(self) -> dict[str, list[ScrapedContest]]:
        """Scrape all platforms concurrently."""
        results = {}

        async def scrape_one(platform: str):
            try:
                contests = await self.scrape_platform(platform)
                results[platform] = contests
            except Exception as e:
                print(f"[!] Failed to scrape {platform}: {e}")
                results[platform] = []

        await asyncio.gather(*[
            scrape_one(platform) for platform in self.SCRAPERS
        ])

        return results

    async def discover_contests(self, platforms: list[str] | None = None) -> list[Contest]:
        """Discover contests and return as Contest objects."""
        if platforms is None:
            platforms = list(self.SCRAPERS.keys())

        all_contests = []

        for platform in platforms:
            try:
                scraped = await self.scrape_platform(platform)
                for sc in scraped:
                    all_contests.append(sc.to_contest())
            except Exception as e:
                print(f"[!] Failed to discover from {platform}: {e}")

        return all_contests

    @classmethod
    def available_platforms(cls) -> list[str]:
        """Get list of available platforms."""
        return list(cls.SCRAPERS.keys())
