"""
Live Threat Intelligence Enrichment — auto-enrich IOCs against external feeds.

Supported feeds:
- VirusTotal (file hashes, IPs, domains)
- AbuseIPDB (IP reputation)
- MISP (indicators sharing)
- STIX/TAXII (structured threat intel streams)
"""

import asyncio
import hashlib
import logging
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class IOCType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    URL = "url"
    EMAIL = "email"
    FILE_PATH = "file_path"


@dataclass
class IOC:
    """An Indicator of Compromise."""
    value: str
    ioc_type: IOCType
    first_seen: datetime = field(default_factory=datetime.utcnow)
    source_hunt_id: Optional[str] = None
    source_node: Optional[str] = None


@dataclass
class EnrichmentResult:
    """Result of enriching an IOC against threat intel feeds."""
    ioc: IOC
    feed_name: str
    is_malicious: bool
    confidence: float  # 0.0 - 1.0
    details: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    first_seen_in_feed: Optional[datetime] = None
    last_seen_in_feed: Optional[datetime] = None
    enriched_at: datetime = field(default_factory=datetime.utcnow)


class ThreatFeed(ABC):
    """Base class for threat intelligence feed integrations."""

    @abstractmethod
    async def enrich(self, ioc: IOC) -> Optional[EnrichmentResult]:
        pass

    @abstractmethod
    def supports_type(self, ioc_type: IOCType) -> bool:
        pass


class VirusTotalFeed(ThreatFeed):
    """VirusTotal API v3 integration."""

    def __init__(self, api_key: str, rate_limit: int = 4):
        self.api_key = api_key
        self.rate_limit = rate_limit  # requests per minute
        self._last_request = 0.0

    def supports_type(self, ioc_type: IOCType) -> bool:
        return ioc_type in (IOCType.IP, IOCType.DOMAIN, IOCType.HASH_MD5,
                           IOCType.HASH_SHA1, IOCType.HASH_SHA256, IOCType.URL)

    async def enrich(self, ioc: IOC) -> Optional[EnrichmentResult]:
        """Query VirusTotal for IOC reputation."""
        await self._rate_limit_wait()

        try:
            import aiohttp
            endpoint = self._get_endpoint(ioc)
            if not endpoint:
                return None

            headers = {"x-apikey": self.api_key}
            async with aiohttp.ClientSession() as session:
                async with session.get(endpoint, headers=headers) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()

            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 1

            return EnrichmentResult(
                ioc=ioc,
                feed_name="virustotal",
                is_malicious=malicious > 3,
                confidence=min(malicious / max(total, 1), 1.0),
                details={
                    "malicious_detections": malicious,
                    "total_engines": total,
                    "tags": attrs.get("tags", []),
                    "reputation": attrs.get("reputation", 0),
                },
                tags=attrs.get("tags", []),
            )
        except Exception as e:
            logger.error(f"VirusTotal enrichment failed for {ioc.value}: {e}")
            return None

    def _get_endpoint(self, ioc: IOC) -> Optional[str]:
        base = "https://www.virustotal.com/api/v3"
        if ioc.ioc_type == IOCType.IP:
            return f"{base}/ip_addresses/{ioc.value}"
        elif ioc.ioc_type == IOCType.DOMAIN:
            return f"{base}/domains/{ioc.value}"
        elif ioc.ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
            return f"{base}/files/{ioc.value}"
        return None

    async def _rate_limit_wait(self):
        elapsed = time.time() - self._last_request
        min_interval = 60.0 / self.rate_limit
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request = time.time()


class AbuseIPDBFeed(ThreatFeed):
    """AbuseIPDB integration for IP reputation."""

    def __init__(self, api_key: str):
        self.api_key = api_key

    def supports_type(self, ioc_type: IOCType) -> bool:
        return ioc_type == IOCType.IP

    async def enrich(self, ioc: IOC) -> Optional[EnrichmentResult]:
        try:
            import aiohttp
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self.api_key, "Accept": "application/json"}
            params = {"ipAddress": ioc.value, "maxAgeInDays": 90}

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()

            report = data.get("data", {})
            abuse_score = report.get("abuseConfidenceScore", 0)

            return EnrichmentResult(
                ioc=ioc,
                feed_name="abuseipdb",
                is_malicious=abuse_score > 50,
                confidence=abuse_score / 100.0,
                details={
                    "abuse_score": abuse_score,
                    "total_reports": report.get("totalReports", 0),
                    "country": report.get("countryCode", ""),
                    "isp": report.get("isp", ""),
                    "usage_type": report.get("usageType", ""),
                },
                tags=report.get("categories", []),
            )
        except Exception as e:
            logger.error(f"AbuseIPDB enrichment failed: {e}")
            return None


class MISPFeed(ThreatFeed):
    """MISP (Malware Information Sharing Platform) integration."""

    def __init__(self, url: str, api_key: str, verify_ssl: bool = True):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl

    def supports_type(self, ioc_type: IOCType) -> bool:
        return True  # MISP supports all IOC types

    async def enrich(self, ioc: IOC) -> Optional[EnrichmentResult]:
        try:
            import aiohttp
            search_url = f"{self.url}/attributes/restSearch"
            headers = {
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            payload = {"value": ioc.value, "limit": 5}

            async with aiohttp.ClientSession() as session:
                async with session.post(search_url, headers=headers,
                                        json=payload, ssl=self.verify_ssl) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()

            attributes = data.get("response", {}).get("Attribute", [])
            if not attributes:
                return EnrichmentResult(
                    ioc=ioc, feed_name="misp",
                    is_malicious=False, confidence=0.0,
                )

            # Found in MISP — likely malicious
            tags = []
            for attr in attributes:
                tags.extend([t.get("name", "") for t in attr.get("Tag", [])])

            return EnrichmentResult(
                ioc=ioc,
                feed_name="misp",
                is_malicious=True,
                confidence=0.8,
                details={
                    "event_count": len(attributes),
                    "categories": list(set(a.get("category", "") for a in attributes)),
                },
                tags=list(set(tags)),
            )
        except Exception as e:
            logger.error(f"MISP enrichment failed: {e}")
            return None


class STIXTAXIIFeed(ThreatFeed):
    """STIX/TAXII 2.1 feed consumer."""

    def __init__(self, discovery_url: str, api_root: str,
                 collection_id: str, username: str = "", password: str = ""):
        self.discovery_url = discovery_url
        self.api_root = api_root
        self.collection_id = collection_id
        self.username = username
        self.password = password
        self._indicator_cache: Dict[str, Dict] = {}

    def supports_type(self, ioc_type: IOCType) -> bool:
        return True

    async def enrich(self, ioc: IOC) -> Optional[EnrichmentResult]:
        """Check if IOC exists in TAXII collection."""
        # Search local cache first
        if ioc.value in self._indicator_cache:
            indicator = self._indicator_cache[ioc.value]
            return EnrichmentResult(
                ioc=ioc,
                feed_name="stix_taxii",
                is_malicious=True,
                confidence=0.85,
                details=indicator,
                tags=indicator.get("labels", []),
            )
        return None

    async def poll_collection(self):
        """Poll TAXII collection for new indicators."""
        try:
            import aiohttp
            url = f"{self.api_root}/collections/{self.collection_id}/objects/"
            auth = aiohttp.BasicAuth(self.username, self.password) if self.username else None
            headers = {"Accept": "application/taxii+json;version=2.1"}

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, auth=auth) as resp:
                    if resp.status != 200:
                        return
                    data = await resp.json()

            for obj in data.get("objects", []):
                if obj.get("type") == "indicator":
                    pattern = obj.get("pattern", "")
                    # Extract IOC value from STIX pattern
                    value = self._extract_value_from_pattern(pattern)
                    if value:
                        self._indicator_cache[value] = obj

        except Exception as e:
            logger.error(f"TAXII poll failed: {e}")

    def _extract_value_from_pattern(self, pattern: str) -> Optional[str]:
        """Extract IOC value from STIX 2.1 pattern."""
        import re
        # Match patterns like [ipv4-addr:value = '1.2.3.4']
        match = re.search(r"'([^']+)'", pattern)
        return match.group(1) if match else None


class ThreatIntelEnricher:
    """
    Orchestrates IOC enrichment across multiple threat intel feeds.
    
    Features:
    - Parallel enrichment across feeds
    - Result caching with TTL
    - Consensus scoring (multiple feeds agreeing = higher confidence)
    """

    def __init__(self, feeds: Optional[List[ThreatFeed]] = None,
                 cache_ttl_hours: int = 24):
        self.feeds = feeds or []
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self._cache: Dict[str, List[EnrichmentResult]] = {}
        self._cache_timestamps: Dict[str, datetime] = {}

    def add_feed(self, feed: ThreatFeed):
        self.feeds.append(feed)

    async def enrich(self, ioc: IOC) -> List[EnrichmentResult]:
        """
        Enrich an IOC against all applicable feeds.
        Returns list of results from each feed.
        """
        # Check cache
        cache_key = f"{ioc.ioc_type.value}:{ioc.value}"
        if cache_key in self._cache:
            cache_time = self._cache_timestamps.get(cache_key, datetime.min)
            if datetime.utcnow() - cache_time < self.cache_ttl:
                return self._cache[cache_key]

        # Query applicable feeds in parallel
        applicable = [f for f in self.feeds if f.supports_type(ioc.ioc_type)]
        tasks = [f.enrich(ioc) for f in applicable]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        results = [r for r in raw_results if isinstance(r, EnrichmentResult)]

        # Cache results
        self._cache[cache_key] = results
        self._cache_timestamps[cache_key] = datetime.utcnow()

        return results

    async def enrich_batch(self, iocs: List[IOC]) -> Dict[str, List[EnrichmentResult]]:
        """Enrich multiple IOCs, returns mapping of IOC value -> results."""
        tasks = {ioc.value: self.enrich(ioc) for ioc in iocs}
        results = {}
        for value, task in tasks.items():
            results[value] = await task
        return results

    def consensus_score(self, results: List[EnrichmentResult]) -> float:
        """
        Calculate consensus maliciousness score across feeds.
        Multiple feeds agreeing increases confidence.
        """
        if not results:
            return 0.0

        malicious_count = sum(1 for r in results if r.is_malicious)
        avg_confidence = sum(r.confidence for r in results) / len(results)

        # Consensus bonus: if >50% of feeds agree it's malicious
        consensus_ratio = malicious_count / len(results)
        return min(avg_confidence * (1 + consensus_ratio * 0.5), 1.0)
