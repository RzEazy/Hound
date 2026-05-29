"""
HoundAI Production Configuration
"""

import os
from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class DatabaseConfig:
    url: str = os.getenv("HOUNDAI_DB_URL", "postgresql+asyncpg://houndai:houndai@localhost:5432/houndai")
    pool_size: int = 20
    max_overflow: int = 10


@dataclass
class NATSConfig:
    servers: List[str] = field(default_factory=lambda: [os.getenv("NATS_URL", "nats://localhost:4222")])
    credentials_path: Optional[str] = None


@dataclass 
class FleetConfig:
    enroll_secret: str = os.getenv("HOUNDAI_ENROLL_SECRET", "change-me")
    node_stale_minutes: int = 5
    distributed_query_ttl: int = 300


@dataclass
class ThreatIntelConfig:
    virustotal_api_key: str = os.getenv("VT_API_KEY", "")
    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    misp_url: str = os.getenv("MISP_URL", "")
    misp_api_key: str = os.getenv("MISP_API_KEY", "")
    enrichment_cache_hours: int = 24


@dataclass
class AuthConfig:
    jwt_secret: str = os.getenv("HOUNDAI_JWT_SECRET", "change-me-in-production")
    token_expiry_hours: int = 8
    oidc_issuer: str = os.getenv("OIDC_ISSUER", "")
    oidc_client_id: str = os.getenv("OIDC_CLIENT_ID", "")
    oidc_client_secret: str = os.getenv("OIDC_CLIENT_SECRET", "")


@dataclass
class EvidenceConfig:
    signing_key_path: Optional[str] = os.getenv("EVIDENCE_KEY_PATH", None)


@dataclass
class HoundAIConfig:
    """Master configuration for production HoundAI deployment."""
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    nats: NATSConfig = field(default_factory=NATSConfig)
    fleet: FleetConfig = field(default_factory=FleetConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    evidence: EvidenceConfig = field(default_factory=EvidenceConfig)
    
    # LLM
    cohere_api_key: str = os.getenv("COHERE_API_KEY", "")
    llm_model: str = "command-a-03-2025"
    
    # Paths
    playbooks_dir: str = "playbooks"
    chroma_db_path: str = "data/chroma_db"
