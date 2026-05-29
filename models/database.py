"""
PostgreSQL Database Models — replaces hunt_history.json with proper case management.

Features:
- Full hunt session persistence with timeline indexing
- Full-text search over findings
- Campaign linking (multiple hunts → one campaign)
- Evidence chain storage
- Audit logging
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, JSON,
    ForeignKey, Index, Enum as SQLEnum, func
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR, UUID, ARRAY
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class Hunt(Base):
    """A single threat hunt session."""
    __tablename__ = "hunts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hypothesis = Column(Text, nullable=False)
    status = Column(String(20), default="running")  # running, completed, paused, failed
    initiated_by = Column(String(100), nullable=False)
    team_namespace = Column(String(100), default="default")
    campaign_id = Column(UUID(as_uuid=True), ForeignKey("campaigns.id"), nullable=True)

    # Results
    conclusion = Column(Text)
    confidence_score = Column(Float)
    max_severity = Column(String(20))

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime)

    # Fleet targeting
    target_nodes = Column(ARRAY(String))

    # Full-text search vector (auto-generated from hypothesis + conclusion)
    search_vector = Column(TSVECTOR)

    # Relationships
    findings = relationship("Finding", back_populates="hunt", cascade="all, delete-orphan")
    evidence_entries = relationship("EvidenceEntry", back_populates="hunt")
    actions = relationship("HuntAction", back_populates="hunt")

    __table_args__ = (
        Index("ix_hunts_search", "search_vector", postgresql_using="gin"),
        Index("ix_hunts_team_created", "team_namespace", "created_at"),
    )


class Finding(Base):
    """A single finding within a hunt."""
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hunt_id = Column(UUID(as_uuid=True), ForeignKey("hunts.id"), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), index=True)  # critical, high, medium, low, info
    category = Column(String(50))
    query_used = Column(Text)
    raw_data = Column(JSONB)
    indicators = Column(ARRAY(String))
    mitre_technique = Column(String(20))
    node_key = Column(String(100))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    # Full-text search
    search_vector = Column(TSVECTOR)

    hunt = relationship("Hunt", back_populates="findings")

    __table_args__ = (
        Index("ix_findings_search", "search_vector", postgresql_using="gin"),
        Index("ix_findings_severity_time", "severity", "timestamp"),
        Index("ix_findings_mitre", "mitre_technique"),
    )


class EvidenceEntry(Base):
    """Cryptographically signed evidence chain entry."""
    __tablename__ = "evidence_chain"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hunt_id = Column(UUID(as_uuid=True), ForeignKey("hunts.id"), nullable=False)
    evidence_id = Column(String(50), unique=True, nullable=False)
    sequence_number = Column(Integer, nullable=False)
    node_key = Column(String(100))
    query_sql = Column(Text)
    query_purpose = Column(Text)
    result_hash = Column(String(64))
    previous_hash = Column(String(64))
    signature = Column(Text)
    public_key = Column(String(128))
    timestamp = Column(DateTime, default=datetime.utcnow)

    hunt = relationship("Hunt", back_populates="evidence_entries")

    __table_args__ = (
        Index("ix_evidence_hunt_seq", "hunt_id", "sequence_number"),
    )


class Campaign(Base):
    """Links multiple hunts into a campaign/investigation."""
    __tablename__ = "campaigns"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    status = Column(String(20), default="active")
    created_by = Column(String(100))
    team_namespace = Column(String(100), default="default")
    created_at = Column(DateTime, default=datetime.utcnow)
    closed_at = Column(DateTime)
    tags = Column(ARRAY(String))

    hunts = relationship("Hunt", backref="campaign")


class HuntAction(Base):
    """Audit log of every agent action during a hunt."""
    __tablename__ = "hunt_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hunt_id = Column(UUID(as_uuid=True), ForeignKey("hunts.id"), nullable=False)
    agent_role = Column(String(20))
    action_type = Column(String(50))
    description = Column(Text)
    input_data = Column(JSONB)
    output_data = Column(JSONB)
    requires_approval = Column(Boolean, default=False)
    approved = Column(Boolean)
    approved_by = Column(String(100))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    hunt = relationship("Hunt", back_populates="actions")


class AuditLog(Base):
    """System-wide audit log for all user/agent actions."""
    __tablename__ = "audit_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String(100), nullable=False, index=True)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50))  # hunt, campaign, node, user
    resource_id = Column(String(100))
    details = Column(JSONB)
    ip_address = Column(String(45))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    team_namespace = Column(String(100), index=True)


class FleetNodeRecord(Base):
    """Persistent record of fleet nodes."""
    __tablename__ = "fleet_nodes"

    node_key = Column(String(100), primary_key=True)
    hostname = Column(String(255), nullable=False)
    platform = Column(String(50))
    os_version = Column(String(100))
    osquery_version = Column(String(50))
    status = Column(String(20), default="active")
    config_group = Column(String(100), default="default")
    tags = Column(ARRAY(String))
    metadata = Column(JSONB)
    enrolled_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index("ix_nodes_status_seen", "status", "last_seen"),
    )
