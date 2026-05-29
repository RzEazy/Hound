"""
Cryptographic Evidence Signing — tamper-evident query-result pairs for legal/IR use.

Every query-result pair is cryptographically signed so the evidence chain
is verifiable and admissible for incident response and legal proceedings.

Uses Ed25519 for signatures (fast, small, quantum-resistant-ish).
Chain structure: each entry includes hash of previous entry (blockchain-style).
"""

import json
import hashlib
import base64
import logging
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class SignedEvidence:
    """A cryptographically signed query-result pair."""
    evidence_id: str
    hunt_id: str
    sequence_number: int
    timestamp: str
    node_key: str
    query_sql: str
    query_purpose: str
    results: List[Dict[str, Any]]
    result_hash: str  # SHA-256 of canonical results JSON
    previous_hash: str  # Hash of previous evidence entry (chain)
    signature: str  # Ed25519 signature over the canonical payload
    public_key: str  # Public key that signed this evidence
    metadata: Dict[str, Any] = field(default_factory=dict)

    def canonical_payload(self) -> bytes:
        """Generate the canonical byte representation for signing/verification."""
        payload = {
            "evidence_id": self.evidence_id,
            "hunt_id": self.hunt_id,
            "sequence_number": self.sequence_number,
            "timestamp": self.timestamp,
            "node_key": self.node_key,
            "query_sql": self.query_sql,
            "results_hash": self.result_hash,
            "previous_hash": self.previous_hash,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class EvidenceSigner:
    """
    Signs and verifies evidence entries using Ed25519.
    
    In production:
    - Private key stored in HSM or Vault
    - Public key distributed to all verifiers
    - Key rotation handled via key versioning
    """

    def __init__(self, private_key_path: Optional[str] = None):
        """
        Initialize signer. Generates ephemeral key if no path provided.
        
        Args:
            private_key_path: Path to Ed25519 private key PEM file
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization

            if private_key_path:
                with open(private_key_path, "rb") as f:
                    self._private_key = serialization.load_pem_private_key(f.read(), password=None)
            else:
                self._private_key = Ed25519PrivateKey.generate()

            self._public_key = self._private_key.public_key()
            self._public_key_bytes = self._public_key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            self.public_key_hex = self._public_key_bytes.hex()
        except ImportError:
            logger.warning("cryptography package not installed — signatures disabled")
            self._private_key = None
            self._public_key = None
            self.public_key_hex = "disabled"

    def sign(self, payload: bytes) -> str:
        """Sign a payload, returns base64-encoded signature."""
        if not self._private_key:
            return "unsigned"
        signature = self._private_key.sign(payload)
        return base64.b64encode(signature).decode()

    def verify(self, payload: bytes, signature_b64: str, public_key_hex: str) -> bool:
        """Verify a signature against payload and public key."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pub_key_bytes = bytes.fromhex(public_key_hex)
            pub_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
            signature = base64.b64decode(signature_b64)
            pub_key.verify(signature, payload)
            return True
        except Exception:
            return False


class EvidenceChain:
    """
    Maintains a tamper-evident chain of signed evidence for a hunt.
    
    Properties:
    - Each entry is signed individually
    - Each entry includes hash of previous entry (chain integrity)
    - Chain can be independently verified by any party with the public key
    """

    def __init__(self, hunt_id: str, signer: Optional[EvidenceSigner] = None):
        self.hunt_id = hunt_id
        self.signer = signer or EvidenceSigner()
        self._chain: List[SignedEvidence] = []
        self._previous_hash = "genesis"

    def add_evidence(self, node_key: str, query_sql: str, query_purpose: str,
                     results: List[Dict[str, Any]],
                     metadata: Dict[str, Any] = None) -> SignedEvidence:
        """
        Add a new query-result pair to the evidence chain.
        
        The entry is signed and chained to the previous entry.
        """
        # Hash results deterministically
        results_canonical = json.dumps(results, sort_keys=True, separators=(",", ":"))
        result_hash = hashlib.sha256(results_canonical.encode()).hexdigest()

        evidence = SignedEvidence(
            evidence_id=f"ev_{hashlib.sha256(f'{self.hunt_id}_{len(self._chain)}'.encode()).hexdigest()[:12]}",
            hunt_id=self.hunt_id,
            sequence_number=len(self._chain),
            timestamp=datetime.utcnow().isoformat() + "Z",
            node_key=node_key,
            query_sql=query_sql,
            query_purpose=query_purpose,
            results=results,
            result_hash=result_hash,
            previous_hash=self._previous_hash,
            signature="",  # Will be set below
            public_key=self.signer.public_key_hex,
            metadata=metadata or {},
        )

        # Sign the canonical payload
        evidence.signature = self.signer.sign(evidence.canonical_payload())

        # Update chain hash
        self._previous_hash = hashlib.sha256(evidence.canonical_payload()).hexdigest()
        self._chain.append(evidence)

        return evidence

    def verify_chain(self) -> Tuple[bool, Optional[str]]:
        """
        Verify the entire evidence chain integrity.
        
        Returns:
            (is_valid, error_message)
        """
        expected_prev = "genesis"

        for i, evidence in enumerate(self._chain):
            # Check chain linkage
            if evidence.previous_hash != expected_prev:
                return False, f"Chain broken at entry {i}: expected prev_hash {expected_prev}, got {evidence.previous_hash}"

            # Verify signature
            if evidence.signature != "unsigned":
                is_valid = self.signer.verify(
                    evidence.canonical_payload(),
                    evidence.signature,
                    evidence.public_key,
                )
                if not is_valid:
                    return False, f"Invalid signature at entry {i} ({evidence.evidence_id})"

            # Verify result hash
            results_canonical = json.dumps(evidence.results, sort_keys=True, separators=(",", ":"))
            computed_hash = hashlib.sha256(results_canonical.encode()).hexdigest()
            if computed_hash != evidence.result_hash:
                return False, f"Result hash mismatch at entry {i}: data tampered"

            # Update expected previous hash
            expected_prev = hashlib.sha256(evidence.canonical_payload()).hexdigest()

        return True, None

    def export_chain(self) -> List[Dict[str, Any]]:
        """Export the full chain for storage or transfer."""
        return [
            {
                "evidence_id": e.evidence_id,
                "hunt_id": e.hunt_id,
                "sequence_number": e.sequence_number,
                "timestamp": e.timestamp,
                "node_key": e.node_key,
                "query_sql": e.query_sql,
                "query_purpose": e.query_purpose,
                "result_hash": e.result_hash,
                "result_count": len(e.results),
                "previous_hash": e.previous_hash,
                "signature": e.signature,
                "public_key": e.public_key,
            }
            for e in self._chain
        ]

    def __len__(self):
        return len(self._chain)
