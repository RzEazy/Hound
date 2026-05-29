"""
Hybrid Search Engine — BM25 sparse + dense vector retrieval over enriched corpus.

Corpus includes:
- MITRE ATT&CK v15 techniques and sub-techniques
- Sigma rule library
- CVE/NVD database
- Threat intel reports
- osquery table documentation (existing)
"""

import math
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    """A single search result with combined score."""
    doc_id: str
    text: str
    metadata: Dict[str, Any]
    score: float
    bm25_score: float = 0.0
    vector_score: float = 0.0
    source: str = ""  # mitre, sigma, cve, osquery, threat_report


class BM25Index:
    """
    BM25 sparse retrieval index for keyword-heavy security content.
    
    BM25 excels at exact term matching which is critical for:
    - CVE IDs (CVE-2024-1234)
    - MITRE technique IDs (T1059.001)
    - Binary names, IP addresses, file paths
    - Sigma rule names and tags
    """

    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self._documents: Dict[str, Dict[str, Any]] = {}  # doc_id -> {text, metadata}
        self._inverted_index: Dict[str, Dict[str, int]] = defaultdict(dict)  # term -> {doc_id: tf}
        self._doc_lengths: Dict[str, int] = {}
        self._avg_dl: float = 0.0
        self._n_docs: int = 0

    def add_document(self, doc_id: str, text: str, metadata: Dict[str, Any] = None):
        """Index a document."""
        tokens = self._tokenize(text)
        self._documents[doc_id] = {"text": text, "metadata": metadata or {}}
        self._doc_lengths[doc_id] = len(tokens)

        for token in tokens:
            self._inverted_index[token][doc_id] = self._inverted_index[token].get(doc_id, 0) + 1

        self._n_docs = len(self._documents)
        self._avg_dl = sum(self._doc_lengths.values()) / max(self._n_docs, 1)

    def search(self, query: str, top_k: int = 10) -> List[Tuple[str, float]]:
        """Search index, returns list of (doc_id, score)."""
        tokens = self._tokenize(query)
        scores: Dict[str, float] = defaultdict(float)

        for token in tokens:
            if token not in self._inverted_index:
                continue
            postings = self._inverted_index[token]
            df = len(postings)
            idf = math.log((self._n_docs - df + 0.5) / (df + 0.5) + 1)

            for doc_id, tf in postings.items():
                dl = self._doc_lengths[doc_id]
                numerator = tf * (self.k1 + 1)
                denominator = tf + self.k1 * (1 - self.b + self.b * dl / self._avg_dl)
                scores[doc_id] += idf * (numerator / denominator)

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return ranked[:top_k]

    def _tokenize(self, text: str) -> List[str]:
        """Simple whitespace + punctuation tokenizer."""
        import re
        text = text.lower()
        tokens = re.findall(r'[a-z0-9_\-\.\/]+', text)
        return tokens


class HybridSearchEngine:
    """
    Combines BM25 sparse retrieval with dense vector search (ChromaDB).
    
    Uses Reciprocal Rank Fusion (RRF) to merge results from both retrievers.
    """

    def __init__(self, vector_db=None, bm25_index: Optional[BM25Index] = None,
                 rrf_k: int = 60, alpha: float = 0.5):
        """
        Args:
            vector_db: VectorDB instance for dense retrieval
            bm25_index: BM25Index for sparse retrieval
            rrf_k: RRF constant (higher = more uniform blending)
            alpha: Weight for vector score (1-alpha for BM25)
        """
        self.vector_db = vector_db
        self.bm25 = bm25_index or BM25Index()
        self.rrf_k = rrf_k
        self.alpha = alpha
        self._collections = {
            "mitre_attack": "MITRE ATT&CK techniques and sub-techniques",
            "sigma_rules": "Sigma detection rules",
            "cve_nvd": "CVE/NVD vulnerability database",
            "threat_reports": "Threat intelligence reports",
            "osquery_docs": "osquery table documentation",
        }

    def search(self, query: str, collections: Optional[List[str]] = None,
               top_k: int = 10) -> List[SearchResult]:
        """
        Hybrid search across specified collections.
        
        Args:
            query: Search query
            collections: Which collections to search (None = all)
            top_k: Number of results to return
        """
        target_collections = collections or list(self._collections.keys())

        # BM25 sparse retrieval
        bm25_results = self.bm25.search(query, top_k=top_k * 2)
        bm25_ranked = {doc_id: rank + 1 for rank, (doc_id, _) in enumerate(bm25_results)}
        bm25_scores = {doc_id: score for doc_id, score in bm25_results}

        # Dense vector retrieval
        vector_ranked: Dict[str, int] = {}
        vector_scores: Dict[str, float] = {}
        
        if self.vector_db:
            for collection in target_collections:
                try:
                    results = self.vector_db.search(collection, query, n_results=top_k)
                    if results and results.get("ids") and results["ids"][0]:
                        for i, doc_id in enumerate(results["ids"][0]):
                            vector_ranked[doc_id] = i + 1
                            distances = results.get("distances", [[]])[0]
                            vector_scores[doc_id] = 1.0 - (distances[i] if i < len(distances) else 0.5)
                except Exception:
                    continue

        # Reciprocal Rank Fusion
        all_doc_ids = set(bm25_ranked.keys()) | set(vector_ranked.keys())
        fused_scores: Dict[str, float] = {}

        for doc_id in all_doc_ids:
            bm25_rrf = 1.0 / (self.rrf_k + bm25_ranked.get(doc_id, 1000))
            vec_rrf = 1.0 / (self.rrf_k + vector_ranked.get(doc_id, 1000))
            fused_scores[doc_id] = (1 - self.alpha) * bm25_rrf + self.alpha * vec_rrf

        # Build results
        ranked_ids = sorted(fused_scores.keys(), key=lambda x: fused_scores[x], reverse=True)[:top_k]
        results = []

        for doc_id in ranked_ids:
            doc_data = self.bm25._documents.get(doc_id, {})
            results.append(SearchResult(
                doc_id=doc_id,
                text=doc_data.get("text", ""),
                metadata=doc_data.get("metadata", {}),
                score=fused_scores[doc_id],
                bm25_score=bm25_scores.get(doc_id, 0.0),
                vector_score=vector_scores.get(doc_id, 0.0),
                source=doc_data.get("metadata", {}).get("source", "unknown"),
            ))

        return results

    def ingest_mitre_attack(self, attack_data: List[Dict[str, Any]]):
        """
        Ingest MITRE ATT&CK techniques into both indices.
        
        Expected format per technique:
        {
            "id": "T1059.001",
            "name": "PowerShell",
            "description": "...",
            "tactic": "execution",
            "platforms": ["windows"],
            "detection": "...",
            "data_sources": ["Process: Process Creation", ...]
        }
        """
        for technique in attack_data:
            doc_id = f"mitre_{technique['id']}"
            text = (
                f"MITRE ATT&CK {technique['id']}: {technique['name']}\n"
                f"Tactic: {technique.get('tactic', '')}\n"
                f"Description: {technique.get('description', '')}\n"
                f"Detection: {technique.get('detection', '')}\n"
                f"Data Sources: {', '.join(technique.get('data_sources', []))}"
            )
            metadata = {
                "source": "mitre_attack",
                "technique_id": technique["id"],
                "tactic": technique.get("tactic", ""),
                "platforms": technique.get("platforms", []),
            }
            self.bm25.add_document(doc_id, text, metadata)

        if self.vector_db:
            try:
                docs = [
                    f"MITRE ATT&CK {t['id']}: {t['name']}. {t.get('description', '')[:500]}"
                    for t in attack_data
                ]
                ids = [f"mitre_{t['id']}" for t in attack_data]
                metas = [{"source": "mitre_attack", "technique_id": t["id"]} for t in attack_data]
                self.vector_db.add_documents("mitre_attack", docs, metas, ids)
            except Exception as e:
                logger.error(f"Vector ingestion of MITRE failed: {e}")

    def ingest_sigma_rules(self, rules: List[Dict[str, Any]]):
        """Ingest Sigma detection rules."""
        for rule in rules:
            doc_id = f"sigma_{rule.get('id', hashlib.md5(rule.get('title','').encode()).hexdigest())}"
            text = (
                f"Sigma Rule: {rule.get('title', '')}\n"
                f"Status: {rule.get('status', '')}\n"
                f"Description: {rule.get('description', '')}\n"
                f"Detection: {json.dumps(rule.get('detection', {})) if 'detection' in rule else ''}\n"
                f"Tags: {', '.join(rule.get('tags', []))}\n"
                f"Level: {rule.get('level', '')}"
            )
            metadata = {"source": "sigma_rules", "level": rule.get("level", ""), "tags": rule.get("tags", [])}
            self.bm25.add_document(doc_id, text, metadata)

    def ingest_cves(self, cves: List[Dict[str, Any]]):
        """Ingest CVE/NVD entries."""
        for cve in cves:
            doc_id = f"cve_{cve['id']}"
            text = (
                f"{cve['id']}: {cve.get('description', '')}\n"
                f"CVSS: {cve.get('cvss_score', 'N/A')}\n"
                f"Affected: {', '.join(cve.get('affected_products', []))}\n"
                f"References: {', '.join(cve.get('references', [])[:3])}"
            )
            metadata = {"source": "cve_nvd", "cvss": cve.get("cvss_score", 0), "cve_id": cve["id"]}
            self.bm25.add_document(doc_id, text, metadata)


# Need json import for sigma rule detection serialization
import json
