# ─────────────────────────────────────────────────────────────
# DARKWATCH — Schémas de données (dataclasses + validation)
# ─────────────────────────────────────────────────────────────

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime
from enum import Enum


class RiskLevel(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    CRITICAL = "CRITICAL"


class ThreatType(str, Enum):
    RANSOMWARE = "RANSOMWARE"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    DATA_LEAK = "DATA_LEAK"
    CREDENTIAL_SALE = "CREDENTIAL_SALE"
    VULNERABILITY = "VULNERABILITY"
    MALWARE_SALE = "MALWARE_SALE"
    HACKTIVISM = "HACKTIVISM"
    FRAUD = "FRAUD"
    UNKNOWN = "UNKNOWN"


@dataclass
class IOCs:
    emails: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)

    def merge(self, other: "IOCs") -> "IOCs":
        """Fusionne deux ensembles d'IOCs en dédupliquant."""
        return IOCs(
            emails=list(set(self.emails + other.emails)),
            ips=list(set(self.ips + other.ips)),
            hashes=list(set(self.hashes + other.hashes)),
        )

    def to_dict(self) -> dict:
        return {
            "emails": self.emails,
            "ips": self.ips,
            "hashes": self.hashes,
        }


@dataclass
class ThreatAnalysis:
    summary: str
    risk_level: RiskLevel
    threat_type: ThreatType
    targeted_assets: List[str]
    iocs: IOCs
    confidence_score: int           # 0-100
    recommended_actions: List[str]
    tags: List[str]

    # Métadonnées (non produites par le LLM)
    source_url: Optional[str] = None
    source_title: Optional[str] = None
    raw_content: Optional[str] = None
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    model_used: str = "mistral"

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "risk_level": self.risk_level.value,
            "threat_type": self.threat_type.value,
            "targeted_assets": self.targeted_assets,
            "iocs": self.iocs.to_dict(),
            "confidence_score": self.confidence_score,
            "recommended_actions": self.recommended_actions,
            "tags": self.tags,
            "source_url": self.source_url,
            "source_title": self.source_title,
            "analyzed_at": self.analyzed_at.isoformat(),
            "model_used": self.model_used,
        }


def parse_llm_response(data: dict, source_url: str = None, source_title: str = None) -> ThreatAnalysis:
    """
    Convertit la réponse JSON brute du LLM en ThreatAnalysis typé.
    Tolère les valeurs manquantes ou invalides.
    """
    # Normalise le risk_level
    try:
        risk_level = RiskLevel(data.get("risk_level", "INFO").upper())
    except ValueError:
        risk_level = RiskLevel.INFO

    # Normalise le threat_type
    try:
        threat_type = ThreatType(data.get("threat_type", "UNKNOWN").upper())
    except ValueError:
        threat_type = ThreatType.UNKNOWN

    # Parse les IOCs
    raw_iocs = data.get("iocs", {})
    iocs = IOCs(
        emails=raw_iocs.get("emails", []) or [],
        ips=raw_iocs.get("ips", []) or [],
        hashes=raw_iocs.get("hashes", []) or [],
    )

    # Borne le confidence_score
    score = int(data.get("confidence_score", 50))
    score = max(0, min(100, score))

    return ThreatAnalysis(
        summary=data.get("summary", "No summary available."),
        risk_level=risk_level,
        threat_type=threat_type,
        targeted_assets=data.get("targeted_assets", []) or [],
        iocs=iocs,
        confidence_score=score,
        recommended_actions=data.get("recommended_actions", []) or [],
        tags=data.get("tags", []) or [],
        source_url=source_url,
        source_title=source_title,
    )
