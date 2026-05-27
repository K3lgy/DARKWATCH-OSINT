# ─────────────────────────────────────────────────────────────
# DARKWATCH — Extraction d'IOCs (regex + enrichissement LLM)
# ─────────────────────────────────────────────────────────────

import re
import ipaddress
from typing import List
from .schemas import IOCs

# ─── Patterns regex ──────────────────────────────────────────

EMAIL_RE    = re.compile(r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
IP_RE       = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
SHA256_RE   = re.compile(r"\b[0-9a-fA-F]{64}\b")
MD5_RE      = re.compile(r"\b[0-9a-fA-F]{32}\b")

# IPs privées / loopback à exclure
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_public_ip(ip_str: str) -> bool:
    """Retourne True si l'IP est publique et valide."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return not any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def extract_iocs_regex(text: str) -> IOCs:
    """
    Extrait les IOCs via regex. Rapide, déterministe, sans LLM.
    Les IPs privées / invalides sont filtrées.
    """
    emails = list(set(EMAIL_RE.findall(text)))

    raw_ips = IP_RE.findall(text)
    ips = list(set(ip for ip in raw_ips if _is_public_ip(ip)))

    # SHA256 en priorité (64 hex) — les MD5 (32 hex) sont un sous-ensemble
    sha256 = list(set(SHA256_RE.findall(text)))

    # MD5 uniquement si pas déjà capturé comme début de SHA256
    sha256_set = set(h.lower() for h in sha256)
    md5 = list(set(
        h for h in MD5_RE.findall(text)
        if not any(s.startswith(h.lower()) for s in sha256_set)
    ))

    hashes = sha256 + md5

    return IOCs(emails=emails, ips=ips, hashes=hashes)


def merge_iocs(regex_iocs: IOCs, llm_iocs: IOCs) -> IOCs:
    """
    Fusionne les IOCs regex et LLM.
    Le LLM peut capturer des IOCs obfusqués (ex: "1.2.3[.]4"),
    les regex couvrent les formats standards.
    """
    return regex_iocs.merge(llm_iocs)


def ioc_summary(iocs: IOCs) -> str:
    """Résumé lisible du nombre d'IOCs extraits."""
    parts = []
    if iocs.emails:
        parts.append(f"{len(iocs.emails)} email(s)")
    if iocs.ips:
        parts.append(f"{len(iocs.ips)} IP(s)")
    if iocs.hashes:
        parts.append(f"{len(iocs.hashes)} hash(es)")
    return ", ".join(parts) if parts else "aucun IOC détecté"
