# ─────────────────────────────────────────────────────────────
# DARKWATCH — Risk Engine hybride (LLM + heuristiques)
# ─────────────────────────────────────────────────────────────
#
# Le LLM produit un premier risk_level et un confidence_score.
# Ce module applique des heuristiques déterministes par-dessus
# pour éviter les faux négatifs sur des patterns connus.
# ─────────────────────────────────────────────────────────────

from .schemas import ThreatAnalysis, RiskLevel, ThreatType

# Mots-clés haute criticité dans le résumé ou le contenu
_CRITICAL_KEYWORDS = {
    "ransomware", "blackbasta", "lockbit", "alphv", "clop", "akira",
    "admin access", "domain admin", "root access", "full access",
    "edr disabled", "edr bypass", "av disabled",
    "data exfiltration", "exfiltrated", "database dump",
    "credentials leak", "credentials sale",
    "0day", "zero-day", "rce", "remote code execution",
}

_WARN_KEYWORDS = {
    "vpn access", "rdp", "ssh credentials", "webshell",
    "password", "login", "account sale", "access for sale",
    "breach", "leak", "exposed", "forum post",
    "phishing kit", "stealer log",
}

# Types de menaces qui élèvent automatiquement le score
_CRITICAL_THREAT_TYPES = {
    ThreatType.RANSOMWARE,
    ThreatType.INITIAL_ACCESS,
    ThreatType.VULNERABILITY,
}

_WARN_THREAT_TYPES = {
    ThreatType.DATA_LEAK,
    ThreatType.CREDENTIAL_SALE,
    ThreatType.MALWARE_SALE,
}


def _keyword_score(text: str) -> int:
    """Retourne un score additionnel basé sur les mots-clés."""
    text_lower = text.lower()
    score = 0
    for kw in _CRITICAL_KEYWORDS:
        if kw in text_lower:
            score += 15
    for kw in _WARN_KEYWORDS:
        if kw in text_lower:
            score += 8
    return min(score, 60)   # plafonné à 60 pts


def compute_risk(analysis: ThreatAnalysis) -> RiskLevel:
    """
    Réévalue le risk_level en combinant :
    - Le score de confiance LLM
    - Le type de menace
    - Les IOCs présents
    - Les mots-clés dans le résumé
    - Le nombre d'assets ciblés
    """
    score = 0

    # 1. Apport du LLM
    score += analysis.confidence_score * 0.4   # max 40 pts

    # 2. Type de menace
    if analysis.threat_type in _CRITICAL_THREAT_TYPES:
        score += 30
    elif analysis.threat_type in _WARN_THREAT_TYPES:
        score += 15

    # 3. IOCs présents
    iocs = analysis.iocs
    if iocs.emails:
        score += 5
    if iocs.ips:
        score += 5
    if iocs.hashes:
        score += 10

    # 4. Mots-clés dans le résumé
    score += _keyword_score(analysis.summary)

    # 5. Assets ciblés identifiés
    if len(analysis.targeted_assets) >= 1:
        score += 10

    # ─── Décision finale ────────────────────────────────────
    if score >= 70:
        return RiskLevel.CRITICAL
    elif score >= 40:
        return RiskLevel.WARN
    return RiskLevel.INFO


def enrich_analysis(analysis: ThreatAnalysis) -> ThreatAnalysis:
    """
    Applique le risk engine hybride sur une analyse existante.
    Remplace le risk_level LLM par le score hybride.
    """
    analysis.risk_level = compute_risk(analysis)
    return analysis
