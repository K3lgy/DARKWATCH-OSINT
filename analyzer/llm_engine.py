#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
# DARKWATCH — LLM Engine (Ollama)
# ─────────────────────────────────────────────────────────────
#
# Gère les appels au LLM local via Ollama.
# Pipeline complet : chunking → analyse → fusion des chunks
# → enrichissement IOC regex → risk engine hybride.
# ─────────────────────────────────────────────────────────────

import json
import logging
import os
import time
from typing import Optional

import requests

from .chunking import split_text, should_chunk
from .ioc_parser import extract_iocs_regex, merge_iocs
from .prompts import SOC_ANALYSIS_PROMPT, EXPLAIN_WHY_PROMPT, SUMMARIZE_CHUNK_PROMPT
from .risk_engine import enrich_analysis
from .schemas import ThreatAnalysis, IOCs, RiskLevel, ThreatType, parse_llm_response

logger = logging.getLogger("darkwatch.analyzer")

# ─── Configuration ───────────────────────────────────────────

OLLAMA_URL    = os.getenv("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL", "mistral")
LLM_TIMEOUT   = int(os.getenv("LLM_TIMEOUT", 120))
LLM_MAX_RETRIES = int(os.getenv("LLM_MAX_RETRIES", 2))


# ─── Appel Ollama bas niveau ──────────────────────────────────

def _call_ollama(prompt: str, expect_json: bool = True) -> str:
    """
    Appel brut à l'API Ollama /api/generate.
    Retourne le texte de réponse ou lève une exception.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,        # Déterministe pour l'analyse
            "num_predict": 1024,
        },
    }
    if expect_json:
        payload["format"] = "json"

    for attempt in range(1, LLM_MAX_RETRIES + 1):
        try:
            resp = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json=payload,
                timeout=LLM_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "")
        except requests.exceptions.ConnectionError:
            logger.error("Ollama non joignable — vérifiez que le service tourne (docker compose up ollama)")
            raise
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout Ollama (tentative {attempt}/{LLM_MAX_RETRIES})")
            if attempt == LLM_MAX_RETRIES:
                raise
            time.sleep(5)
        except Exception as e:
            logger.error(f"Erreur Ollama : {e}")
            raise


def _parse_json_response(raw: str) -> dict:
    """Parse la réponse JSON du LLM, tolère les fences markdown."""
    # Nettoie les éventuels ```json ... ```
    clean = raw.strip()
    if clean.startswith("```"):
        clean = clean.split("```")[1]
        if clean.startswith("json"):
            clean = clean[4:]
    clean = clean.strip()
    return json.loads(clean)


# ─── Analyse d'un chunk unique ────────────────────────────────

def _analyze_chunk(chunk: str) -> dict:
    """Envoie un chunk au LLM et retourne le dict JSON brut."""
    prompt = SOC_ANALYSIS_PROMPT.format(content=chunk)
    raw = _call_ollama(prompt, expect_json=True)
    return _parse_json_response(raw)


def _summarize_chunk(chunk: str) -> str:
    """Résume un chunk avant analyse multi-chunk."""
    prompt = SUMMARIZE_CHUNK_PROMPT.format(content=chunk)
    return _call_ollama(prompt, expect_json=False).strip()


# ─── Fusion de résultats multi-chunks ────────────────────────

def _merge_chunk_results(results: list[dict]) -> dict:
    """
    Fusionne plusieurs analyses de chunks en une seule.
    Stratégie : prend le pire risk_level, fusionne IOCs/assets/tags.
    """
    if len(results) == 1:
        return results[0]

    risk_order = {"CRITICAL": 2, "WARN": 1, "INFO": 0}
    best = max(results, key=lambda r: risk_order.get(r.get("risk_level", "INFO"), 0))

    merged = dict(best)

    all_emails, all_ips, all_hashes = set(), set(), set()
    all_assets, all_tags, all_actions = set(), set(), []

    for r in results:
        iocs = r.get("iocs", {})
        all_emails.update(iocs.get("emails", []))
        all_ips.update(iocs.get("ips", []))
        all_hashes.update(iocs.get("hashes", []))
        all_assets.update(r.get("targeted_assets", []))
        all_tags.update(r.get("tags", []))
        all_actions.extend(r.get("recommended_actions", []))

    merged["iocs"] = {
        "emails": list(all_emails),
        "ips": list(all_ips),
        "hashes": list(all_hashes),
    }
    merged["targeted_assets"] = list(all_assets)
    merged["tags"] = list(all_tags)
    # Déduplique les actions en préservant l'ordre
    seen = set()
    merged["recommended_actions"] = [
        a for a in all_actions if not (a in seen or seen.add(a))
    ][:6]
    # Moyenne des scores de confiance
    scores = [r.get("confidence_score", 50) for r in results]
    merged["confidence_score"] = int(sum(scores) / len(scores))

    return merged


# ─── Point d'entrée principal ────────────────────────────────

def analyze_content(
    content: str,
    source_url: Optional[str] = None,
    source_title: Optional[str] = None,
) -> ThreatAnalysis:
    """
    Pipeline complet :
    1. Chunking si nécessaire
    2. Analyse LLM (par chunk)
    3. Fusion des résultats
    4. Enrichissement IOCs regex
    5. Risk engine hybride
    """
    logger.info(f"Analyse LLM — {len(content)} caractères — modèle : {OLLAMA_MODEL}")

    chunks = split_text(content)
    logger.info(f"  → {len(chunks)} chunk(s)")

    # Pour les textes multi-chunks, on résume d'abord chaque chunk
    if len(chunks) > 3:
        logger.info("  → Résumé des chunks avant analyse...")
        chunks = [_summarize_chunk(c) for c in chunks]

    chunk_results = []
    for i, chunk in enumerate(chunks, 1):
        logger.info(f"  → Chunk {i}/{len(chunks)}...")
        try:
            result = _analyze_chunk(chunk)
            chunk_results.append(result)
        except Exception as e:
            logger.warning(f"  ✘ Chunk {i} échoué : {e}")

    if not chunk_results:
        logger.error("Tous les chunks ont échoué — retour analyse vide")
        return _fallback_analysis(content, source_url, source_title)

    merged = _merge_chunk_results(chunk_results)

    # Parse en objet typé
    analysis = parse_llm_response(merged, source_url=source_url, source_title=source_title)
    analysis.raw_content = content[:2000]   # Stocke un extrait
    analysis.model_used = OLLAMA_MODEL

    # Enrichissement IOC regex (filet de sécurité)
    regex_iocs = extract_iocs_regex(content)
    analysis.iocs = merge_iocs(regex_iocs, analysis.iocs)

    # Risk engine hybride
    analysis = enrich_analysis(analysis)

    logger.info(
        f"  ✔ Analyse terminée — {analysis.risk_level.value} "
        f"[{analysis.threat_type.value}] — score={analysis.confidence_score}"
    )
    return analysis


def explain_analysis(analysis: ThreatAnalysis) -> str:
    """
    Génère une explication en langage naturel de l'analyse.
    Utile pour les analystes SOC juniors.
    """
    prompt = EXPLAIN_WHY_PROMPT.format(analysis=json.dumps(analysis.to_dict(), indent=2))
    return _call_ollama(prompt, expect_json=False).strip()


def _fallback_analysis(
    content: str,
    source_url: Optional[str],
    source_title: Optional[str],
) -> ThreatAnalysis:
    """Analyse de fallback si le LLM est indisponible (regex seulement)."""
    from .schemas import IOCs as _IOCs
    regex_iocs = extract_iocs_regex(content)
    return ThreatAnalysis(
        summary="LLM unavailable — regex-only analysis.",
        risk_level=RiskLevel.INFO,
        threat_type=ThreatType.UNKNOWN,
        targeted_assets=[],
        iocs=regex_iocs,
        confidence_score=10,
        recommended_actions=["Review content manually."],
        tags=["fallback"],
        source_url=source_url,
        source_title=source_title,
        raw_content=content[:2000],
        model_used="fallback",
    )


# ─── Health check Ollama ──────────────────────────────────────

def check_ollama() -> bool:
    """Retourne True si Ollama est joignable et le modèle disponible."""
    try:
        resp = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        resp.raise_for_status()
        models = [m["name"] for m in resp.json().get("models", [])]
        available = any(OLLAMA_MODEL in m for m in models)
        if not available:
            logger.warning(
                f"Modèle '{OLLAMA_MODEL}' non trouvé dans Ollama. "
                f"Lancez : ollama pull {OLLAMA_MODEL}"
            )
        return available
    except Exception:
        return False
