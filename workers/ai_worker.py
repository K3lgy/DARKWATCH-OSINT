#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
# DARKWATCH — AI Worker (Redis queue consumer)
# ─────────────────────────────────────────────────────────────
#
# Consomme la queue Redis "darkwatch:events", analyse chaque
# événement via le LLM engine et sauvegarde en PostgreSQL.
#
# Usage :
#   python -m workers.ai_worker
#   (ou via docker compose service)
# ─────────────────────────────────────────────────────────────

import json
import logging
import os
import sys
import time

import psycopg2
import redis

# Le module analyzer est dans le parent
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.llm_engine import analyze_content, check_ollama
from analyzer.schemas import ThreatAnalysis

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("darkwatch.worker")

# ─── Configuration ───────────────────────────────────────────

REDIS_URL    = os.getenv("REDIS_URL", "redis://localhost:6379")
REDIS_QUEUE  = "darkwatch:events"
REDIS_DONE   = "darkwatch:done"
REDIS_FAILED = "darkwatch:failed"

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 5432))
DB_NAME = os.getenv("DB_NAME", "darkwatch")
DB_USER = os.getenv("DB_USER", "osint_user")
DB_PASS = os.getenv("DB_PASS", "changeme")

POLL_TIMEOUT = 5    # secondes de blocage sur blpop


# ─── Connexions ──────────────────────────────────────────────

def get_redis() -> redis.Redis:
    return redis.from_url(REDIS_URL, decode_responses=True)


def get_db():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT,
        dbname=DB_NAME, user=DB_USER, password=DB_PASS,
    )


# ─── Persistance ─────────────────────────────────────────────

INSERT_SQL = """
INSERT INTO ai_alerts (
    source_url, source_title, summary, threat_type, risk_level,
    confidence_score, raw_content, ai_analysis
) VALUES (
    %(source_url)s, %(source_title)s, %(summary)s, %(threat_type)s,
    %(risk_level)s, %(confidence_score)s, %(raw_content)s, %(ai_analysis)s
)
RETURNING id;
"""


def save_analysis(conn, analysis: ThreatAnalysis) -> int:
    d = analysis.to_dict()
    with conn.cursor() as cur:
        cur.execute(INSERT_SQL, {
            "source_url":       d["source_url"],
            "source_title":     d["source_title"],
            "summary":          d["summary"],
            "threat_type":      d["threat_type"],
            "risk_level":       d["risk_level"],
            "confidence_score": d["confidence_score"],
            "raw_content":      d.get("raw_content", "")[:10000],
            "ai_analysis":      json.dumps(d),
        })
        row_id = cur.fetchone()[0]
    conn.commit()
    return row_id


# ─── Boucle principale ────────────────────────────────────────

def run_worker():
    logger.info("═" * 55)
    logger.info("  DARKWATCH AI Worker — démarrage")
    logger.info("═" * 55)

    # Attendre qu'Ollama soit prêt
    for attempt in range(12):   # max 60s
        if check_ollama():
            logger.info("✔ Ollama joignable — modèle prêt")
            break
        logger.warning(f"Ollama non prêt ({attempt + 1}/12) — attente 5s...")
        time.sleep(5)
    else:
        logger.error("Ollama indisponible après 60s — arrêt du worker")
        sys.exit(1)

    r = get_redis()
    db = get_db()

    logger.info(f"En attente d'événements sur '{REDIS_QUEUE}'...")

    while True:
        try:
            item = r.blpop(REDIS_QUEUE, timeout=POLL_TIMEOUT)
            if item is None:
                continue    # timeout — on reboucle

            _, raw = item
            event = json.loads(raw)

            content       = event.get("content", "")
            source_url    = event.get("url")
            source_title  = event.get("title")

            if not content.strip():
                logger.warning(f"Événement vide ignoré : {source_url}")
                continue

            logger.info(f"▶ Analyse : {source_url or '(sans URL)'}")

            analysis = analyze_content(
                content,
                source_url=source_url,
                source_title=source_title,
            )

            alert_id = save_analysis(db, analysis)
            logger.info(
                f"  ✔ Alerte #{alert_id} sauvegardée — "
                f"{analysis.risk_level.value} [{analysis.threat_type.value}]"
            )

            # Notifie la queue "done" pour le dashboard (SSE / polling)
            r.rpush(REDIS_DONE, json.dumps({
                "alert_id": alert_id,
                "risk_level": analysis.risk_level.value,
                "threat_type": analysis.threat_type.value,
                "summary": analysis.summary[:120],
            }))

        except psycopg2.OperationalError as e:
            logger.error(f"PostgreSQL déconnecté : {e} — reconnexion...")
            time.sleep(3)
            try:
                db = get_db()
            except Exception:
                pass

        except redis.exceptions.RedisError as e:
            logger.error(f"Redis erreur : {e} — reconnexion...")
            time.sleep(3)
            try:
                r = get_redis()
            except Exception:
                pass

        except Exception as e:
            logger.exception(f"Erreur inattendue : {e}")
            # Remet l'événement en queue "failed" pour inspection
            try:
                r.rpush(REDIS_FAILED, raw)
            except Exception:
                pass


if __name__ == "__main__":
    run_worker()
