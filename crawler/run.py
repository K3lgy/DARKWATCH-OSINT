#!/usr/bin/env python3
"""
DARKWATCH OSINT Crawler
-----------------------
Module de crawl pour sites .onion via le réseau Tor (SOCKS5).

Usage:
    python crawler/run.py --target <adresse.onion> --depth <n>

Prérequis:
    - Tor daemon actif sur localhost:9050
    - pip install scrapy requests[socks] stem

AVERTISSEMENT LÉGAL:
    Ce crawler est destiné à un usage défensif et légal uniquement.
    Ne crawlez que des sites pour lesquels vous avez une base légale.
    Consultez docs/ethical-use.md et docs/legal-notice.md.
"""

import argparse
import logging
import os
import sys
import time
from datetime import datetime

# ─── Vérification des dépendances ────────────────────────────
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[ERREUR] Module 'requests' manquant. Installez-le : pip install requests[socks]")
    sys.exit(1)

try:
    import stem
    from stem import Signal
    from stem.control import Controller
except ImportError:
    print("[AVERTISSEMENT] Module 'stem' manquant. La rotation de circuit Tor sera désactivée.")
    stem = None

# ─── Configuration ────────────────────────────────────────────
TOR_SOCKS_HOST = os.getenv("TOR_SOCKS_HOST", "127.0.0.1")
TOR_SOCKS_PORT = int(os.getenv("TOR_SOCKS_PORT", 9050))
TOR_CONTROL_PORT = int(os.getenv("TOR_CONTROL_PORT", 9051))
TOR_CONTROL_PASSWORD = os.getenv("TOR_CONTROL_PASSWORD", "")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", 30))
CRAWL_DELAY = float(os.getenv("CRAWL_DELAY", 2))
DEFAULT_DEPTH = int(os.getenv("DEFAULT_CRAWL_DEPTH", 2))

PROXIES = {
    "http": f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
    "https": f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("darkwatch.crawler")


# ─── Fonctions utilitaires ────────────────────────────────────

def check_tor_connection() -> bool:
    """Vérifie que la connexion Tor est active."""
    try:
        session = requests.Session()
        session.proxies = PROXIES
        response = session.get(
            "https://check.torproject.org/api/ip",
            timeout=15,
        )
        data = response.json()
        if data.get("IsTor"):
            logger.info(f"✔ Circuit Tor actif — IP sortante : {data.get('IP', 'inconnue')}")
            return True
        else:
            logger.warning("⚠ La connexion ne passe pas par Tor.")
            return False
    except Exception as e:
        logger.error(f"✘ Impossible de joindre le réseau Tor : {e}")
        return False


def rotate_circuit():
    """Demande un nouveau circuit Tor via le port de contrôle."""
    if stem is None:
        logger.warning("stem non disponible — rotation de circuit désactivée.")
        return
    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
            controller.authenticate(password=TOR_CONTROL_PASSWORD)
            controller.signal(Signal.NEWNYM)
            logger.info("↻ Nouveau circuit Tor demandé.")
            time.sleep(5)  # Attendre la stabilisation
    except Exception as e:
        logger.error(f"Rotation de circuit échouée : {e}")


def build_session() -> requests.Session:
    """Construit une session requests configurée pour Tor."""
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        "User-Agent": os.getenv("CRAWL_USER_AGENT", "DarkwatchBot/2.4 (defensive OSINT research)"),
        "Accept-Language": "en-US,en;q=0.5",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    retry = Retry(total=2, backoff_factor=1, status_forcelist=[500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def sanitize_onion(target: str) -> str:
    """Normalise une adresse .onion."""
    target = target.strip().lower()
    if not target.startswith("http"):
        target = f"http://{target}"
    if not target.endswith("/"):
        target += "/"
    return target


def extract_links(html: str, base_url: str) -> list[str]:
    """Extrait les liens .onion d'une page HTML (sans beautifulsoup)."""
    import re
    links = []
    pattern = re.compile(r'href=["\']([^"\']*\.onion[^"\']*)["\']', re.IGNORECASE)
    for match in pattern.findall(html):
        href = match.strip()
        if href.startswith("http"):
            links.append(href)
        elif href.startswith("/"):
            from urllib.parse import urljoin
            links.append(urljoin(base_url, href))
    return list(set(links))


def extract_entities(html: str) -> dict:
    """Extrait des entités basiques d'une page (emails, IPs, hashes)."""
    import re
    entities = {"emails": [], "ips": [], "sha256": [], "md5": []}

    entities["emails"] = list(set(re.findall(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", html
    )))
    entities["ips"] = list(set(re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b", html
    )))
    entities["sha256"] = list(set(re.findall(
        r"\b[0-9a-fA-F]{64}\b", html
    )))
    entities["md5"] = list(set(re.findall(
        r"\b[0-9a-fA-F]{32}\b", html
    )))
    return entities


# ─── Crawler principal ────────────────────────────────────────

class DarkwatchCrawler:
    def __init__(self, target: str, depth: int = DEFAULT_DEPTH, output_dir: str = "crawler/output"):
        self.start_url = sanitize_onion(target)
        self.max_depth = depth
        self.output_dir = output_dir
        self.visited: set[str] = set()
        self.queue: list[tuple[str, int]] = []
        self.results: list[dict] = []
        self.session = build_session()

        os.makedirs(output_dir, exist_ok=True)

    def crawl(self):
        logger.info(f"▶ Démarrage du crawl — Cible : {self.start_url} — Profondeur : {self.max_depth}")
        self.queue.append((self.start_url, 0))

        while self.queue:
            url, depth = self.queue.pop(0)

            if url in self.visited:
                continue
            if depth > self.max_depth:
                continue

            self.visited.add(url)
            logger.info(f"  [{depth}/{self.max_depth}] Crawl : {url}")

            try:
                response = self.session.get(url, timeout=REQUEST_TIMEOUT)
                html = response.text
                status = response.status_code
            except Exception as e:
                logger.warning(f"  ✘ Erreur sur {url} : {e}")
                continue

            entities = extract_entities(html)
            links = extract_links(html, url)

            result = {
                "url": url,
                "depth": depth,
                "status": status,
                "timestamp": datetime.utcnow().isoformat(),
                "content_length": len(html),
                "links_found": len(links),
                "entities": entities,
            }
            self.results.append(result)
            logger.info(f"  ✔ {status} — {len(html)} octets — {len(links)} liens — {len(entities['emails'])} emails")

            # Ajout des liens à la queue
            for link in links:
                if link not in self.visited:
                    self.queue.append((link, depth + 1))

            time.sleep(CRAWL_DELAY)

        self._save_results()
        logger.info(f"■ Crawl terminé — {len(self.visited)} pages visitées — {len(self.results)} résultats")

    def _save_results(self):
        import json
        from urllib.parse import urlparse

        domain = urlparse(self.start_url).hostname or "unknown"
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/{domain}_{timestamp}.json"

        with open(filename, "w", encoding="utf-8") as f:
            json.dump({
                "meta": {
                    "target": self.start_url,
                    "max_depth": self.max_depth,
                    "pages_visited": len(self.visited),
                    "crawl_date": datetime.utcnow().isoformat(),
                    "tool": "DARKWATCH Crawler v2.4",
                },
                "results": self.results,
            }, f, indent=2, ensure_ascii=False)

        logger.info(f"  ✔ Résultats sauvegardés : {filename}")


# ─── Point d'entrée ───────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DARKWATCH — Crawler OSINT pour sites .onion",
        epilog="Usage défensif et légal uniquement. Voir docs/ethical-use.md.",
    )
    parser.add_argument("--target", required=True, help="Adresse .onion cible (ex: example3g2uudmdvys.onion)")
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH, help=f"Profondeur de crawl (défaut: {DEFAULT_DEPTH})")
    parser.add_argument("--output", default="crawler/output", help="Répertoire de sortie")
    parser.add_argument("--no-tor-check", action="store_true", help="Ignorer la vérification Tor (non recommandé)")
    parser.add_argument("--rotate-circuit", action="store_true", help="Demander un nouveau circuit Tor avant de démarrer")
    args = parser.parse_args()

    logger.info("═" * 55)
    logger.info("  DARKWATCH OSINT Crawler v2.4")
    logger.info("  Usage défensif et légal uniquement")
    logger.info("═" * 55)

    if args.rotate_circuit:
        rotate_circuit()

    if not args.no_tor_check:
        if not check_tor_connection():
            logger.error("Connexion Tor non disponible. Démarrez le daemon Tor (tor &) et réessayez.")
            sys.exit(1)

    crawler = DarkwatchCrawler(
        target=args.target,
        depth=args.depth,
        output_dir=args.output,
    )
    crawler.crawl()


if __name__ == "__main__":
    main()
