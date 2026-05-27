-- ─────────────────────────────────────────────────────────────
-- DARKWATCH OSINT Platform — Initialisation PostgreSQL
-- ─────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Table principale des pages crawlées
CREATE TABLE IF NOT EXISTS pages (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    url         TEXT NOT NULL,
    depth       INTEGER NOT NULL DEFAULT 0,
    status_code INTEGER,
    content_length INTEGER,
    crawled_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    raw_html    TEXT,
    UNIQUE(url)
);

-- Table des entités extraites
CREATE TABLE IF NOT EXISTS entities (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    page_id     UUID REFERENCES pages(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,   -- 'email', 'ip', 'sha256', 'md5'
    value       TEXT NOT NULL,
    found_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table des mots-clés de la watchlist détectés
CREATE TABLE IF NOT EXISTS matches (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    page_id     UUID REFERENCES pages(id) ON DELETE CASCADE,
    keyword     TEXT NOT NULL,
    alert_level TEXT NOT NULL DEFAULT 'info',  -- critical, high, medium, info
    context     TEXT,
    matched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index pour les recherches fréquentes
CREATE INDEX IF NOT EXISTS idx_pages_crawled_at ON pages(crawled_at DESC);
CREATE INDEX IF NOT EXISTS idx_entities_type_value ON entities(entity_type, value);
CREATE INDEX IF NOT EXISTS idx_matches_level ON matches(alert_level);
CREATE INDEX IF NOT EXISTS idx_matches_keyword ON matches(keyword);

-- Vue résumée pour le tableau de bord
CREATE OR REPLACE VIEW dashboard_summary AS
SELECT
    DATE_TRUNC('day', crawled_at) AS day,
    COUNT(*)                      AS pages_crawled,
    (SELECT COUNT(*) FROM matches m
     JOIN pages p2 ON m.page_id = p2.id
     WHERE DATE_TRUNC('day', p2.crawled_at) = DATE_TRUNC('day', pages.crawled_at)
    )                             AS matches_found
FROM pages
GROUP BY day
ORDER BY day DESC;

-- ─────────────────────────────────────────────────────────────
-- Table des alertes IA (module AI Analyst)
-- ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ai_alerts (
    id               SERIAL PRIMARY KEY,
    source_url       TEXT,
    source_title     TEXT,
    summary          TEXT,
    threat_type      TEXT,
    risk_level       TEXT NOT NULL DEFAULT 'INFO',
    confidence_score INTEGER,
    raw_content      TEXT,
    ai_analysis      JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_alerts_risk    ON ai_alerts(risk_level);
CREATE INDEX IF NOT EXISTS idx_ai_alerts_created ON ai_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_alerts_type    ON ai_alerts(threat_type);
-- Recherche full-text sur le résumé
CREATE INDEX IF NOT EXISTS idx_ai_alerts_summary_fts
    ON ai_alerts USING gin(to_tsvector('english', coalesce(summary, '')));
