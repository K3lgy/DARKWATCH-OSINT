# ─────────────────────────────────────────────────────────────
# DARKWATCH — Chunking intelligent pour LLM
# ─────────────────────────────────────────────────────────────
#
# Les dumps dark web peuvent être volumineux. On chunke avant
# d'envoyer au LLM, puis on consolide les résultats.
# ─────────────────────────────────────────────────────────────

import re
from typing import List


# Taille cible par chunk (en caractères)
# Mistral 7B : context window ~32k tokens ≈ ~24k chars — on reste large
DEFAULT_CHUNK_SIZE = 4000
OVERLAP = 200       # chevauchement pour ne pas couper des IOCs en deux


def clean_text(text: str) -> str:
    """
    Nettoyage basique avant chunking :
    - Supprime les lignes vides répétées
    - Normalise les espaces
    - Supprime les caractères de contrôle sauf newline/tab
    """
    # Caractères de contrôle
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # Lignes vides multiples → une seule
    text = re.sub(r"\n{3,}", "\n\n", text)
    # Espaces multiples
    text = re.sub(r"[ \t]{2,}", " ", text)
    return text.strip()


def split_by_paragraphs(text: str, max_size: int = DEFAULT_CHUNK_SIZE) -> List[str]:
    """
    Découpe le texte en chunks en respectant les paragraphes.
    Meilleur que le split naïf par caractères pour préserver le contexte.
    """
    paragraphs = re.split(r"\n{2,}", text)
    chunks: List[str] = []
    current = ""

    for para in paragraphs:
        para = para.strip()
        if not para:
            continue

        # Si le paragraphe seul dépasse max_size, on le coupe bêtement
        if len(para) > max_size:
            if current:
                chunks.append(current.strip())
                current = ""
            for i in range(0, len(para), max_size - OVERLAP):
                chunks.append(para[i : i + max_size])
            continue

        if len(current) + len(para) + 2 > max_size:
            if current:
                chunks.append(current.strip())
            current = para
        else:
            current = f"{current}\n\n{para}" if current else para

    if current:
        chunks.append(current.strip())

    return chunks


def split_text(text: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> List[str]:
    """
    Point d'entrée principal.
    Nettoie puis découpe intelligemment.
    """
    cleaned = clean_text(text)
    if len(cleaned) <= chunk_size:
        return [cleaned]
    return split_by_paragraphs(cleaned, max_size=chunk_size)


def should_chunk(text: str, threshold: int = DEFAULT_CHUNK_SIZE) -> bool:
    """Retourne True si le texte nécessite d'être chunké."""
    return len(text) > threshold
