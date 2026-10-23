"""Lightweight Indic script/language hints; never treats language as risk evidence.

Shared scripts are intentionally reported as ambiguous. Callers may pass a
validated language_hint, but detection rules still run independently of it.
"""
from __future__ import annotations

import re
from collections import Counter

SUPPORTED_LANGUAGES = {
    "en": "English", "hi": "Hindi", "hinglish": "Hinglish / Romanized Hindi",
    "bn": "Bengali", "mr": "Marathi", "te": "Telugu", "ta": "Tamil",
    "gu": "Gujarati", "ur": "Urdu", "kn": "Kannada", "ml": "Malayalam",
    "or": "Odia", "pa": "Punjabi", "as": "Assamese",
}

_SCRIPT_RANGES = (
    ("ur_pa", 0x0600, 0x06FF),
    ("pa", 0x0A00, 0x0A7F), ("gu", 0x0A80, 0x0AFF),
    ("or", 0x0B00, 0x0B7F), ("ta", 0x0B80, 0x0BFF),
    ("te", 0x0C00, 0x0C7F), ("kn", 0x0C80, 0x0CFF),
    ("ml", 0x0D00, 0x0D7F), ("hi_mr", 0x0900, 0x097F),
    ("bn_as", 0x0980, 0x09FF),
)
_ROMAN_HINDI = re.compile(
    r"\b(?:aap|aapka|aapke|khata|band|hojayega|ho\s+jayega|turant|abhi|bhejo|bhej|"
    r"paise|paisa|inaam|jeeta|jeet|jama|karo|karna|daalo|daalo|nahi|mat|hai|hoga|"
    r"kripya|pahle|pehle|aaj|kal|milne|liye|seva|vapas|wapas)\b",
    re.IGNORECASE,
)
_MARATHI_HINT = re.compile(r"\b(?:tumcha|tumche|ahe|kara|lagech|khate|paise|krupaya)\b|(?:तुमचे|तुमचा|त्वरित|अद्ययावत|बक्षीस|परतावा)")


def detect_language(text: str, language_hint: str | None = None) -> tuple[str, float, str]:
    """Return a best-effort code, confidence and style; no language is inferred as safe."""
    hint = (language_hint or "auto").strip().casefold().replace("_", "-")
    hint_map = {"english": "en", "hindi": "hi", "marathi": "mr", "bengali": "bn", "assamese": "as",
                "telugu": "te", "tamil": "ta", "gujarati": "gu", "urdu": "ur", "kannada": "kn",
                "malayalam": "ml", "odia": "or", "oriya": "or", "punjabi": "pa", "hinglish": "hinglish"}
    hinted = hint_map.get(hint, hint if hint in SUPPORTED_LANGUAGES else None)
    if hinted:
        return hinted, 0.65, "user_hint"

    counts = Counter()
    latin = 0
    for char in text:
        codepoint = ord(char)
        if char.isalpha() and (0x0041 <= codepoint <= 0x024F):
            latin += 1
        for language, start, end in _SCRIPT_RANGES:
            if start <= codepoint <= end and char.isalpha():
                counts[language] += 1
                break
    indic_count = sum(counts.values())
    total = latin + indic_count
    if not total:
        return "und", 0.0, "unknown"

    active = [language for language, count in counts.items() if count / total >= 0.15]
    if active and latin / total >= 0.15:
        return "mixed", min(0.99, max(latin / total, max(counts.values()) / total)), "code_mixed"
    if len(active) > 1:
        return "mixed", max(counts[language] for language in active) / total, "multi_script"
    if active:
        script = active[0]
        confidence = counts[script] / total
        if script == "ur_pa":
            return "ur", min(0.65, confidence), "urdu_punjabi_shahmukhi_ambiguous"
        if script == "hi_mr":
            if _MARATHI_HINT.search(text):
                return "mr", max(0.65, confidence), "devanagari"
            return "hi", min(0.72, confidence), "devanagari_ambiguous_hi_mr"
        if script == "bn_as":
            # Assamese and Bengali share the Unicode block. Distinctive letters
            # are hints, not a dependable language classifier.
            if re.search(r"[ৰৱ]", text):
                return "as", max(0.7, confidence), "bengali_assamese_script"
            return "bn", min(0.72, confidence), "bengali_assamese_ambiguous"
        return script, confidence, "native_script"
    if _ROMAN_HINDI.search(text):
        return "hinglish", 0.78, "romanized_hindi"
    if latin / total > 0.8:
        return "en", min(0.85, latin / total), "latin_script"
    return "und", 0.0, "unknown"
