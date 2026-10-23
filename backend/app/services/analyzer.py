"""Privacy-conscious scam analysis using explicit rules plus a development ML model.

Rules are intentionally context-aware. The bundled classifier is only a small
development fixture and must never be presented as a calibrated production model.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import socket
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import httpx

from app.config import ARTIFACT_DIR, SAFE_BROWSING_API_KEY
from app.schemas import MLAssessment, RuleIndicator, ThreatIntelResult
from app.services.language import detect_language

logger = logging.getLogger("scamsathi.analyzer")


def _load_model():
    artifact = ARTIFACT_DIR / "model.joblib"
    try:
        metadata_path = ARTIFACT_DIR / "metadata.json"
        if not metadata_path.exists():
            logger.error("model_metadata_missing; rules-only analysis enabled")
            return None
        if metadata_path.exists():
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            artifact_name = metadata.get("artifact_file", "model.joblib")
            if Path(artifact_name).name != artifact_name:
                raise ValueError("unsafe model artifact path")
            artifact = ARTIFACT_DIR / artifact_name
        if not artifact.exists():
            logger.error("model_artifact_missing; rules-only analysis enabled")
            return None
        if metadata_path.exists():
            expected_hash = metadata.get("artifact_sha256")
            if not expected_hash:
                logger.error("model_artifact_checksum_missing; rules-only analysis enabled")
                return None
            if hashlib.sha256(artifact.read_bytes()).hexdigest() != expected_hash:
                logger.error("model_artifact_hash_mismatch; rules-only analysis enabled")
                return None
        import joblib

        return joblib.load(artifact)
    except Exception as exc:  # Broken artifacts must not take the API down.
        logger.warning("model_artifact_unavailable type=%s", type(exc).__name__)
        return None


MODEL_METADATA = {}
try:
    metadata_file = ARTIFACT_DIR / "metadata.json"
    if metadata_file.exists():
        MODEL_METADATA = json.loads(metadata_file.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    logger.warning("model_metadata_unavailable type=%s", type(exc).__name__)
MODEL = _load_model()


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    severity: str
    weight: int
    pattern: re.Pattern[str]
    description: str


def _rule(identifier: str, name: str, category: str, severity: str, weight: int, pattern: str, description: str) -> Rule:
    return Rule(identifier, name, category, severity, weight, re.compile(pattern, re.IGNORECASE), description)


RULES = [
    _rule(
        "UPI_PIN_REQUEST", "UPI PIN / Collect Request Trap", "UPI Payment Fraud", "critical", 48,
        r"(?:\bupi\s*pin\b.{0,55}\b(?:receive|claim|collect|refund|cashback|money|payment|paise|paisa)\b"
        r"|\b(?:receive|claim|collect|refund|cashback|money|payment|paise|paisa)\b.{0,55}\bupi\s*pin\b"
        r"|\b(?:scan|approve|accept|enter|pay)\b.{0,35}\b(?:qr(?:\s+code)?|collect(?:\s+request)?|upi\s+request)\b.{0,55}\b(?:receive|claim|refund|cashback|money|payment|paise|paisa)\b"
        r"|\bupi\s+request\b.{0,35}\b(?:approve|accept|enter)\w*\b.{0,35}\b(?:pin|otp|password)\b"
        r"|\b(?:paise|paisa|money)\b.{0,55}\b(?:qr|pin|collect request)\b.{0,30}\b(?:receive|claim|refund|cashback|daal|dalo|daalo|enter|scan|approve)\w*\b)",
        "A UPI PIN authorizes money leaving an account; approving a collect request or entering a PIN to receive a payment is a warning sign.",
    ),
    _rule(
        "OTP_CREDENTIAL_THEFT", "OTP / Secret Credential Solicitation", "Credential & OTP Theft", "critical", 46,
        r"(?:(?:\b(?:share|send|tell|provide|reveal|forward|reply|batao|bhejo|likho)\b[^.!?;\n]{0,35})"
        r"(?:\b(?:otp|one[ -]?time password|cvv(?:\s+number)?|atm\s+pin|bank\s+pin|security code)\b)"
        r"|(?:\b(?:otp|one[ -]?time password|cvv(?:\s+number)?|atm\s+pin|bank\s+pin|security code)\b[^.!?;\n]{0,35})"
        r"\b(?:share|send|tell|provide|reveal|forward|reply|batao|bhejo|likho)\b)",
        "A message asks the recipient to disclose a one-time code or payment credential.",
    ),
    _rule(
        "KYC_ACCOUNT_BLOCK", "Urgent KYC / Account Suspension Threat", "Phishing & KYC Fraud", "high", 38,
        r"(?:(?:\b(?:kyc|pan|account|card|bank)\b.{0,60}\b(?:blocked|suspend(?:ed)?|freeze|deactivat\w*|clos\w*|expir\w*)\b)"
        r"|(?:\b(?:blocked|suspend(?:ed)?|freeze|deactivat\w*|clos\w*|expir\w*)\b.{0,60}\b(?:kyc|pan|account|card|bank)\b))"
        r".{0,80}\b(?:today|tonight|immediately|urgent|within\s+\d+|update|verify|click|link|share|send|otp|kyc)\b"
        r"|\b(?:kyc|pan)\b.{0,35}\b(?:expired|update|verify|suspend|blocked)\b.{0,60}\b(?:immediately|today|tonight|link|click|otp|send|share)\b",
        "An account threat is paired with urgent identity verification or a request to act through a message.",
    ),
    _rule(
        "FAKE_REFUND_REWARD_PAYMENT", "Fee or Payment to Claim a Refund / Reward", "Payment & Reward Scam", "high", 36,
        r"(?:(?:\b(?:refund|cashback|reward|prize|lottery|winner|payout|claim)\b.{0,65}\b(?:pay|payment|fee|charge|deposit|transfer|tax)\b)"
        r"|(?:\b(?:pay|payment|fee|charge|deposit|transfer|tax)\b.{0,65}\b(?:refund|cashback|reward|prize|lottery|winner|payout|claim)\b))"
        r"|\b(?:processing fee|release fee|verification charge)\b.{0,65}\b(?:claim|refund|reward|cashback|prize|release)\b",
        "The message asks for money before releasing a refund, reward, prize, or payout.",
    ),
    _rule(
        "URGENT_TRANSFER_COERCION", "Urgent or Coerced Money Transfer", "Payment & Extortion Scam", "high", 35,
        r"\b(?:transfer|send|pay|deposit|wire)\b.{0,55}\b(?:now|immediately|urgent|today|secret|verification|safe account|avoid arrest|avoid block)\b"
        r"|\b(?:now|immediately|urgent|today|secret)\b.{0,55}\b(?:transfer|send|pay|deposit|wire)\b",
        "An urgent or coercive instruction asks the recipient to move money.",
    ),
    _rule(
        "IMPERSONATION_DIGITAL_ARREST", "Police / Authority Impersonation and Coercion", "Impersonation & Extortion", "critical", 48,
        r"(?:(?:\b(?:cbi|police|customs|fedex|trai|enforcement directorate|ed officer|court|aadhaar|parcel)\b.{0,100})"
        r"(?:\b(?:arrest|warrant|contraband|drugs|illegal parcel|investigation|case registered|digital arrest|disconnect your number|criminal case)\b)"
        r"|(?:\b(?:arrest|warrant|contraband|drugs|illegal parcel|investigation|case registered|digital arrest|disconnect your number|criminal case)\b.{0,100})"
        r"\b(?:cbi|police|customs|fedex|trai|enforcement directorate|ed officer|court|aadhaar|parcel)\b)"
        r".{0,100}\b(?:video call|whatsapp|skype|stay on (?:the )?(?:call|line|video)|do not disconnect|transfer|pay|rbi account|verification account|immediately|secret|arrest warrant)\b"
        r"|\bdigital arrest\b.{0,80}\b(?:video call|whatsapp|skype|transfer|pay|rbi account|stay on (?:the )?(?:call|line|video))\b",
        "A claimed authority or law-enforcement case is paired with coercion, remote interrogation, or a payment demand.",
    ),
    _rule(
        "FAKE_JOB_TASK_SCAM", "Prepaid Task / Job Deposit Scheme", "Suspicious Job Offer", "high", 36,
        r"(?:(?:\b(?:telegram|whatsapp|task|rating|like videos|part[ -]?time job|commission|earnings)\b.{0,70})"
        r"(?:\b(?:prepaid|deposit|recharge|unlock|merchant task|vip task|crypto task|pay first)\b)"
        r"|(?:\b(?:prepaid|deposit|recharge|unlock|merchant task|vip task|crypto task|pay first)\b.{0,70})"
        r"\b(?:telegram|whatsapp|task|rating|like videos|part[ -]?time job|commission|earnings)\b)"
        r"|\b(?:deposit|recharge|pay)\b.{0,40}\b(?:unlock|release)\b.{0,35}\b(?:commission|earnings|salary|task)\b",
        "The job or task offer requires a deposit or prepaid task before earnings can be released.",
    ),
    _rule(
        "SUSPICIOUS_REMOTE_ACCESS", "Remote Access App / APK Prompt", "Malware & Remote Access Fraud", "critical", 44,
        r"\b(?:download|install|open|allow)\b.{0,40}\b(?:anydesk|teamviewer|quicksupport|remote access|screen.?share|\.apk)\b"
        r"|\b(?:anydesk|teamviewer|quicksupport|remote access|screen.?share|\.apk)\b.{0,40}\b(?:bank|otp|support|refund|account|install|download)\b",
        "A message asks the recipient to install remote-access software or an app package.",
    ),
    _rule(
        "LOTTERY_PRIZE_SCAM", "Prize Claim Fee", "Prize & Lottery Scam", "high", 34,
        r"\b(?:won|winner|lottery|lucky draw|kbc|prize|reward)\b.{0,65}\b(?:processing fee|pay|payment|tax|charge|deposit)\b"
        r"|\b(?:processing fee|pay|payment|tax|charge|deposit)\b.{0,65}\b(?:won|winner|lottery|lucky draw|kbc|prize|reward)\b",
        "An unexpected prize or reward requires an upfront fee or payment.",
    ),
]


_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
_CONFUSABLES = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "у": "y", "к": "k", "м": "m", "т": "t", "в": "b"})
_LANGUAGE_TERMS = {
    "यूपीआई": "upi", "ओटीपी": "otp", "एक बार का पासवर्ड": "one time password", "पिन": "pin",
    "खाता": "account", "बैंक": "bank", "केवाईसी": "kyc", "खाता बंद": "account blocked",
    "बंद हो जाएगा": "blocked", "तुरंत": "immediately", "आज": "today", "अभी": "now",
    "पैसे": "paise", "पैसा": "paisa", "रुपये": "rupees", "प्राप्त": "receive", "मिलने": "receive",
    "वापसी": "refund", "रिफंड": "refund", "कैशबैक": "cashback", "इनाम": "reward", "जमा": "deposit",
    "भेजो": "send", "बताओ": "tell", "दर्ज करें": "enter", "स्कैन": "scan", "क्यूआर": "qr",
    "अनुमोदित": "approve", "अनुरोध": "request", "गिरफ्तार": "arrest", "गिरफ्तारी": "arrest",
    "पुलिस": "police", "सीबीआई": "cbi", "पार्सल": "parcel", "डिजिटल गिरफ्तारी": "digital arrest",
    "निवेश": "deposit", "कार्य": "task", "कमाई": "earnings", "भुगतान": "payment",
    "न करें": "do not", "मत": "do not", "नहीं": "not", "कभी": "never", "कभी भी": "never",
    # Romanized Hindi/Hinglish. These are language normalization hints, not
    # standalone risk triggers; contextual rules still require paired evidence.
    "aapka": "your", "aapke": "your", "khata": "account", "khate": "account",
    "band ho jayega": "blocked", "band ho jaega": "blocked", "band ho jayegi": "blocked",
    "turant": "immediately", "abhi": "now", "bhejo": "send", "bhej": "send",
    "batao": "tell", "paise": "money", "paisa": "money", "inaam": "reward",
    "jeeta": "won", "jeete": "won", "jama": "deposit", "daalo": "enter",
    "dalo": "enter", "karo": "do", "karna": "do", "nahi": "not", "mat": "do not",
    "aaj": "today", "liye": "for", "vapas": "refund", "wapas": "refund",
    # Bengali and Assamese (shared Unicode block; language identification can be ambiguous).
    "আপনার": "your", "আপোনাৰ": "your", "তোমার": "your", "ব্যাংক": "bank", "বেংক": "bank",
    "অ্যাকাউন্ট": "account", "একাউন্ট": "account", "একাউণ্ট": "account", "খাতা": "account", "বন্ধ": "blocked",
    "হবে": "will", "হয়েছে": "blocked", "হ'ব": "will", "হব": "will", "এখনই": "immediately", "এতিয়াই": "immediately", "তৎক্ষণাৎ": "immediately",
    "কেওয়াইসি": "kyc", "আপডেট": "update", "ওটিপি": "otp", "পিন": "pin",
    "টাকা": "money", "পাঠান": "send", "শেয়ার": "share", "ফেরত": "refund",
    "পুরস্কার": "reward", "জিতেছেন": "won", "জমা": "deposit", "ক্লিক": "click",
    "লিংক": "link", "অভিনন্দন": "congratulations", "কৰক": "do",
    # Marathi (shares Devanagari with Hindi).
    "तुमचे": "your", "तुमचा": "your", "खाते": "account", "बँक": "bank", "बंद": "blocked",
    "होईल": "blocked", "त्वरित": "immediately", "लगेच": "immediately", "अद्ययावत": "update",
    "करा": "do", "पाठवा": "send",
    "बक्षीस": "reward", "परतावा": "refund", "पैसे": "money",
    # Gujarati.
    "તમારું": "your", "તમારો": "your", "બેંક": "bank", "ખાતું": "account",
    "બંધ": "blocked", "થશે": "will", "તરત": "immediately", "હમણાં": "now",
    "અપડેટ": "update", "ઓટીપી": "otp", "પિન": "pin", "પૈસા": "money",
    "મોકલો": "send", "ઇનામ": "reward", "પરત": "refund", "જમા": "deposit",
    # Punjabi in Gurmukhi; Shahmukhi overlaps with Urdu and is conservatively ambiguous.
    "ਤੁਹਾਡਾ": "your", "ਤੁਹਾਡੀ": "your", "ਬੈਂਕ": "bank", "ਖਾਤਾ": "account",
    "ਬੰਦ": "blocked", "ਹੋ": "will", "ਜਾਵੇਗਾ": "blocked", "ਤੁਰੰਤ": "immediately",
    "ਅੱਪਡੇਟ": "update", "ਓਟੀਪੀ": "otp", "ਪਿਨ": "pin", "ਪੈਸੇ": "money",
    "ਭੇਜੋ": "send", "ਇਨਾਮ": "reward", "ਜਮ੍ਹਾਂ": "deposit",
    # Urdu / Punjabi Shahmukhi.
    "آپ کا": "your", "آپ کی": "your", "بینک": "bank", "اکاؤنٹ": "account",
    "کھاتہ": "account", "بند": "blocked", "ہو جائے گا": "blocked", "فوراً": "immediately",
    "ابھی": "now", "اپ ڈیٹ": "update", "او ٹی پی": "otp", "پن": "pin",
    "رقم": "money", "پیسے": "money", "بھیجیں": "send", "انعام": "reward",
    "واپس": "refund", "جمع": "deposit", "لنک": "link", "کلک": "click",
    # Telugu.
    "మీ": "your", "బ్యాంక్": "bank", "ఖాతా": "account", "నిలిపివేయబడుతుంది": "blocked",
    "మూసివేయబడుతుంది": "blocked", "వెంటనే": "immediately", "తక్షణమే": "immediately",
    "నవీకరించండి": "update", "కెవైసి": "kyc", "ఓటిపి": "otp", "పిన్": "pin",
    "డబ్బు": "money", "పంపండి": "send", "బహుమతి": "reward", "వాపసు": "refund",
    # Tamil.
    "உங்கள்": "your", "வங்கி": "bank", "கணக்கு": "account", "முடக்கப்படும்": "blocked",
    "மூடப்படும்": "blocked", "உடனே": "immediately", "உடனடியாக": "immediately",
    "புதுப்பிக்கவும்": "update", "கேஒய்சி": "kyc", "ஓடிபி": "otp", "பின்": "pin",
    "பணம்": "money", "அனுப்பவும்": "send", "பரிசு": "reward", "திரும்ப": "refund",
    # Kannada.
    "ನಿಮ್ಮ": "your", "ಬ್ಯಾಂಕ್": "bank", "ಖಾತೆ": "account", "ಮುಚ್ಚಲಾಗುತ್ತದೆ": "blocked",
    "ತಕ್ಷಣ": "immediately", "ನವೀಕರಿಸಿ": "update", "ಕೆವೈಸಿ": "kyc", "ಒಟಿಪಿ": "otp",
    "ಪಿನ್": "pin", "ಹಣ": "money", "ಕಳುಹಿಸಿ": "send", "ಬಹುಮಾನ": "reward",
    # Malayalam.
    "നിങ്ങളുടെ": "your", "ബാങ്ക്": "bank", "അക്കൗണ്ട്": "account", "അടയ്ക്കും": "blocked",
    "ബ്ലോക്ക്": "blocked", "ഉടൻ": "immediately", "പുതുക്കുക": "update", "കെവൈസി": "kyc",
    "ഒടിപി": "otp", "പിൻ": "pin", "പണം": "money", "അയയ്ക്കുക": "send",
    "സമ്മാനം": "reward", "റീഫണ്ട്": "refund",
    # Odia.
    "ଆପଣଙ୍କ": "your", "ବ୍ୟାଙ୍କ": "bank", "ଖାତା": "account", "ବନ୍ଦ": "blocked",
    "ହେବ": "will", "ତୁରନ୍ତ": "immediately", "ଅପଡେଟ": "update", "କେୱାଇସି": "kyc",
    "ଓଟିପି": "otp", "ପିନ": "pin", "ଟଙ୍କା": "money", "ପଠାନ୍ତୁ": "send",
    "ପୁରସ୍କାର": "reward", "ଫେରସ୍ତ": "refund",
}


def normalize_text(text: str) -> str:
    """Normalize Unicode and common obfuscations for rule matching only."""
    normalized = unicodedata.normalize("NFKC", text).translate(_CONFUSABLES).casefold()
    normalized = _ZERO_WIDTH.sub("", normalized)
    for source, target in sorted(_LANGUAGE_TERMS.items(), key=lambda item: len(item[0]), reverse=True):
        normalized = normalized.replace(source, target)
    normalized = re.sub(r"\bo\s*[._-]?\s*t\s*[._-]?\s*p\b", "otp", normalized)
    normalized = re.sub(r"\bu\s*p\s*i\b", "upi", normalized)
    normalized = re.sub(r"\bp\s*i\s*n\b", "pin", normalized)
    normalized = normalized.replace("0tp", "otp").replace("up1", "upi").replace("p1n", "pin")
    return normalized


def _normalize_text_with_offsets(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Return normalized detection text and source spans for evidence display."""
    chars: list[str] = []
    offsets: list[tuple[int, int]] = []
    for source_index, source_char in enumerate(text):
        normalized_char = unicodedata.normalize("NFKC", source_char).translate(_CONFUSABLES).casefold()
        for char in normalized_char:
            if not _ZERO_WIDTH.fullmatch(char):
                chars.append(char)
                offsets.append((source_index, source_index + 1))

    value = "".join(chars)

    def replace_with_spans(pattern: re.Pattern[str], replacement: str):
        nonlocal value, offsets
        parts: list[str] = []
        new_offsets: list[tuple[int, int]] = []
        cursor = 0
        for match in pattern.finditer(value):
            parts.append(value[cursor:match.start()])
            new_offsets.extend(offsets[cursor:match.start()])
            if match.start() < match.end():
                source_start = min(span[0] for span in offsets[match.start():match.end()])
                source_end = max(span[1] for span in offsets[match.start():match.end()])
            else:
                source_start = source_end = 0
            parts.append(replacement)
            new_offsets.extend([(source_start, source_end)] * len(replacement))
            cursor = match.end()
        parts.append(value[cursor:])
        new_offsets.extend(offsets[cursor:])
        value, offsets = "".join(parts), new_offsets

    for source, replacement in sorted(_LANGUAGE_TERMS.items(), key=lambda item: len(item[0]), reverse=True):
        replace_with_spans(re.compile(re.escape(source)), replacement)
    for pattern, replacement in (
        (re.compile(r"\bo\s*[._-]?\s*t\s*[._-]?\s*p\b"), "otp"),
        (re.compile(r"\bu\s*p\s*i\b"), "upi"),
        (re.compile(r"\bp\s*i\s*n\b"), "pin"),
        (re.compile(r"\b0tp\b"), "otp"),
        (re.compile(r"\bup1\b"), "upi"),
        (re.compile(r"\bp1n\b"), "pin"),
    ):
        replace_with_spans(pattern, replacement)
    return value, offsets


_NEGATED_REQUEST = re.compile(r"\b(?:never|don't|do not|dont|shouldn't|should not|cannot|can't|avoid|not)\b", re.IGNORECASE)
_ADVISORY_CONTEXT = re.compile(
    r"\b(?:never share|do not share|don't share|banks? (?:will )?never ask|never enter|do not enter|"
    r"a pin is (?:only )?used to|otp is (?:private|confidential)|beware of|watch out for|"
    r"report (?:this|the|a) scam|how to spot)\b",
    re.IGNORECASE,
)


def _is_negated_match(text: str, match: re.Match[str]) -> bool:
    # Restrict negation to the sentence containing this match. An educational
    # sentence must not cancel a separate live request in a later sentence.
    left = max((text.rfind(mark, 0, match.start()) for mark in ".!?;\n"), default=-1) + 1
    right_candidates = [text.find(mark, match.end()) for mark in ".!?;\n"]
    right_candidates = [index for index in right_candidates if index >= 0]
    right = min(right_candidates) if right_candidates else len(text)
    clause = text[left:right]
    credential = re.search(r"\b(?:otp|pin|cvv|one[ -]?time password)\b", clause)
    if not credential:
        return False
    action = re.search(r"\b(?:share|send|tell|provide|reveal|forward|reply|enter|approve|accept|scan)\b", clause)
    if action:
        around_action = clause[max(0, action.start() - 28):min(len(clause), action.end() + 24)]
        if _NEGATED_REQUEST.search(around_action):
            return True
    around_credential = clause[max(0, credential.start() - 22):min(len(clause), credential.end() + 30)]
    return bool(_NEGATED_REQUEST.search(around_credential))


def _matches_rule(rule: Rule, text: str) -> re.Match[str] | None:
    for match in rule.pattern.finditer(text):
        # A direct warning that tells a reader not to disclose credentials is
        # benign context; the ML estimate remains a separate signal.
        if rule.id in ("OTP_CREDENTIAL_THEFT", "UPI_PIN_REQUEST") and _is_negated_match(text, match):
            continue
        # Avoid classifying educational discussion of coercive scams as a live threat.
        if rule.id in ("IMPERSONATION_DIGITAL_ARREST", "KYC_ACCOUNT_BLOCK") and _ADVISORY_CONTEXT.search(text) and not re.search(
            r"\b(?:you are|you have been|stay on|join|transfer|pay|send|remain on|do not disconnect|update your|click|enter|share)\b", text
        ):
            continue
        return match
    return None


_URL_IN_TEXT = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']{3,2048}")
_PII_PATTERNS = [
    (re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b"), "[REDACTED_ID]"),
    (re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b", re.IGNORECASE), "[REDACTED_PAN]"),
    (re.compile(r"\b(?:\+91[ -]?)?[6-9]\d{9}\b"), "[REDACTED_PHONE]"),
    (re.compile(r"\b\d{4,6}\b"), "[REDACTED_CODE]"),
]


def redact(text: str, max_len: int = 120) -> str:
    output = text.strip()
    for pattern, replacement in _PII_PATTERNS:
        output = pattern.sub(replacement, output)
    return output[:max_len] + ("..." if len(output) > max_len else "")


def _ml_assessment(text: str, language: str, language_method: str) -> MLAssessment:
    language_fields = {"detected_language": language, "language_identification": language_method}
    # The checked-in TF-IDF model has only English plus a few Romanized Hindi
    # fixture rows. Do not apply its probability to native-script inputs.
    if language not in ("en", "hinglish") or language_method == "user_hint":
        return MLAssessment(
            status="rules_only", predicted_label="unknown", calibrated_probability=None,
            top_features=[], model_version=None,
            note="The development classifier is not validated for this language or mixed-script input; contextual rules ran, and no language-based safety verdict is inferred.",
            **language_fields,
        )
    if MODEL is None:
        return MLAssessment(status="untrained", predicted_label="unknown", calibrated_probability=None, top_features=[], model_version=None, note="No usable classifier artifact was found; the transparent rule checks were used.", **language_fields)
    try:
        probabilities = MODEL.predict_proba([text])[0]
        classes = [str(label) for label in MODEL.classes_]
        if "scam" not in classes:
            return MLAssessment(status="unavailable", predicted_label="unknown", calibrated_probability=None, top_features=[], model_version=None, note="The classifier artifact does not contain a scam class; rule checks were used.", **language_fields)
        probability = float(probabilities[classes.index("scam")])
        return MLAssessment(
            status=str(MODEL_METADATA.get("status", "trained_demo")), predicted_label="scam" if probability >= getattr(MODEL, "scam_threshold", MODEL_METADATA.get("risk_threshold", .5)) else "benign",
            calibrated_probability=round(probability, 4), top_features=[], model_version=str(MODEL_METADATA.get("model_version", "1.0.0")),
            note="Uncalibrated classifier estimate from the small development fixture; not evidence of real-world accuracy.",
            **language_fields,
        )
    except Exception as exc:
        logger.warning("model_inference_unavailable type=%s", type(exc).__name__)
        return MLAssessment(status="unavailable", predicted_label="unknown", calibrated_probability=None, top_features=[], model_version=None, note="Classifier inference failed; transparent rule checks were used.", **language_fields)


def analyze_text(text: str, language_hint: str | None = None):
    normalized, source_offsets = _normalize_text_with_offsets(text)
    indicators: list[RuleIndicator] = []
    spans: list[str] = []
    categories: list[str] = []
    for rule in RULES:
        match = _matches_rule(rule, normalized)
        if match:
            if match.start() < len(source_offsets) and match.end() > 0:
                source_start = source_offsets[match.start()][0]
                source_end = source_offsets[match.end() - 1][1]
                evidence = text[source_start:source_end].strip()
            else:
                evidence = ""
            evidence = evidence or match.group(0)
            evidence = evidence[:100]
            indicators.append(RuleIndicator(id=rule.id, name=rule.name, severity=rule.severity, description=rule.description, matched_text=evidence, weight=float(rule.weight)))
            spans.append(evidence)
            categories.append(rule.category)

    links = _URL_IN_TEXT.findall(text)
    for raw_url in links[:3]:
        # Message-embedded URLs are not fetched here. The user can submit a URL
        # separately for safe parsing and optional reputation lookup.
        indicators.append(RuleIndicator(id="EMBEDDED_LINK", name="Embedded External Link in Message", severity="low", description="The link destination has not been verified. Check it separately before opening.", matched_text=raw_url[:100], weight=5.0))
        spans.append(raw_url[:100])

    # A link paired with credential or account-action language is stronger than
    # a bare URL, while a benign message that merely contains a link stays weak.
    if links and re.search(r"\b(?:login|sign[ -]?in|verify|update|suspend|blocked|claim|refund|otp|password|kyc)\b", normalized) and re.search(
        r"\b(?:click|open|visit|update|verify|sign[ -]?in|login|enter|share|send)\b", normalized
    ):
        evidence = links[0][:100]
        if not any(item.id == "KYC_ACCOUNT_BLOCK" for item in indicators):
            indicators.append(RuleIndicator(id="LINK_WITH_ACCOUNT_ACTION", name="Link Paired with Account or Credential Action", severity="high", description="An external link is paired with an account, login, identity, or credential action. Verify the destination independently.", matched_text=evidence, weight=32.0))
            spans.append(evidence)
            categories.append("Phishing & Credential Theft")

    detected_language, _, language_method = detect_language(text, language_hint)
    ml = _ml_assessment(text, detected_language, language_method)
    category = categories[0] if categories else ("Unverified Link / Message" if links else "No Specific Threat Pattern")
    return indicators, spans, category, ml


_LEGACY_NUMERIC_HOST = re.compile(r"^(?:0[xX][0-9a-fA-F]+|[0-9]+)(?:\.(?:0[xX][0-9a-fA-F]+|[0-9]+))*$")
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home", ".home.arpa")


def _canonical_host(raw_host: str) -> tuple[str, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
    host = unicodedata.normalize("NFKC", raw_host).translate(str.maketrans({"。": ".", "．": ".", "｡": "."})).casefold().rstrip(".")
    if not host or "%" in host:
        raise ValueError("The URL hostname is malformed.")
    try:
        address = ipaddress.ip_address(host)
        return str(address), address
    except ValueError:
        pass

    # Browsers accept legacy decimal/octal/hex IPv4 forms. Canonicalize these
    # before private-address checks so 2130706433 cannot disguise 127.0.0.1.
    if _LEGACY_NUMERIC_HOST.fullmatch(host):
        try:
            address = ipaddress.IPv4Address(socket.inet_aton(host))
            return str(address), address
        except (OSError, ValueError, struct.error):
            raise ValueError("Ambiguous numeric URL hosts are blocked for safety.")

    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("The internationalized URL hostname is invalid.") from exc
    if len(ascii_host) > 253 or any(not label or len(label) > 63 for label in ascii_host.split(".")):
        raise ValueError("The URL hostname is malformed.")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in ascii_host.split(".")):
        raise ValueError("The URL hostname contains invalid characters.")
    return ascii_host, None


def normalize_url(raw: str):
    value = raw.strip()
    if not value or any(ord(character) < 32 or character.isspace() for character in value) or "\\" in value:
        raise ValueError("The URL contains whitespace or ambiguous characters.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "http://" + value
    try:
        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        raw_host = parsed.hostname or ""
        port = parsed.port
    except ValueError as exc:
        raise ValueError("The URL is malformed.") from exc
    if scheme not in ("http", "https") or not raw_host:
        raise ValueError("Only valid HTTP or HTTPS URLs are supported.")

    host, address = _canonical_host(raw_host)
    if address is not None:
        if not address.is_global:
            raise ValueError("Private, loopback, link-local, and reserved IP addresses are blocked.")
    elif host == "localhost" or host.endswith(_BLOCKED_SUFFIXES):
        raise ValueError("Local and internal hostnames are blocked for safety.")

    # The app never connects to the submitted hostname. It only parses it and,
    # when configured, sends the URL string to the fixed Safe Browsing endpoint.
    # Avoid DNS resolution entirely: this makes DNS rebinding irrelevant here.
    authority_host = f"[{host}]" if isinstance(address, ipaddress.IPv6Address) else host
    authority = authority_host + (f":{port}" if port is not None else "")
    normalized = urlunparse((scheme, authority, parsed.path or "/", parsed.params, parsed.query, ""))
    return normalized, host


_OFFICIAL_DOMAINS = {
    "sbi": ("onlinesbi.sbi", "sbi.co.in"),
    "hdfc": ("hdfcbank.com",),
    "icici": ("icicibank.com",),
    "axis": ("axisbank.com",),
    "paytm": ("paytm.com",),
    "phonepe": ("phonepe.com",),
    "gpay": ("google.com",),
    "npci": ("npci.org.in",),
    "epfo": ("epfindia.gov.in",),
    "indiapost": ("indiapost.gov.in",),
    "irctc": ("irctc.co.in",),
}
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at", "goo.gl"}
_RISKY_TLDS = {"xyz", "top", "buzz", "click", "loan", "work", "gq", "tk", "ml", "cf"}


def _add_url_indicator(indicators: list[RuleIndicator], identifier: str, name: str, severity: str, description: str, evidence: str, weight: int):
    indicators.append(RuleIndicator(id=identifier, name=name, severity=severity, description=description, matched_text=evidence[:120], weight=float(weight)))


def _is_official_brand_host(host: str, brand: str) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in _OFFICIAL_DOMAINS[brand])


def analyze_url(raw: str):
    raw_value = raw.strip()
    source_url = raw_value if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_value) else "http://" + raw_value
    try:
        original_parsed = urlparse(source_url)
    except ValueError as exc:
        raise ValueError("The URL is malformed.") from exc
    normalized, host = normalize_url(raw)
    parsed = urlparse(normalized)
    indicators: list[RuleIndicator] = []

    try:
        address = ipaddress.ip_address(host)
        _add_url_indicator(indicators, "URL_RAW_IP_HOST", "Raw IP Address Hostname", "high", "Numeric IP hosts can obscure the identity of the site operator.", host, 36)
        if not address.is_global:
            raise ValueError("Private, loopback, link-local, and reserved IP addresses are blocked.")
    except ValueError as exc:
        # The normalized host is a valid domain when address parsing fails.
        if "blocked" in str(exc):
            raise

    raw_host = original_parsed.hostname or ""
    try:
        ascii_raw_host = unicodedata.normalize("NFKC", raw_host).encode("idna").decode("ascii").lower()
    except UnicodeError:
        ascii_raw_host = host
    if any(label.startswith("xn--") for label in ascii_raw_host.split(".")):
        _add_url_indicator(indicators, "URL_PUNYCODE_IDN", "Internationalized Punycode Domain", "medium", "The hostname uses an internationalized label. Check the displayed domain carefully; this alone does not prove maliciousness.", host, 30)

    if original_parsed.username is not None or original_parsed.password is not None:
        _add_url_indicator(indicators, "URL_USERINFO", "Username or Password Before Hostname", "high", "Text before @ in a URL can make a different destination look trusted.", original_parsed.netloc.split("@", 1)[0] + "@…", 38)
    if host in _SHORTENERS:
        _add_url_indicator(indicators, "URL_SHORTENER", "Obfuscated Link Shortener", "medium", "A shortened URL hides the final destination, which was not followed or verified here.", host, 26)
    if host.rsplit(".", 1)[-1] in _RISKY_TLDS:
        _add_url_indicator(indicators, "URL_HIGH_RISK_TLD", "Higher-Abuse Top-Level Domain", "low", "This top-level domain is sometimes used for disposable sites; this signal alone is weak and does not prove maliciousness.", host, 10)

    labels = host.split(".")
    if len(labels) >= 5:
        _add_url_indicator(indicators, "URL_DEEP_SUBDOMAINS", "Unusually Deep Subdomain", "medium", "Nested hostnames can place a trusted-looking label in front of a different registered domain.", host, 22)

    brand_aliases = {"sbi": ("sbi", "onlinesbi", "sb1", "onlinesb1"), "hdfc": ("hdfc",), "icici": ("icici",), "axis": ("axis",), "paytm": ("paytm",), "phonepe": ("phonepe",), "gpay": ("gpay", "googlepay"), "npci": ("npci",), "epfo": ("epfo",), "indiapost": ("indiapost",), "irctc": ("irctc",)}
    if not any(_is_official_brand_host(host, brand) for brand in _OFFICIAL_DOMAINS):
        for brand, aliases in brand_aliases.items():
            matching_label = next((label for label in labels[:-1] if any(alias in label for alias in aliases)), None)
            # A brand name in the path is deliberately ignored: it is not the host.
            if matching_label:
                _add_url_indicator(indicators, "URL_BRAND_IMPERSONATION", f"Potential Brand Lookalike ({brand.upper()})", "critical", "A financial or public-service brand appears in a hostname that is not one of its known official domains.", host, 48)
                break

    if parsed.scheme == "http":
        _add_url_indicator(indicators, "URL_UNENCRYPTED_HTTP", "Unencrypted HTTP Protocol", "low", "HTTP does not encrypt the connection. HTTPS alone would not prove that a site is safe.", "http://", 8)
    if len(normalized) > 140:
        _add_url_indicator(indicators, "URL_EXCESSIVE_LENGTH", "Unusually Long URL", "low", "Long addresses can obscure paths and parameters; inspect the destination carefully.", f"Length: {len(normalized)} characters", 8)
    if re.search(r"%(?:25){2,}|%(?:0d|0a|00)", normalized, re.IGNORECASE):
        _add_url_indicator(indicators, "URL_OBFUSCATED_ENCODING", "Obfuscated URL Encoding", "medium", "Repeatedly encoded or control-character URL components can make the destination difficult to inspect.", "Encoded URL component", 24)

    category = "Phishing / Deceptive URL" if indicators else "Unverified External URL"
    return normalized, indicators, category


def assessment_basis(indicators, threat=None):
    if threat and threat.verdict == "malicious":
        return "external_threat_match"
    if any(indicator.severity in ("critical", "high") for indicator in indicators):
        return "suspicious_pattern"
    if indicators:
        return "warning_signals"
    return "insufficient_evidence"


def score(indicators, ml, threat=None, scan_type="message"):
    """Sum explicit evidence weights; never blend the uncalibrated dev classifier.

    Bands are policy thresholds over the rule weights (low <22, medium 22–31,
    high 32–39, critical >=40). A provider-confirmed malicious match contributes
    40 declared evidence points. Scores are evidence scores, not probabilities.
    """
    # Each rule is emitted at most once by the analyzer. Keeping this a plain,
    # inspectable sum avoids severity-based score floors that inflate results.
    rule_score = min(100, sum(indicator.weight for indicator in indicators))
    total = round(rule_score, 1)
    if threat and threat.verdict == "malicious":
        # A provider-confirmed malicious match contributes a declared 40-point
        # evidence weight, the critical-band threshold, rather than a probability.
        total = min(100, total + 40)

    level = "Critical" if total >= 40 else "High" if total >= 32 else "Medium" if total >= 22 else "Low"
    reasons: list[str] = []
    if threat and threat.verdict == "malicious":
        reasons.append("A configured external threat-intelligence provider reported a match; independently confirm before acting.")
    elif any(indicator.severity in ("critical", "high") for indicator in indicators):
        reasons.append(f"{len(indicators)} rule indicator(s) matched: " + ", ".join(indicator.name for indicator in indicators[:3]) + ".")
    elif indicators:
        reasons.append(f"{len(indicators)} lower-severity warning signal(s) matched; these do not establish that the sender or content is fraudulent.")
    if threat and threat.verdict == "unknown":
        reasons.append("URL reputation is unknown or unavailable; no clean reputation verdict is claimed.")
    if not indicators and not (threat and threat.verdict == "malicious"):
        reasons.append("Evidence is insufficient: no known warning pattern matched. This is not confirmation that the content is safe.")

    basis = assessment_basis(indicators, threat)
    basis_label = {
        "external_threat_match": "External threat feed match",
        "suspicious_pattern": "Suspicious pattern evidence",
        "warning_signals": "Limited warning signals",
        "insufficient_evidence": "Insufficient evidence",
    }[basis]
    summary = f"{basis_label} · {level} level of concern (evidence score: {total}/100; not a probability). " + " ".join(reasons)
    actions = ["Never share an OTP, UPI PIN, ATM PIN, or CVV.", "Verify the sender through an independently obtained official number or website."]
    if level in ("High", "Critical"):
        actions.insert(0, "Do not open links, install apps, approve payment requests, or transfer money until independently verified.")
    limits = "This is an advisory evidence score, not a probability or guarantee. It sums matched rule weights and adds 40 points for a provider-confirmed malicious match, capped at 100; the uncalibrated development classifier is excluded. Bands: low <22, medium 22–31, high 32–39, critical ≥40. A low score is not a verified-safe result. New scams may evade known rules, and legitimate content can trigger false positives."
    return total, level, summary, actions, limits


def threat_result(normalized_url=None):
    if not normalized_url:
        return ThreatIntelResult(provider="Google Safe Browsing (optional)", mode="not_queried", verdict="unknown", details="No URL reputation lookup was performed for this scan.")
    if not SAFE_BROWSING_API_KEY:
        return ThreatIntelResult(provider="Google Safe Browsing (optional)", mode="offline_fallback", verdict="unknown", details="Live reputation lookup is not configured. The URL remains unverified; heuristic checks were used.")

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "scamsathi", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": normalized_url}],
        },
    }
    try:
        response = httpx.post(endpoint, params={"key": SAFE_BROWSING_API_KEY}, json=payload, timeout=4.0, follow_redirects=False)
        response.raise_for_status()
        matches = response.json().get("matches", [])
        if matches:
            kind = matches[0].get("threatType", "unknown")
            return ThreatIntelResult(provider="Google Safe Browsing v4", mode="live_api", verdict="malicious", details=f"Provider reported a threat match ({kind}).")
        return ThreatIntelResult(provider="Google Safe Browsing v4", mode="live_api", verdict="unknown", details="No current match was reported. This is not a clean bill of health; the URL remains unverified.")
    except Exception as exc:
        logger.info("threat_lookup_unavailable type=%s", type(exc).__name__)
        return ThreatIntelResult(provider="Google Safe Browsing v4", mode="offline_fallback", verdict="unknown", details=f"Provider lookup unavailable ({type(exc).__name__}); no reputation verdict is claimed and heuristic checks were used.")

