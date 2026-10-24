"""Hosted Gemini integration with explicit rule-based safety guidance."""

import asyncio
import ipaddress
import json
import logging
import re
import time
from urllib.parse import urlparse

import httpx

from app.complaint_resources import COMPLAINT_RESOURCES, SAFE_FALLBACK
from app.config import (
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    GEMINI_API_KEY,
    GEMINI_MODEL,
    GEMINI_TIMEOUT_SECONDS,
)
from app.services.analyzer import redact
from app.services.language import detect_language

logger = logging.getLogger("scamsathi.assistant")
_EMAIL_OR_UPI = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9][A-Z0-9.-]*\b", re.IGNORECASE)
_LONG_ACCOUNT_NUMBER = re.compile(r"(?<!\d)\d(?:[ -]?\d){7,18}(?!\d)")
_SECRET_MENTION = re.compile(
    r"(?i)\b(?:upi\s*pin|atm\s*pin|pin|otp|one[ -]?time password|password|passcode|passphrase|cvv|cvc|security code|verification code|login code|recovery code)\b"
    r"|(?:यूपीआई|ओटीपी|पिन|पासवर्ड|सीवीवी)"
)
_SECRET_QUESTION = re.compile(
    r"(?i)(?:\?|\b(?:ask(?:s|ed|ing)? for|request(?:s|ed|ing)?|want(?:s|ed|ing)?|share|send|tell|give|enter|type|provide|"
    r"should i|can i|is it safe|is this normal|is this a scam|what if|someone wants|maang(?:e|ra|ri|te)?|mang(?:e|ra|ri|te)?)\b|"
    r"क्या|मांग रहा|मांग रही|मांगा|देना चाहिए|सुरक्षित है)"
)
_HINGLISH_HINT = re.compile(
    r"(?i)\b(?:bhai|kya|mere|mujhe|mujhse|account|khata|paise|paisa|aaye|aaya|aana|kat(?:e|a)?|"
    r"gaye|gye|gya|gayi|maine|nahi|nahin|karu|karun|rahe|rahi|raha|bol|wala|wale|hai|hain|h|kyun|kaise)\b"
)
_UNEXPECTED_CREDIT = re.compile(
    r"(?i)(?:\b(?:unknown|unfamiliar|unexpected|strange|someone|kisi|extra)\b.{0,45}\b(?:money|paise|paisa|credit|account|balance)\b|"
    r"\b(?:money|paise|paisa)\b.{0,45}\b(?:aaye|aaya|received|came|credited|account|unknown|kisi)\b|"
    r"\b(?:received money|money came|unknown credit|unexpected credit|unknown person)\b|"
    r"\b(?:bank account balance|account balance)\b.{0,35}\b(?:aana|come|normal)\b)"
)
_KYC_REQUEST = re.compile(r"(?i)\b(?:kyc|know your customer)\b.{0,55}\b(?:update|verify|link|message|call|bol|rahe|request|urgent)\b|\b(?:kyc update|update kyc)\b")
_UNAUTHORIZED_DEBIT = re.compile(
    r"(?i)(?:\b(?:paise|paisa|money|funds?)\b.{0,35}\b(?:kat(?:e|a)?(?:\s+(?:gaye|gye|gya|gayi))?|deduct(?:ed)?|debited|gone|nikal)\b|"
    r"\b(?:unauthori[sz]ed|unknown)\b.{0,35}\b(?:transaction|debit|payment)\b|"
    r"\b(?:transaction|payment)\b.{0,35}\b(?:did not|didn't|maine nahi|not me|unknown|nahi kiya)\b)"
)
_REPORTING_OR_LOSS = re.compile(r"(?i)\b(?:lost money|money lost|paise kho|cybercrime helpline|report(?:ing)? a (?:scam|fraud)|report.{0,35}(?:suspicious|scam|fraud|call|message|email)|(?:suspicious|scam|fraud).{0,35}report)\b")

SETUP_INSTRUCTIONS = [
    "Set GEMINI_API_KEY in the backend environment variables.",
    "Verify that the configured Gemini model is available to your API key.",
    "Restart or redeploy the backend after updating environment variables.",
]



def redact_chat(content: str, max_len: int = 12000) -> str:
    """Apply scanner redactions and also mask email/UPI-style identifiers."""
    output = redact(content, max_len=max_len)
    output = _EMAIL_OR_UPI.sub("[REDACTED_EMAIL_OR_UPI]", output)
    return _LONG_ACCOUNT_NUMBER.sub("[REDACTED_ACCOUNT_NUMBER]", output)


def _is_loopback_url(base_url: str) -> bool:
    try:
        parsed = urlparse(base_url)
        if parsed.scheme != "http" or not parsed.hostname:
            return False
        if parsed.hostname == "localhost":
            return True
        return ipaddress.ip_address(parsed.hostname).is_loopback
    except (ValueError, TypeError):
        return False



async def inspect_local_model() -> dict:
    """Check whether the configured Gemini model is reachable."""
    if not GEMINI_API_KEY or not GEMINI_MODEL:
        return {
            "runtime_available": False,
            "model_available": False,
            "model_loaded": False,
            "ready": False,
        }

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}"
    )
    headers = {"x-goog-api-key": GEMINI_API_KEY}

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(5.0, connect=3.0),
            follow_redirects=False,
        ) as client:
            response = await client.get(url, headers=headers)

        if response.is_success:
            return {
                "runtime_available": True,
                "model_available": True,
                "model_loaded": False,
                "ready": True,
            }

        logger.info("gemini_status_http status=%s", response.status_code)
        return {
            "runtime_available": True,
            "model_available": False,
            "model_loaded": False,
            "ready": False,
        }

    except (httpx.HTTPError, ValueError, TypeError) as exc:
        logger.info("gemini_status_unavailable type=%s", type(exc).__name__)
        return {
            "runtime_available": False,
            "model_available": False,
            "model_loaded": False,
            "ready": False,
        }

def status_payload(runtime: dict) -> dict:
    runtime_available = bool(runtime.get("runtime_available", False))
    model_available = bool(runtime.get("model_available", False))
    ready = bool(runtime.get("ready", False)) and runtime_available and model_available

    return {
        "runtime": "Gemini API (hosted)",
        "runtime_available": runtime_available,
        "model": GEMINI_MODEL,
        "model_available": model_available,
        "model_loaded": False,
        "ready": ready,
        "setup_instructions": (
            [] if ready else SETUP_INSTRUCTIONS
        ),
        "resources": COMPLAINT_RESOURCES,
    }

def curated_secret_guidance(message: str, language_hint: str | None = None) -> dict | None:
    """Return a transparent rule-based safety answer for secret-credential questions."""
    if not _SECRET_MENTION.search(message) or not _SECRET_QUESTION.search(message):
        return None
    language = _chat_language(message, language_hint)
    if language == "hi":
        text = (
            "अपना UPI PIN, ATM PIN, OTP, CVV, पासवर्ड या कोई अन्य गोपनीय प्रमाणीकरण जानकारी किसी को न बताएं और किसी लिंक या कॉल पर दर्ज न करें। "
            "UPI PIN पैसे भेजने की अनुमति देता है; पैसे प्राप्त करने के लिए PIN डालना या collect request मंज़ूर करना आवश्यक नहीं है। "
            "यह सवाल अकेले किसी खास भेजने वाले या संदेश को धोखाधड़ी साबित नहीं करता। यदि आपके पास संदेश है, तो उसका मूल पाठ अलग ‘संदेश की जाँच’ फ़ील्ड में दें।"
        )
    elif language == "hinglish":
        text = (
            "Apna UPI PIN, ATM PIN, OTP, CVV, password ya koi aur authentication secret kisi ko mat batayein aur kisi call/link par enter na karein. "
            "UPI PIN paise bhejne ko authorize karta hai; paise receive karne ke liye PIN dalna ya collect request approve karna zaroori nahi hota. "
            "Sirf is sawaal se kisi particular sender ya message ka scam hona prove nahi hota. Message check karna ho to original text alag ‘Message to analyse’ field mein paste karein."
        )
    else:
        text = (
            "Never tell anyone your UPI PIN, ATM PIN, OTP, CVV, password, or any other authentication secret, and do not enter it because of a call or message. "
            "A UPI PIN authorizes money to leave your account; you do not need to enter it or approve a collect request to receive money. "
            "This question alone does not establish that a particular sender or message is fraudulent. To review a message, paste only its original text into the separate scan-content field."
        )
    return {"title": "Protect private payment credentials", "text": text, "source": "curated_safety_rule"}


def _chat_language(message: str, language_hint: str | None = None) -> str:
    hinted = (language_hint or "auto").lower()
    if hinted not in ("", "auto", "und"):
        return hinted
    if re.search(r"[\u0900-\u097f]", message):
        # This script also covers Marathi. We avoid a stronger claim than needed
        # for these short safety replies and use simple Hindi phrasing.
        return "hi"
    detected, confidence, _style = detect_language(message)
    if detected == "hinglish" or _HINGLISH_HINT.search(message):
        return "hinglish"
    if detected in ("hi", "mr", "bn", "as", "te", "ta", "gu", "ur", "kn", "ml", "or", "pa") and confidence >= 0.65:
        return detected
    return "en"


def resolve_reply_language(message: str, language_hint: str | None = None) -> str:
    """Resolve the UI's auto setting to a useful language instruction for Gemini."""
    hinted = (language_hint or "auto").strip().lower()
    return _chat_language(message) if hinted in ("", "auto", "und") else hinted


def curated_fallback_guidance(message: str, language_hint: str | None = None) -> dict | None:
    """Return concise, transparent guidance only for intents supported by the text."""
    secret = curated_secret_guidance(message, language_hint)
    if secret:
        return secret

    language = _chat_language(message, language_hint)
    is_hinglish = language == "hinglish"
    is_hindi = language == "hi"

    if _UNEXPECTED_CREDIT.search(message) and not _UNAUTHORIZED_DEBIT.search(message):
        if is_hinglish:
            text = (
                "Salary, refund, ya pehchane hue transfer ka credit aana normal ho sakta hai. Agar paise ka source unknown hai, bank ke official app ya independently verified channel mein transaction check karein. Jab tak source clear na ho, "
                "paise spend ya forward na karein; kisi ke kehne par ‘return’ bhi na karein. OTP, UPI PIN ya password share na karein. "
                "Kya amount official app mein actual credit dikh raha hai, sirf SMS aaya hai, ya koi aapse paise wapas maang raha hai?"
            )
        elif is_hindi:
            text = (
                "बैंक के आधिकारिक ऐप या स्वतंत्र रूप से सत्यापित माध्यम में लेन-देन जाँचें। स्रोत स्पष्ट होने तक पैसे खर्च या आगे न भेजें, "
                "और किसी के कहने पर उन्हें वापस भी न करें। OTP, UPI PIN या पासवर्ड साझा न करें। क्या आधिकारिक ऐप में वास्तविक क्रेडिट दिख रहा है, "
                "केवल SMS आया है, या कोई आपसे पैसे लौटाने को कह रहा है?"
            )
        else:
            text = (
                "A credit from a salary, refund, or transfer you recognize can be normal. If the source is unfamiliar, check the transaction in your bank’s official app or through a channel you verify independently. Until the source is clear, "
                "do not spend or forward the money, including in response to a return request. Never share an OTP, UPI PIN, or password. "
                "Does the official app show an actual credit, did you only receive an SMS, or is someone asking you to send money back?"
            )
        return {"title": "Verify an unexpected credit", "text": text, "source": "curated_safety_rule"}

    if _KYC_REQUEST.search(message):
        if is_hinglish:
            text = (
                "KYC ki request ko independently verify karein: message ke link ya number se nahi, bank ke official app ya khud khole gaye official website se. "
                "OTP, UPI PIN, CVV ya password kisi ko na batayein. Sirf KYC ka zikr sender ko fraud prove nahi karta. "
                "Kya unhone aapko link bheja hai, ya OTP/PIN maanga hai?"
            )
        elif is_hindi:
            text = (
                "KYC अनुरोध को स्वतंत्र रूप से जाँचें: संदेश के लिंक या नंबर से नहीं, बल्कि बैंक के आधिकारिक ऐप या स्वयं खोली गई आधिकारिक वेबसाइट से। "
                "OTP, UPI PIN, CVV या पासवर्ड किसी को न बताएं। केवल KYC का उल्लेख किसी भेजने वाले को धोखेबाज़ साबित नहीं करता। "
                "क्या उन्होंने लिंक भेजा है या OTP/PIN माँगा है?"
            )
        else:
            text = (
                "Verify the KYC request independently through your bank’s official app or a website you open yourself. Do not use a link or number "
                "from the message, and never share an OTP, UPI PIN, CVV, or password. A KYC request alone does not prove the sender is fraudulent. "
                "Did they send you a link or ask for a code or PIN?"
            )
        return {"title": "Verify the KYC request", "text": text, "source": "curated_safety_rule"}

    if _UNAUTHORIZED_DEBIT.search(message):
        if is_hinglish:
            text = (
                "Bhai, agar account se paise kate hain aur transaction tumne nahi kiya, toh bank ke official app mein details check karo. "
                "Apne bank ko uske official app ya independently verified number se turant report karo, aur account/card ya UPI ko secure ya block karne ke options poochho. "
                "Agar online fraud ka shak ho, India ki cybercrime helpline 1930 par jaldi call karo; official portal https://cybercrime.gov.in/ hai. "
                "OTP, PIN ya password kisi ko mat dena. Paise kis type ke transaction mein kate—UPI, card, ATM ya bank transfer?"
            )
        elif is_hindi:
            text = (
                "यदि लेन-देन बैंक के आधिकारिक ऐप में दिख रहा है और आपने नहीं किया, तो तुरंत बैंक के आधिकारिक ऐप या स्वतंत्र रूप से सत्यापित माध्यम से "
                "संपर्क करें और लेन-देन रिपोर्ट तथा खाते/कार्ड को सुरक्षित करने के विकल्प पूछें। यदि साइबर धोखाधड़ी में पैसे गए हैं, तो जल्द 1930 पर कॉल करें "
                "और https://cybercrime.gov.in/ पर रिपोर्ट करें। OTP, PIN या पासवर्ड किसी को न दें। क्या डेबिट आधिकारिक ऐप में दिख रहा है या केवल SMS आया है?"
            )
        else:
            text = (
                "If the debit appears in your bank’s official app and you did not make it, contact the bank promptly through its official app or an "
                "independently verified channel to report it and ask how to secure the account or card. If money was lost to cyber fraud, call 1930 "
                "promptly and report at https://cybercrime.gov.in/. Do not share an OTP, PIN, or password. Does the debit appear in the official app, "
                "or did you only receive an SMS?"
            )
        return {"title": "Check an unrecognized debit", "text": text, "source": "curated_safety_rule"}

    if _REPORTING_OR_LOSS.search(message):
        text = (
            "If money was lost to cyber fraud, contact your bank through its official app or an independently verified channel and call India’s cybercrime "
            "helpline 1930 promptly. You can also report through https://cybercrime.gov.in/. Keep transaction references and original messages safely. "
            "This is general guidance; no complaint has been submitted."
        )
        if is_hinglish:
            text = (
                "Agar cyber fraud mein paise gaye hain, bank ke official app ya independently verified channel se contact karein aur India ki cybercrime "
                "helpline 1930 par jaldi call karein. https://cybercrime.gov.in/ par bhi report kar sakte hain. Transaction reference aur original messages "
                "securely sambhal kar rakhein. Yeh general guidance hai; complaint submit nahi hui hai."
            )
        elif is_hindi:
            text = (
                "यदि साइबर धोखाधड़ी में पैसे गए हैं, तो बैंक के आधिकारिक ऐप या स्वतंत्र रूप से सत्यापित माध्यम से संपर्क करें और भारत की साइबर अपराध "
                "हेल्पलाइन 1930 पर जल्द कॉल करें। https://cybercrime.gov.in/ पर भी रिपोर्ट कर सकते हैं। लेन-देन संदर्भ और मूल संदेश सुरक्षित रखें। "
                "यह सामान्य मार्गदर्शन है; कोई शिकायत जमा नहीं हुई है।"
            )
        return {"title": "Report an online fraud", "text": text, "source": "curated_safety_rule"}
    return None


def _system_prompt(language_hint: str | None) -> str:
    official = "\n".join(f"- {item['name']}: {item['url']}" for item in COMPLAINT_RESOURCES)
    resolved = language_hint or "en"
    language_instruction = {
        "hinglish": "Reply in natural conversational Hinglish using Latin/Roman letters. Do not switch into Devanagari unless the user explicitly asks.",
        "hi": "Reply in Hindi using Devanagari script.",
        "en": "Reply in clear, natural English.",
    }.get(resolved, f"Reply in the language identified by this explicit language selection: {resolved}.")
    return f"""You are VEDVIQ AI, a cyber-safety assistant. Answer in the user's language and conversational style where possible, including English, Hindi in Devanagari, Romanized Hindi, Hinglish, and major Indian languages. Understand common informal spellings and code-mixed sentences; do not treat language identification as intent detection. Keep answers concise, calm, and practical. A general question is advice, not suspicious sample content; analyze only content explicitly supplied for a separate scan. State uncertainty; an unknown URL is not safe by default. Never request OTPs, PINs, passwords, full account/card numbers, or unnecessary personal data. Ask only non-sensitive report facts (approximate time, channel, incident type, money lost). For suspected financial fraud, advise contacting the bank through a channel found independently and the official 1930 helpline / https://cybercrime.gov.in/. Separate official destinations from suggestions. Complaint/email text is only a draft; never say it was submitted. Use placeholders for unknown facts. Do not claim checks that were not performed or guarantee recovery. Keep the answer concise and finish complete sentences.
Language instruction: {language_instruction}
Resolved language hint: {resolved}
Official directory: {official}
Safe fallback: {SAFE_FALLBACK}"""


async def generate_local_reply(
    messages: list[dict],
    language_hint: str | None = None,
) -> tuple[str, dict]:
    if not GEMINI_API_KEY or not GEMINI_MODEL:
        raise RuntimeError("Gemini API key and model must be configured.")

    timeout = max(5.0, min(float(GEMINI_TIMEOUT_SECONDS), 90.0))
    prompt_started = time.perf_counter()

    system_parts = [_system_prompt(language_hint)]
    conversation = []

    for item in messages:
        role = item.get("role", "")
        content = item.get("content", "")
        if not isinstance(content, str) or not content.strip():
            continue

        if role == "system":
            system_parts.append(content)
        elif role in ("user", "assistant"):
            conversation.append({
                "role": "user" if role == "user" else "model",
                "parts": [{"text": content}],
            })

    if not conversation:
        raise ValueError("No valid conversation messages were provided.")

    payload = {
        "systemInstruction": {
            "parts": [{"text": "\n\n".join(system_parts)}]
        },
        "contents": conversation,
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 512,
        },
    }

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent"
    )
    headers = {
        "x-goog-api-key": GEMINI_API_KEY,
        "Content-Type": "application/json",
    }

    prompt_preparation_ms = round(
        (time.perf_counter() - prompt_started) * 1000, 2
    )
    started = time.perf_counter()

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=10.0),
        follow_redirects=False,
    ) as client:
        response = await client.post(
            url,
            headers=headers,
            json=payload,
        )
    if not response.is_success:
        error_body = response.text
        if GEMINI_API_KEY:
            error_body = error_body.replace(GEMINI_API_KEY, "[REDACTED]")
        error_body = " ".join(error_body.split())[:1500]
        logger.error(
            "gemini_api_error status=%s body=%s",
            response.status_code,
            error_body,
        )
        response.raise_for_status()

    result = response.json()
    if not isinstance(result, dict):
        raise ValueError("Gemini returned an invalid response body.")
    candidates = result.get("candidates") or []
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("Gemini returned no response candidates.")

    candidate = candidates[0]
    candidate_content = candidate.get("content") if isinstance(candidate, dict) else None
    parts = candidate_content.get("parts", []) if isinstance(candidate_content, dict) else []
    if not isinstance(parts, list):
        parts = []

    content = "".join(
        part.get("text", "")
        for part in parts
        if isinstance(part, dict) and isinstance(part.get("text"), str)
    ).strip()

    if not content:
        raise ValueError("Gemini returned an empty response.")

    usage = result.get("usageMetadata")
    usage = usage if isinstance(usage, dict) else {}
    timings = {
        "prompt_preparation_ms": prompt_preparation_ms,
        "request_wall_ms": round((time.perf_counter() - started) * 1000, 2),
        "time_to_first_text_ms": 0.0,
        "gemini_total_ms": round((time.perf_counter() - started) * 1000, 2),
        "prompt_tokens": usage.get("promptTokenCount"),
        "generated_tokens": usage.get("candidatesTokenCount"),
    }

    logger.info(
        "gemini_inference_timing model=%s timings=%s",
        GEMINI_MODEL,
        timings,
    )
    return content[:12000], timings
