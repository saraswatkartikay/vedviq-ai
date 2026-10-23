"""Local-only Ollama integration. It never downloads a model or fakes a reply."""

import asyncio
import ipaddress
import json
import logging
import re
import time
from urllib.parse import urlparse

import httpx

from app.complaint_resources import COMPLAINT_RESOURCES, SAFE_FALLBACK
from app.config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT_SECONDS
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
    "Install Ollama from https://ollama.com/download and start the Ollama service.",
    f"In a terminal, run: ollama pull {OLLAMA_MODEL}",
    "Restart the ScamSathi API. The assistant checks the configured local model and will show ready only when it is present.",
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
    """Return observed availability, with short timeouts and no model pull side effects."""
    started = time.perf_counter()
    if not _is_loopback_url(OLLAMA_BASE_URL) or not OLLAMA_MODEL:
        logger.info("ollama_status_timing model=%s available=false elapsed_ms=0", OLLAMA_MODEL)
        return {"runtime_available": False, "model_available": False, "ready": False}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(2.5, connect=1.0), follow_redirects=False) as client:
            # The tags check confirms installation; ps is an observation only
            # and may be unavailable on older Ollama versions.
            tags_response, ps_response = await asyncio.gather(
                client.get(f"{OLLAMA_BASE_URL}/api/tags"),
                client.get(f"{OLLAMA_BASE_URL}/api/ps"),
                return_exceptions=True,
            )
            if isinstance(tags_response, Exception):
                raise tags_response
            tags_response.raise_for_status()
            models = tags_response.json().get("models", [])

            def matches(item):
                name = str(item.get("name", ""))
                return name.split(":")[0] == OLLAMA_MODEL.split(":")[0] and name.split(":", 1)[-1] == OLLAMA_MODEL.split(":", 1)[-1]

            available = any(matches(item) for item in models)
            loaded = False
            if not isinstance(ps_response, Exception) and ps_response.is_success:
                loaded = any(matches(item) for item in ps_response.json().get("models", []))
            logger.info("ollama_status_timing model=%s runtime=true installed=%s loaded=%s elapsed_ms=%.2f", OLLAMA_MODEL, available, loaded, (time.perf_counter() - started) * 1000)
            return {"runtime_available": True, "model_available": available, "model_loaded": loaded, "ready": available}
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        logger.info("ollama_status_unavailable type=%s elapsed_ms=%.2f", type(exc).__name__, (time.perf_counter() - started) * 1000)
        return {"runtime_available": False, "model_available": False, "ready": False}


def status_payload(runtime: dict) -> dict:
    return {
        "runtime": "Ollama (local)",
        **runtime,
        "model": OLLAMA_MODEL,
        "setup_instructions": SETUP_INSTRUCTIONS,
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
    """Resolve the UI's auto setting to a useful language instruction for Ollama."""
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
    return f"""You are ScamSathi, a cyber-safety assistant. Answer in the user's language and conversational style where possible, including English, Hindi in Devanagari, Romanized Hindi, Hinglish, and major Indian languages. Understand common informal spellings and code-mixed sentences; do not treat language identification as intent detection. Keep answers concise, calm, and practical. A general question is advice, not suspicious sample content; analyze only content explicitly supplied for a separate scan. State uncertainty; an unknown URL is not safe by default. Never request OTPs, PINs, passwords, full account/card numbers, or unnecessary personal data. Ask only non-sensitive report facts (approximate time, channel, incident type, money lost). For suspected financial fraud, advise contacting the bank through a channel found independently and the official 1930 helpline / https://cybercrime.gov.in/. Separate official destinations from suggestions. Complaint/email text is only a draft; never say it was submitted. Use placeholders for unknown facts. Do not claim checks that were not performed or guarantee recovery. Keep the answer concise and finish complete sentences.
Language instruction: {language_instruction}
Resolved language hint: {resolved}
Official directory: {official}
Safe fallback: {SAFE_FALLBACK}"""


async def generate_local_reply(messages: list[dict], language_hint: str | None = None) -> tuple[str, dict]:
    if not _is_loopback_url(OLLAMA_BASE_URL):
        raise RuntimeError("Ollama must be configured on a local loopback address.")
    timeout = max(5.0, min(float(OLLAMA_TIMEOUT_SECONDS), 90.0))
    prompt_started = time.perf_counter()
    payload = {
        "model": OLLAMA_MODEL,
        "stream": True,
        "messages": [{"role": "system", "content": _system_prompt(language_hint)}, *messages],
        "keep_alive": "10m",
        "options": {"temperature": 0.2, "num_predict": 192, "num_ctx": 4096},
    }
    prompt_preparation_ms = round((time.perf_counter() - prompt_started) * 1000, 2)
    started = time.perf_counter()
    first_chunk_ms = None
    content_parts: list[str] = []
    result: dict = {}
    logger.info("ollama_prompt model=%s messages=%d chars=%d context_chars=%d stream=true", OLLAMA_MODEL, len(payload["messages"]), sum(len(item["content"]) for item in payload["messages"]), sum(len(item["content"]) for item in messages))
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=2.0), follow_redirects=False) as client:
        async with client.stream("POST", f"{OLLAMA_BASE_URL}/api/chat", json=payload) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError("Ollama returned malformed streaming data.") from exc
                piece = chunk.get("message", {}).get("content", "")
                if isinstance(piece, str) and piece:
                    if first_chunk_ms is None:
                        first_chunk_ms = round((time.perf_counter() - started) * 1000, 2)
                    content_parts.append(piece)
                if chunk.get("done"):
                    result = chunk
    content = "".join(content_parts).strip()
    if not content:
        raise ValueError("Ollama returned an empty response.")
    if result.get("done_reason") == "length":
        logger.warning("ollama_inference_incomplete model=%s reason=length generated_tokens=%s", OLLAMA_MODEL, result.get("eval_count"))
        raise ValueError("Ollama stopped at the response token limit; incomplete reply was not shown.")
    ns_to_ms = lambda value: round(float(value or 0) / 1_000_000, 2)
    timings = {
        "prompt_preparation_ms": prompt_preparation_ms,
        "request_wall_ms": round((time.perf_counter() - started) * 1000, 2),
        "time_to_first_text_chunk_ms": first_chunk_ms if first_chunk_ms is not None else 0.0,
        "ollama_total_ms": ns_to_ms(result.get("total_duration")),
        "model_load_ms": ns_to_ms(result.get("load_duration")),
        "prompt_eval_ms": ns_to_ms(result.get("prompt_eval_duration")),
        "generation_ms": ns_to_ms(result.get("eval_duration")),
        "prompt_tokens": result.get("prompt_eval_count"),
        "generated_tokens": result.get("eval_count"),
    }
    logger.info("ollama_inference_timing model=%s timings=%s", OLLAMA_MODEL, timings)
    return content[:12000], timings
