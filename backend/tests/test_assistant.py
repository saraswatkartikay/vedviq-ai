import pytest
import httpx
import asyncio
import re
from sqlalchemy import create_engine, inspect as sqlalchemy_inspect, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.complaint_resources import COMPLAINT_RESOURCES, VERIFIED_ON
from app.services import assistant as assistant_service


@pytest.mark.parametrize("resource_id", ["national-cybercrime-portal", "chakshu", "rbi-sachet"])
def test_official_reporting_resources_have_sources_and_https(resource_id):
    resource = next(item for item in COMPLAINT_RESOURCES if item["id"] == resource_id)
    assert resource["official"] is True
    assert resource["url"].startswith("https://")
    assert resource["source_urls"]
    assert resource["verified_on"] == VERIFIED_ON


def test_assistant_status_reflects_missing_hosted_model(client, monkeypatch):
    async def missing():
        return {"runtime_available": False, "model_available": False, "ready": False}

    monkeypatch.setattr(main, "inspect_local_model", missing)
    response = client.get("/api/v1/assistant/status")
    assert response.status_code == 200
    assert response.json()["ready"] is False
    assert response.json()["runtime_available"] is False
    assert response.json()["model_loaded"] is False
    assert response.json()["setup_instructions"]


@pytest.mark.parametrize(("status_code", "expected_model_available"), [(200, True), (403, False), (404, False)])
def test_gemini_status_probes_the_configured_model_without_exposing_the_key(monkeypatch, status_code, expected_model_available):
    secret = "test-gemini-secret"
    seen = {}
    monkeypatch.setattr(assistant_service, "GEMINI_API_KEY", secret)
    monkeypatch.setattr(assistant_service, "GEMINI_MODEL", "gemini-test-model")

    class Response:
        def __init__(self, code): self.status_code = code
        @property
        def is_success(self): return 200 <= self.status_code < 300

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def get(self, url, headers):
            seen.update(url=url, headers=headers)
            return Response(status_code)

    monkeypatch.setattr(assistant_service.httpx, "AsyncClient", lambda *args, **kwargs: FakeClient())
    runtime = asyncio.run(assistant_service.inspect_local_model())
    status = assistant_service.status_payload(runtime)
    assert seen["url"].endswith("/models/gemini-test-model")
    assert seen["headers"]["x-goog-api-key"] == secret
    assert runtime["runtime_available"] is True
    assert runtime["model_available"] is expected_model_available
    assert runtime["model_loaded"] is False
    assert runtime["ready"] is expected_model_available
    assert status["ready"] is expected_model_available
    assert status["model"] == "gemini-test-model"
    assert secret not in repr(status)


def test_status_payload_cannot_claim_ready_when_runtime_check_is_inconsistent(monkeypatch):
    monkeypatch.setattr(assistant_service, "GEMINI_MODEL", "gemini-test-model")
    status = assistant_service.status_payload({
        "runtime_available": True,
        "model_available": False,
        "ready": True,
    })
    assert status["ready"] is False
    assert status["setup_instructions"]


def test_gemini_status_skips_probe_when_api_key_is_missing(monkeypatch):
    monkeypatch.setattr(assistant_service, "GEMINI_API_KEY", "")
    monkeypatch.setattr(assistant_service, "GEMINI_MODEL", "gemini-test-model")
    monkeypatch.setattr(assistant_service.httpx, "AsyncClient", lambda *args, **kwargs: pytest.fail("No request should be made without an API key"))
    status = asyncio.run(assistant_service.inspect_local_model())
    assert status["ready"] is False
    assert status["runtime_available"] is False
    assert status["model_available"] is False


def test_chat_is_honest_when_hosted_model_is_unavailable(client, monkeypatch):
    async def unavailable(*args, **kwargs):
        raise httpx.ConnectError("Gemini API is unavailable")

    monkeypatch.setattr(main, "generate_local_reply", unavailable)
    response = client.post("/api/v1/assistant/chat", json={"message": "How does device fingerprinting identify a malicious login?"})
    assert response.status_code == 200
    body = response.json()
    assert body["assistant_status"] == "unavailable"
    assert body["assistant_reply"] is None
    assert body["setup_instructions"]
    assert "scanner;dur=" in response.headers["server-timing"]
    assert "model_inference;dur=" in response.headers["server-timing"]
    assert "total;dur=" in response.headers["server-timing"]


def test_explicit_chat_message_analysis_uses_existing_detector(client, monkeypatch):
    called = {}

    def fake_analyze(text, language_hint=None):
        called["text"] = text
        return [], [], "No Specific Threat Pattern", main.MLAssessment(
            status="untrained", predicted_label="unknown", calibrated_probability=None,
            top_features=[], model_version=None, note="test",
        )

    async def missing():
        return {"runtime_available": False, "model_available": False, "ready": False}

    monkeypatch.setattr(main, "analyze_text", fake_analyze)
    monkeypatch.setattr(main, "inspect_local_model", missing)
    response = client.post("/api/v1/assistant/chat", json={
        "message": "Could you review the message I received?",
        "analysis_type": "message",
        "content_to_analyze": "Share your OTP and enter UPI PIN to receive cashback",
    })
    assert response.status_code == 200
    assert called["text"] == "Share your OTP and enter UPI PIN to receive cashback"
    assert response.json()["analysis"]["scan_type"] == "message"
    assert response.json()["analysis_note"] == "Only the separate scan-content field was analyzed."
    assert client.get("/api/v1/history").json()[0]["scan_type"] == "message"


def test_explicit_chat_url_analysis_uses_existing_url_detector(client, monkeypatch):
    called = {}

    def fake_analyze(url):
        called["url"] = url
        return "https://example.test/", [], "Unverified Link / Message"

    async def missing():
        return {"runtime_available": False, "model_available": False, "ready": False}

    monkeypatch.setattr(main, "analyze_url", fake_analyze)
    monkeypatch.setattr(main, "inspect_local_model", missing)
    response = client.post("/api/v1/assistant/chat", json={
        "message": "Can you check this URL for me?",
        "analysis_type": "url",
        "content_to_analyze": "https://example.test/",
    })
    assert response.status_code == 200
    assert called["url"] == "https://example.test/"
    assert response.json()["analysis"]["normalized_url"] == "https://example.test/"
    assert client.get("/api/v1/history").json()[0]["scan_type"] == "url"


def test_secret_safety_question_is_guidance_and_chat_prompt_is_not_scanned(client, monkeypatch):
    def must_not_scan(*args, **kwargs):
        pytest.fail("A conversational safety question must not be treated as sample content")

    async def must_not_call_model(*args, **kwargs):
        pytest.fail("Curated credential safety guidance does not need model inference")

    monkeypatch.setattr(main, "analyze_text", must_not_scan)
    monkeypatch.setattr(main, "generate_local_reply", must_not_call_model)
    response = client.post("/api/v1/assistant/chat", json={
        "message": "Is asking for my UPI PIN a scam?",
        "analysis_type": "auto",
    })
    assert response.status_code == 200
    body = response.json()
    assert body["assistant_status"] == "guidance"
    assert body["analysis"] is None
    assert body["safety_guidance"]["source"] == "curated_safety_rule"
    assert "does not establish that a particular sender" in body["safety_guidance"]["text"]
    assert "Never tell anyone your UPI PIN" in body["safety_guidance"]["text"]
    assert client.get(f"/api/v1/assistant/conversations/{body['conversation_id']}").json()["messages"][-1]["content"].startswith("[CURATED_SAFETY_GUIDANCE]")


@pytest.mark.parametrize(("message", "language", "expected"), [
    ("क्या UPI PIN मांगना सुरक्षित है?", "auto", "अपना UPI PIN"),
    ("Mujhse UPI PIN maang rahe hain, kya karun?", "auto", "Apna UPI PIN"),
])
def test_secret_safety_guidance_detects_hindi_and_hinglish(client, monkeypatch, message, language, expected):
    async def must_not_call_model(*args, **kwargs):
        pytest.fail("Curated credential advice should be available without Gemini")

    monkeypatch.setattr(main, "generate_local_reply", must_not_call_model)
    response = client.post("/api/v1/assistant/chat", json={"message": message, "analysis_type": "none", "language_hint": None if language == "auto" else language})
    assert response.status_code == 200
    assert response.json()["assistant_status"] == "guidance"
    assert expected in response.json()["safety_guidance"]["text"]


def test_only_separate_suspicious_content_is_analyzed_once(client, monkeypatch):
    calls = []

    async def unavailable(*args, **kwargs):
        raise httpx.ConnectError("offline")

    original = main.analyze_text
    monkeypatch.setattr(main, "analyze_text", lambda text, language_hint=None: (calls.append(text) or original(text, language_hint)))
    monkeypatch.setattr(main, "generate_local_reply", unavailable)
    response = client.post("/api/v1/assistant/chat", json={
        "message": "Is this message dangerous? I received a refund text.",
        "analysis_type": "message",
        "content_to_analyze": "Send your OTP now to receive cashback",
    })
    assert response.status_code == 200
    assert calls == ["Send your OTP now to receive cashback"]
    assert response.json()["analysis"]["risk_level"] == "Critical"


def test_legitimate_content_remains_low_in_chat_scan(client, monkeypatch):
    async def unavailable(*args, **kwargs):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(main, "generate_local_reply", unavailable)
    response = client.post("/api/v1/assistant/chat", json={
        "message": "Please review the confirmation message I got.",
        "analysis_type": "message",
        "content_to_analyze": "Your bank payment was received successfully. Thank you.",
    })
    assert response.status_code == 200
    result = response.json()["analysis"]
    assert result["risk_level"] == "Low"
    assert result["assessment_basis"] == "insufficient_evidence"


def test_chat_history_is_redacted_and_deletable(client, monkeypatch):
    async def unavailable(*args, **kwargs):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(main, "generate_local_reply", unavailable)
    posted = client.post("/api/v1/assistant/chat", json={"message": "My number is 9876543210 and UPI ID is kartik@okaxis, what should I do?"})
    conversation_id = posted.json()["conversation_id"]
    messages = client.get(f"/api/v1/assistant/conversations/{conversation_id}").json()["messages"]
    assert len(messages) == 1
    assert "9876543210" not in messages[0]["content"]
    assert "[REDACTED_PHONE]" in messages[0]["content"]
    assert "kartik@okaxis" not in messages[0]["content"]
    assert "[REDACTED_EMAIL_OR_UPI]" in messages[0]["content"]
    assert client.get("/api/v1/assistant/conversations").json()[0]["id"] == conversation_id
    assert client.delete(f"/api/v1/assistant/conversations/{conversation_id}").json()["deleted"] is True
    assert client.get(f"/api/v1/assistant/conversations/{conversation_id}").status_code == 404


def test_chat_generates_response_only_when_model_is_available(client, monkeypatch):
    async def ready():
        return {"runtime_available": True, "model_available": True, "ready": True}

    async def answer(messages, language_hint=None):
        assert messages[-1]["content"] == "How do phishing kits steal session cookies?"
        return "Use the official portal. This is guidance, not a submitted complaint."

    monkeypatch.setattr(main, "inspect_local_model", ready)
    monkeypatch.setattr(main, "generate_local_reply", answer)
    response = client.post("/api/v1/assistant/chat", json={"message": "How do phishing kits steal session cookies?"})
    assert response.status_code == 200
    assert response.json()["assistant_status"] == "ready"
    assert "not a submitted complaint" in response.json()["assistant_reply"]


@pytest.mark.parametrize(("message", "expected_title"), [
    ("kya bank account balance aana normal hai", "Verify an unexpected credit"),
    ("mere account me unknown paise aaye hain kya karu", "Verify an unexpected credit"),
    ("bank wale KYC update karne ko bol rahe hain", "Verify the KYC request"),
    ("mujhse UPI PIN maang rahe hain", "Protect private payment credentials"),
    ("bhai mere paise kat gye h account se kya karu", "Check an unrecognized debit"),
    ("I received money from an unknown person, what should I do?", "Verify an unexpected credit"),
    ("Mere account se paise kat gaye but maine transaction nahi kiya.", "Check an unrecognized debit"),
])
def test_english_and_hinglish_examples_get_supported_safe_guidance_without_scanning(client, monkeypatch, message, expected_title):
    def must_not_scan(*args, **kwargs):
        pytest.fail("Conversation questions must not be used as scanner samples")

    async def must_not_call_model(*args, **kwargs):
        pytest.fail("A supported safety intent should return before model inference")

    monkeypatch.setattr(main, "analyze_text", must_not_scan)
    monkeypatch.setattr(main, "generate_local_reply", must_not_call_model)
    response = client.post("/api/v1/assistant/chat", json={"message": message, "analysis_type": "auto"})
    assert response.status_code == 200
    body = response.json()
    assert body["analysis"] is None
    assert body["assistant_status"] == "guidance"
    assert body["safety_guidance"]["title"] == expected_title
    assert body["safety_guidance"]["source"] == "curated_safety_rule"


def test_unexpected_credit_guidance_distinguishes_actual_credit_sms_and_return_request():
    result = assistant_service.curated_fallback_guidance("I received money from an unknown person, what should I do?")
    assert result is not None
    assert "official app" in result["text"]
    assert "do not spend or forward" in result["text"]
    assert "actual credit" in result["text"]
    assert "only receive an SMS" in result["text"]
    assert "asking you to send money back" in result["text"]
    assert "OTP, UPI PIN, or password" in result["text"]


def test_rule_fallback_is_not_triggered_by_a_broad_general_scam_question():
    assert assistant_service.curated_fallback_guidance("What is a scam?") is None
    assert assistant_service.curated_fallback_guidance("How do I report a suspicious call?") is not None


def test_romanized_hinglish_debit_is_actionable_fast_guidance():
    message = "bhai mere paise kat gye h account se kya karu"
    result = assistant_service.curated_fallback_guidance(message)
    assert result is not None
    assert assistant_service.resolve_reply_language(message) == "hinglish"
    assert "Bhai," in result["text"]
    assert "official app" in result["text"]
    assert "turant report" in result["text"]
    assert "OTP, PIN ya password" in result["text"]
    assert "UPI, card, ATM ya bank transfer" in result["text"]
    assert "fraud hua hai" not in result["text"]
    assert not re.search(r"[\u0900-\u097f]", result["text"])


def test_explicit_language_overrides_auto_detect():
    assert assistant_service.resolve_reply_language("bhai paise kat gye", "hi") == "hi"
    assert assistant_service.resolve_reply_language("bhai paise kat gye", "en") == "en"


def test_gemini_generate_content_preserves_request_and_response_timings(monkeypatch):
    seen = {}
    monkeypatch.setattr(assistant_service, "GEMINI_API_KEY", "test-gemini-secret")
    monkeypatch.setattr(assistant_service, "GEMINI_MODEL", "gemini-test-model")

    class FakeResponse:
        is_success = True
        status_code = 200
        text = ""
        def json(self):
            return {"candidates": [{"content": {"parts": [{"text": "Check your official bank app."}]}}], "usageMetadata": {"promptTokenCount": 20, "candidatesTokenCount": 8}}

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def post(self, url, headers, json):
            seen.update(url=url, headers=headers, payload=json)
            return FakeResponse()

    monkeypatch.setattr(assistant_service.httpx, "AsyncClient", lambda *args, **kwargs: FakeClient())
    reply, timings = asyncio.run(assistant_service.generate_local_reply([
        {"role": "system", "content": "Scan evidence is advisory."},
        {"role": "user", "content": "How do I protect my account?"},
    ], "hinglish"))
    assert reply == "Check your official bank app."
    assert seen["url"].endswith("/models/gemini-test-model:generateContent")
    assert seen["headers"]["x-goog-api-key"] == "test-gemini-secret"
    assert "test-gemini-secret" not in seen["url"]
    assert "Roman letters" in seen["payload"]["systemInstruction"]["parts"][0]["text"]
    assert "Scan evidence is advisory." in seen["payload"]["systemInstruction"]["parts"][0]["text"]
    assert seen["payload"]["contents"] == [{"role": "user", "parts": [{"text": "How do I protect my account?"}]}]
    assert seen["payload"]["generationConfig"]["maxOutputTokens"] == 512
    assert timings["request_wall_ms"] >= 0
    assert timings["time_to_first_text_ms"] == 0.0
    assert timings["generated_tokens"] == 8


@pytest.mark.parametrize("response_body", [
    {},
    {"candidates": []},
    {"candidates": [{"content": {"parts": []}}]},
    {"candidates": [{"content": {"parts": [{"text": "   "}]}}]},
])
def test_gemini_empty_or_invalid_responses_raise_a_handled_error(monkeypatch, response_body):
    monkeypatch.setattr(assistant_service, "GEMINI_API_KEY", "test-gemini-secret")
    monkeypatch.setattr(assistant_service, "GEMINI_MODEL", "gemini-test-model")

    class FakeResponse:
        is_success = True
        status_code = 200
        text = ""
        def json(self): return response_body

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def post(self, *args, **kwargs): return FakeResponse()

    monkeypatch.setattr(assistant_service.httpx, "AsyncClient", lambda *args, **kwargs: FakeClient())
    with pytest.raises(ValueError, match="Gemini returned"):
        asyncio.run(assistant_service.generate_local_reply([{"role": "user", "content": "Explain this"}]))


def test_gemini_http_error_is_logged_safely_and_raised(monkeypatch, caplog):
    secret = "test-gemini-secret"
    monkeypatch.setattr(assistant_service, "GEMINI_API_KEY", secret)
    monkeypatch.setattr(assistant_service, "GEMINI_MODEL", "gemini-test-model")
    request = httpx.Request("POST", "https://generativelanguage.googleapis.com/test")
    response = httpx.Response(403, text=f'{{"error":"permission denied","echo":"{secret}"}}', request=request)

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def post(self, *args, **kwargs): return response

    monkeypatch.setattr(assistant_service.httpx, "AsyncClient", lambda *args, **kwargs: FakeClient())
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(assistant_service.generate_local_reply([{"role": "user", "content": "Explain this"}]))
    assert "gemini_api_error status=403" in caplog.text
    assert "permission denied" in caplog.text
    assert secret not in caplog.text


def test_gemini_http_error_does_not_crash_chat_endpoint(client, monkeypatch):
    request = httpx.Request("POST", "https://generativelanguage.googleapis.com/test")
    response = httpx.Response(403, text='{"error":"permission denied"}', request=request)

    async def rejected(*args, **kwargs):
        raise httpx.HTTPStatusError("request rejected", request=request, response=response)

    monkeypatch.setattr(main, "generate_local_reply", rejected)
    result = client.post("/api/v1/assistant/chat", json={"message": "How do phishing kits work?"})
    assert result.status_code == 200
    assert result.json()["assistant_status"] == "error"
    assert result.json()["assistant_reply"] is None


def test_timeout_does_not_fabricate_a_model_reply_for_unmatched_intent(client, monkeypatch):
    async def timed_out(*args, **kwargs):
        raise httpx.ReadTimeout("Gemini API request timed out")

    monkeypatch.setattr(main, "generate_local_reply", timed_out)
    response = client.post("/api/v1/assistant/chat", json={"message": "How does device fingerprinting identify a malicious login?"})
    body = response.json()
    assert response.status_code == 200
    assert body["assistant_status"] == "timeout"
    assert body["assistant_reply"] is None
    assert body["safety_guidance"] is None


def test_retry_request_reuses_saved_user_and_scanner_result(client, monkeypatch):
    request_id = "76028512-640f-462d-bf9f-b2ea45a23526"
    scan_calls = []
    original_analyze = main.analyze_text

    def counted_analyze(text, language_hint=None):
        scan_calls.append(text)
        return original_analyze(text, language_hint)

    replies = 0
    async def retrying_model(*args, **kwargs):
        nonlocal replies
        replies += 1
        if replies == 1:
            raise httpx.ConnectError("Gemini API is unavailable")
        return "Review complete. The scanner result is advisory."

    monkeypatch.setattr(main, "analyze_text", counted_analyze)
    monkeypatch.setattr(main, "generate_local_reply", retrying_model)
    payload = {
        "message": "Please review the message I received.",
        "analysis_type": "message",
        "content_to_analyze": "Send your OTP now to receive cashback",
        "client_request_id": request_id,
    }
    first = client.post("/api/v1/assistant/chat", json=payload)
    assert first.json()["assistant_status"] == "unavailable"
    second = client.post("/api/v1/assistant/chat", json={**payload, "conversation_id": first.json()["conversation_id"]})
    assert second.json()["assistant_status"] == "ready"
    assert second.json()["analysis"] is None
    assert scan_calls == ["Send your OTP now to receive cashback"]
    assert len(client.get("/api/v1/history").json()) == 1
    messages = client.get(f"/api/v1/assistant/conversations/{first.json()['conversation_id']}").json()["messages"]
    assert [item["role"] for item in messages] == ["user", "assistant"]


def test_retry_request_id_recovers_conversation_when_first_response_was_lost(client, monkeypatch):
    request_id = "72d70539-c8d0-4433-9421-74d63af1bd11"
    async def unavailable(*args, **kwargs):
        raise httpx.ConnectError("lost before answer")

    monkeypatch.setattr(main, "generate_local_reply", unavailable)
    payload = {"message": "How do I report a suspicious call?", "analysis_type": "none", "client_request_id": request_id}
    # The idempotency key locates the original thread when the client never received its conversation id.
    first = client.post("/api/v1/assistant/chat", json=payload)
    assert first.status_code == 200

    async def answer(*args, **kwargs):
        return "Use the verified reporting route."

    monkeypatch.setattr(main, "generate_local_reply", answer)
    retry = client.post("/api/v1/assistant/chat", json=payload)
    assert retry.status_code == 200
    assert retry.json()["conversation_id"] == first.json()["conversation_id"]


def test_startup_adds_retry_key_without_replacing_existing_chat_history(monkeypatch):
    legacy_engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    with legacy_engine.begin() as connection:
        connection.execute(text("CREATE TABLE assistant_messages (id INTEGER PRIMARY KEY, conversation_id VARCHAR(36), role VARCHAR(16), content TEXT, created_at DATETIME)"))
    monkeypatch.setattr(main, "engine", legacy_engine)
    monkeypatch.setattr(main, "SessionLocal", sessionmaker(bind=legacy_engine, autoflush=False, autocommit=False))
    main.startup()
    columns = {item["name"] for item in sqlalchemy_inspect(legacy_engine).get_columns("assistant_messages")}
    assert {"id", "conversation_id", "role", "content", "created_at", "client_request_id"} <= columns
    assert any(index["name"] == "ix_assistant_messages_client_request_id" for index in sqlalchemy_inspect(legacy_engine).get_indexes("assistant_messages"))
    legacy_engine.dispose()


def test_chat_context_is_limited_to_four_recent_history_messages(client, monkeypatch):
    conversation = client.post("/api/v1/assistant/conversations").json()
    with main.SessionLocal() as db:
        db.add_all([
            main.AssistantMessageRecord(conversation_id=conversation["id"], role="user" if index % 2 == 0 else "assistant", content=f"Older turn {index}")
            for index in range(12)
        ])
        db.commit()
    captured = {}

    async def answer(messages, language_hint=None):
        captured["messages"] = messages
        return "A concise reply."

    monkeypatch.setattr(main, "generate_local_reply", answer)
    response = client.post("/api/v1/assistant/chat", json={
        "message": "What should I do next?", "analysis_type": "none", "conversation_id": conversation["id"],
    })
    assert response.status_code == 200
    assert len(captured["messages"]) == 5
    assert captured["messages"][-1] == {"role": "user", "content": "What should I do next?"}
    assert captured["messages"][0]["content"] == "Older turn 8"
