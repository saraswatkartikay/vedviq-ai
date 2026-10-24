import React, { FormEvent, useEffect, useRef, useState } from "react";
import {
  AlertTriangle, ArrowUp, Bot, BookOpenCheck, Check, ChevronDown, CircleHelp,
  FileImage, FileText, Globe2, LoaderCircle, Plus, ShieldAlert, ShieldCheck,
  Trash2, UserRound, ExternalLink, Copy, RotateCw, ClipboardCheck,
} from "lucide-react";
import { api } from "../services/api";
import type {
  AnalysisResult, AssistantConversationSummary, AssistantMessage,
  AssistantStatus, ComplaintResource,
} from "../types/api";
import { copyAssistantText, draftTextFromMarkdown, isStructuredDraft, MarkdownResponse, markdownToPlainText } from "./AssistantMarkdown";
import "./AssistantScreen.css";

type ViewMessage = AssistantMessage & { analysis?: AnalysisResult; analysisNote?: string };
type AnalysisMode = "auto" | "message" | "url" | "none";
type RetryRequest = { clientRequestId: string; message: string; conversationId?: string; analysisMode: AnalysisMode; scanContent?: string; languageHint?: string; localUserId: number; localReplyId?: number };

function makeRequestId() {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (char) => {
    const value = Math.floor(Math.random() * 16);
    return (char === "x" ? value : (value & 0x3) | 0x8).toString(16);
  });
}

const starterPrompts = [
  { icon: ShieldAlert, text: "Is it safe to share my UPI PIN or OTP with someone who asks?", mode: "none" as AnalysisMode },
  { icon: CircleHelp, text: "I have lost money to an online scam. What should I do right now?", mode: "none" as AnalysisMode },
  { icon: FileText, text: "Help me prepare a cybercrime complaint or bank email draft. Ask only for non-sensitive details.", mode: "none" as AnalysisMode },
];

const languageOptions = [
  ["auto", "Auto-detect"], ["en", "English"], ["hi", "हिन्दी"], ["hinglish", "Hinglish"],
  ["bn", "বাংলা"], ["ta", "தமிழ்"], ["te", "తెలుగు"], ["mr", "मराठी"],
  ["kn", "ಕನ್ನಡ"], ["ml", "മലയാളം"], ["gu", "ગુજરાતી"], ["pa", "ਪੰਜਾਬੀ"],
  ["ur", "اردو"], ["or", "ଓଡ଼ିଆ"], ["as", "অসমীয়া"],
];

function ScanFinding({ result }: { result: AnalysisResult }) {
  const riskClass = result.risk_level.toLowerCase();
  const basisLabel = result.assessment_basis === "external_threat_match" ? "External threat match" : result.assessment_basis === "suspicious_pattern" ? "Suspicious pattern evidence" : result.assessment_basis === "warning_signals" ? "Warning signals" : "Insufficient evidence";
  return <section className={`assistant-finding risk-${riskClass}`} aria-label="Existing VEDVIQ AI analysis result">
    <div className="assistant-finding-head"><span className="assistant-finding-icon"><ShieldAlert size={16} /></span><div><p>{basisLabel}</p><strong>{result.scam_category}</strong></div><span className="assistant-risk-chip">{result.risk_level} · {Math.round(result.risk_score)}/100</span></div>
    <p className="assistant-score-caption">Evidence score, not a probability: rule weights summed, plus 40 for a provider-reported malicious match (capped at 100). Bands: low &lt;22, medium 22–31, high 32–39, critical ≥40.</p>
    <p className="assistant-finding-summary">{result.summary_explanation}</p>
    {result.rule_indicators.length > 0 && <div className="assistant-evidence"><strong>Observed warning signs</strong>{result.rule_indicators.slice(0, 4).map((item) => <p key={item.id}><span />{item.name}{item.matched_text ? <small>“{item.matched_text}”</small> : null}</p>)}</div>}
    {result.recommended_actions.length > 0 && <div className="assistant-evidence"><strong>Suggested next steps</strong>{result.recommended_actions.slice(0, 3).map((action) => <p key={action}><Check size={13} />{action}</p>)}</div>}
    {result.scan_type === "url" && result.threat_intel.verdict === "unknown" && <p className="assistant-finding-caveat">Reputation was not confirmed. Unknown does not mean safe; this address was not opened.</p>}
    <p className="assistant-finding-caveat">Automated review is advisory and can miss threats. Verify independently.</p>
  </section>;
}

function MessageBubble({ message, onRetry }: { message: ViewMessage; onRetry?: () => void }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const [draftCopyState, setDraftCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const resetTimers = useRef<{ response?: number; draft?: number }>({});
  const copyPending = useRef(new Set<string>());
  const user = message.role === "user";
  const curated = !user && message.content.startsWith("[CURATED_SAFETY_GUIDANCE]\n");
  const displayContent = curated ? message.content.replace("[CURATED_SAFETY_GUIDANCE]\n", "") : message.content;
  const draft = !user && isStructuredDraft(displayContent);
  useEffect(() => () => Object.values(resetTimers.current).forEach((timer) => { if (timer !== undefined) window.clearTimeout(timer); }), []);
  const copy = async (draftOnly = false) => {
    const key = draftOnly ? "draft" : "response";
    if (copyPending.current.has(key)) return;
    copyPending.current.add(key);
    const previousTimer = resetTimers.current[key];
    if (previousTimer !== undefined) window.clearTimeout(previousTimer);
    const setState = draftOnly ? setDraftCopyState : setCopyState;
    setState("idle");
    try {
      const text = markdownToPlainText(draftOnly ? draftTextFromMarkdown(displayContent) : displayContent);
      await copyAssistantText(text);
      setState("copied");
      resetTimers.current[key] = window.setTimeout(() => setState("idle"), 1800);
    } catch {
      setState("failed");
      resetTimers.current[key] = window.setTimeout(() => setState("idle"), 2600);
    } finally {
      copyPending.current.delete(key);
    }
  };
  return <article className={`assistant-message ${user ? "is-user" : "is-assistant"}`}>
    <span className="assistant-message-avatar" aria-hidden="true">{user ? <UserRound size={15} /> : <Bot size={15} />}</span>
    <div className="assistant-message-body">
      <div className="assistant-message-meta"><strong>{user ? "You" : curated ? "Curated safety guidance · rule-based" : "VEDVIQ AI assistant"}</strong><time dateTime={message.created_at}>{new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(new Date(message.created_at))}</time></div>
      <div className={`assistant-message-copy ${draft ? "is-draft" : ""}`}>
        {user ? displayContent : draft ? <div className="assistant-draft-document"><MarkdownResponse content={displayContent} /></div> : <MarkdownResponse content={displayContent} />}
      </div>
      {message.analysisNote && <p className="assistant-analysis-note">{message.analysisNote}</p>}
      {message.analysis && <ScanFinding result={message.analysis} />}
      {!user && <div className="assistant-message-actions">
        <button type="button" onClick={() => void copy()} aria-label={copyState === "copied" ? "Assistant response copied" : copyState === "failed" ? "Copy failed; check clipboard permissions" : "Copy complete assistant response"} title={copyState === "failed" ? "Copy failed. Check browser clipboard permissions." : undefined}>
          {copyState === "copied" ? <ClipboardCheck size={14} /> : <Copy size={14} />}{copyState === "copied" ? "Copied!" : copyState === "failed" ? "Copy failed" : "Copy"}
        </button>
        {draft && <button type="button" onClick={() => void copy(true)} aria-label={draftCopyState === "copied" ? "Draft copied" : draftCopyState === "failed" ? "Copy failed; check clipboard permissions" : "Copy complete draft"} title={draftCopyState === "failed" ? "Copy failed. Check browser clipboard permissions." : undefined}>
          {draftCopyState === "copied" ? <ClipboardCheck size={14} /> : <Copy size={14} />}{draftCopyState === "copied" ? "Copied!" : draftCopyState === "failed" ? "Copy failed" : "Copy draft"}
        </button>}
        {onRetry && <button type="button" onClick={onRetry}><RotateCw size={14} />Retry</button>}
      </div>}
    </div>
  </article>;
}

function ResourceCard({ resource }: { resource: ComplaintResource }) {
  return <article className="assistant-resource">
    <div className="assistant-resource-title"><span><ShieldCheck size={15} /></span><strong>{resource.name}</strong><ExternalLink size={13} /></div>
    <p>{resource.purpose}</p>
    <div className="assistant-resource-meta"><span>{resource.jurisdiction}</span><span>Verified {resource.verified_on}</span></div>
    <a href={resource.url} target="_blank" rel="noreferrer">Open official portal <ExternalLink size={13} /></a>
    <details><summary>Source and verification <ChevronDown size={13} /></summary><div>{resource.source_urls.map((url) => <a key={url} href={url} target="_blank" rel="noreferrer">{url}</a>)}</div></details>
  </article>;
}

export default function AssistantScreen() {
  const [status, setStatus] = useState<AssistantStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [resources, setResources] = useState<ComplaintResource[]>([]);
  const [conversations, setConversations] = useState<AssistantConversationSummary[]>([]);
  const [conversationId, setConversationId] = useState<string | undefined>();
  const [messages, setMessages] = useState<ViewMessage[]>([]);
  const [message, setMessage] = useState("");
  const [scanContent, setScanContent] = useState("");
  const [scanOpen, setScanOpen] = useState(false);
  const [analysisMode, setAnalysisMode] = useState<AnalysisMode>("auto");
  const [language, setLanguage] = useState("auto");
  const [loading, setLoading] = useState(false);
  const [loadingSeconds, setLoadingSeconds] = useState(0);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [assistantNotice, setAssistantNotice] = useState<string | null>(null);
  const [retryRequest, setRetryRequest] = useState<RetryRequest | null>(null);
  const [ocrFile, setOcrFile] = useState<File | null>(null);
  const [ocrText, setOcrText] = useState("");
  const [ocrBusy, setOcrBusy] = useState(false);
  const [ocrResult, setOcrResult] = useState<AnalysisResult | null>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const localId = useRef(0);
  const sendingRef = useRef(false);

  const reloadConversations = async () => {
    try { setConversations(await api.getAssistantConversations()); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Conversation history is unavailable."); }
  };

  useEffect(() => {
    let live = true;
    api.getAssistantStatus().then((data) => { if (live) { setStatus(data); setStatusError(null); } })
      .catch((reason) => { if (live) setStatusError(reason instanceof Error ? reason.message : "Could not check the local assistant."); });
    api.getAssistantResources().then((data) => { if (live) setResources(data); }).catch(() => { /* Keep verified fallbacks in backend-owned status when available. */ });
    api.getAssistantConversations().then((data) => { if (live) setConversations(data); })
      .catch((reason) => { if (live) setError(reason instanceof Error ? reason.message : "Conversation history is unavailable."); });
    return () => { live = false; };
  }, []);

  useEffect(() => {
    const element = logRef.current;
    if (element) {
      const reduceMotion = typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      if (typeof element.scrollTo === "function") element.scrollTo({ top: element.scrollHeight, behavior: reduceMotion ? "instant" : "smooth" });
      else element.scrollTop = element.scrollHeight;
    }
  }, [messages, loading]);

  useEffect(() => {
    if (!loading) { setLoadingSeconds(0); return; }
    const started = Date.now();
    const timer = window.setInterval(() => setLoadingSeconds(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => window.clearInterval(timer);
  }, [loading]);

  const selectConversation = async (id: string) => {
    setLoadingHistory(true); setError(null); setAssistantNotice(null); setRetryRequest(null); setOcrResult(null);
    try {
      const data = await api.getAssistantConversation(id);
      setConversationId(id);
      setMessages(data.messages.map((item) => ({ ...item })));
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Could not load this conversation."); }
    finally { setLoadingHistory(false); }
  };

  const newConversation = async () => {
    setError(null); setAssistantNotice(null); setRetryRequest(null); setOcrResult(null); setMessage("");
    try {
      const created = await api.createAssistantConversation();
      setConversationId(created.id); setMessages([]);
      setConversations((current) => [created, ...current.filter((item) => item.id !== created.id)]);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Could not start a new conversation."); }
  };

  const removeConversation = async () => {
    if (!conversationId) return;
    try {
      await api.deleteAssistantConversation(conversationId);
      setConversations((current) => current.filter((item) => item.id !== conversationId));
      setConversationId(undefined); setMessages([]); setAssistantNotice(null); setRetryRequest(null);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Could not delete this conversation."); }
  };

  const sendMessage = async (event?: FormEvent, override?: string, overrideMode?: AnalysisMode, retry?: RetryRequest) => {
    event?.preventDefault();
    const text = (retry?.message ?? override ?? message).trim();
    if (!text || loading || sendingRef.current) return;
    sendingRef.current = true;
    setError(null); setAssistantNotice(null); setMessage("");
    if (!retry) setRetryRequest(null);
    const current: ViewMessage = retry
      ? { id: retry.localUserId, role: "user", content: text, created_at: new Date().toISOString() }
      : { id: -(++localId.current), role: "user", content: text, created_at: new Date().toISOString() };
    const requestToSend: RetryRequest = retry ?? {
      clientRequestId: makeRequestId(), message: text, conversationId,
      analysisMode: overrideMode ?? analysisMode, scanContent: scanContent.trim() || undefined,
      languageHint: language === "auto" ? undefined : language, localUserId: current.id,
    };
    if (!retry) setMessages((items) => [...items, current]);
    setLoading(true);
    try {
      const response = await api.assistantChat({ message: text, conversation_id: requestToSend.conversationId ?? conversationId, analysis_type: requestToSend.analysisMode, content_to_analyze: requestToSend.scanContent, language_hint: requestToSend.languageHint, client_request_id: requestToSend.clientRequestId });
      setConversationId(response.conversation_id);
      if (response.analysis) { setScanContent(""); setScanOpen(false); }
      setMessages((items) => items.map((item) => item.id === current.id ? { ...item, analysis: response.analysis ?? item.analysis, analysisNote: response.analysis_note ?? item.analysisNote } : item));
      if (response.safety_guidance) {
        const curatedContent = `[CURATED_SAFETY_GUIDANCE]\n${response.safety_guidance.text}`;
        const replyId = requestToSend.localReplyId ?? -(++localId.current);
        setMessages((items) => items.some((item) => item.id === replyId)
          ? items.map((item) => item.id === replyId ? { ...item, content: curatedContent } : item)
          : [...items, { id: replyId, role: "assistant", content: curatedContent, created_at: new Date().toISOString() }]);
        requestToSend.localReplyId = replyId;
      }
      if (response.assistant_reply) {
        setMessages((items) => [...items, { id: -(++localId.current), role: "assistant", content: response.assistant_reply as string, created_at: new Date().toISOString() }]);
      }
      if (response.assistant_status === "unavailable") {
        setAssistantNotice(`Hosted Gemini is unavailable${status?.model ? ` (${status.model} is not ready)` : ""}.${response.safety_guidance ? " The clearly labelled rule-based guidance is shown above; no generated answer was substituted." : " No generated answer was substituted and no safe rule-based fallback matched this question."} You can still use the scanner and official reporting links.`);
        setRetryRequest({ ...requestToSend, conversationId: response.conversation_id });
      } else if (response.assistant_status === "timeout") {
        setAssistantNotice(`The Gemini API request timed out.${response.safety_guidance ? " The clearly labelled rule-based guidance is shown above; no generated answer was substituted." : " No generated answer was substituted and no safe rule-based fallback matched this question."}`);
        setRetryRequest({ ...requestToSend, conversationId: response.conversation_id });
      } else if (response.assistant_status === "error") {
        setAssistantNotice(`The Gemini API returned an error.${response.safety_guidance ? " The clearly labelled rule-based guidance is shown above; no generated answer was substituted." : " No generated answer was substituted and no safe rule-based fallback matched this question."} Check the backend Gemini configuration and model access, then retry.`);
        setRetryRequest({ ...requestToSend, conversationId: response.conversation_id });
      } else {
        setRetryRequest(null);
      }
      void reloadConversations();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The message could not be sent.");
      setRetryRequest(requestToSend);
    }
    finally { sendingRef.current = false; setLoading(false); }
  };

  const retryLatest = () => { if (retryRequest) void sendMessage(undefined, undefined, undefined, retryRequest); };

  const analyzeScreenshot = async (event: FormEvent) => {
    event.preventDefault();
    if (!ocrFile) { setError("Choose a PNG, JPEG, or WEBP screenshot first."); return; }
    setError(null); setOcrBusy(true); setOcrResult(null);
    try { setOcrResult(await api.analyzeOcr(ocrFile, ocrText)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Screenshot analysis failed."); }
    finally { setOcrBusy(false); }
  };

  const officialResources = resources.length ? resources : status?.resources ?? [];
  const ready = status?.ready === true;
  const retryOnNotice = Boolean(retryRequest && retryRequest.localReplyId === undefined);

  return <div className="assistant-screen screen-enter">
    <header className="assistant-page-head">
      <div><p className="assistant-eyebrow"><span /> CYBER SAFETY / AI ASSISTANT</p><h1>Ask before you act.</h1><p>Understand a suspicious message, find the right reporting route, and prepare your next step.</p></div>
      <div className={`assistant-runtime ${ready ? "is-ready" : status ? "is-missing" : "is-checking"}`} role="status"><i />{ready ? `Gemini API available · ${status?.model}` : status ? "Gemini API unavailable" : statusError ? "Assistant status unavailable" : "Checking Gemini API"}</div>
    </header>

    {status && !status.ready && <section className="assistant-model-banner" role="status"><span><AlertTriangle size={18} /></span><div><strong>Hosted Gemini is not ready</strong><p>{status.runtime_available ? `The Gemini API responded, but the configured model (${status.model}) could not be verified.` : "The Gemini API could not be reached or configured."} Clearly labelled rule-based safety guidance remains available for supported situations. Other AI answers are unavailable; message, URL, and screenshot checks and the official reporting directory still work.</p><details><summary>Check the Gemini configuration <ChevronDown size={14} /></summary><ol>{status.setup_instructions.map((step) => <li key={step}>{step}</li>)}</ol><code>GEMINI_MODEL={status.model}</code></details></div></section>}
    {!status && statusError && <section className="assistant-model-banner is-error" role="status"><span><AlertTriangle size={18} /></span><div><strong>Assistant service could not be checked</strong><p>{statusError} The rest of the app’s scanner pages are separate and remain available.</p></div></section>}

    <div className="assistant-layout">
      <aside className="assistant-history-panel" aria-label="Chat history">
        <div className="assistant-panel-title"><div><p>YOUR CHATS</p><strong>Conversations</strong></div><button type="button" onClick={newConversation} aria-label="Start a new conversation" title="New conversation"><Plus size={16} /></button></div>
        <div className="assistant-conversation-list">{conversations.length ? conversations.map((item) => <button type="button" key={item.id} className={conversationId === item.id ? "is-active" : ""} onClick={() => void selectConversation(item.id)} title={item.title}><span><Bot size={15} /></span><span className="assistant-conversation-copy"><strong>{item.title}</strong><small>{new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(new Date(item.updated_at))}</small></span></button>) : <p className="assistant-history-empty">Your saved conversations will appear here.</p>}</div>
        <div className="assistant-privacy-note"><ShieldCheck size={14} /><span>Chat history stores redacted text. Avoid sharing secrets or account details.</span></div>
      </aside>

      <section className="assistant-chat-panel" aria-label="Cyber safety conversation">
        <header className="assistant-chat-heading"><div className="assistant-chat-title-icon"><Bot size={18} /></div><div><strong>{conversationId ? conversations.find((item) => item.id === conversationId)?.title || "Conversation" : "New conversation"}</strong><span>{ready ? "Gemini API · hosted model" : "VEDVIQ AI scanner and verified resources"}</span></div><div className="assistant-chat-actions">{conversationId && <button type="button" onClick={removeConversation} title="Delete conversation" aria-label="Delete conversation"><Trash2 size={15} /></button>}</div></header>

        <div className="assistant-chat-log" ref={logRef} role="log" aria-live="polite" aria-relevant="additions text" aria-label="Conversation messages">
          {loadingHistory ? <div className="assistant-chat-empty" role="status"><LoaderCircle className="assistant-spin" size={23} /><strong>Loading conversation</strong></div> : messages.length === 0 ? <div className="assistant-chat-empty"><div className="assistant-empty-mark"><Bot size={25} /></div><p className="assistant-eyebrow">VEDVIQ AI CYBER GUIDE</p><h2>What happened?</h2><p>Share a non-sensitive description. Never send OTPs, PINs, passwords, or full account details.</p><div className="assistant-starters">{starterPrompts.map(({ icon: Icon, text, mode }) => <button type="button" key={text} onClick={() => void sendMessage(undefined, text, mode)}><Icon size={15} /><span>{text}</span><ArrowUp size={14} /></button>)}</div></div> : messages.map((item) => <MessageBubble key={item.id} message={item} onRetry={item.id === retryRequest?.localReplyId && retryRequest ? retryLatest : undefined} />)}
          {loading && <div className="assistant-typing" role="status"><span><Bot size={14} /></span><i /><i /><i /><small>{`Waiting for Gemini · ${loadingSeconds}s`}</small></div>}
          {assistantNotice && <div className="assistant-notice" role="status"><AlertTriangle size={15} /><p>{assistantNotice}</p>{retryOnNotice && <button type="button" onClick={retryLatest} disabled={loading}><RotateCw size={14} />Retry</button>}</div>}
          {error && <div className="assistant-inline-error" role="alert"><AlertTriangle size={15} />{error}{retryRequest && <button type="button" onClick={retryLatest} disabled={loading}><RotateCw size={14} />Retry</button>}<button type="button" onClick={() => setError(null)}>Dismiss</button></div>}
        </div>

        <form className="assistant-composer" onSubmit={(event) => void sendMessage(event)}>
          <details className="assistant-scan-input" open={scanOpen} onToggle={(event) => setScanOpen(event.currentTarget.open)}>
            <summary>Attach original suspicious text or URL for a separate scan <ChevronDown size={13} /></summary>
            <label className="sr-only" htmlFor="assistant-scan-content">Original suspicious message or URL to scan separately</label>
            <textarea id="assistant-scan-content" value={scanContent} onChange={(event) => setScanContent(event.target.value)} maxLength={10000} rows={2} placeholder="Paste only the original message or one URL. This is analyzed separately from your question." disabled={loading} />
            <small>{scanContent.length}/10000 · Do not include OTPs, PINs, or passwords</small>
          </details>
          <label className="sr-only" htmlFor="assistant-message">Message VEDVIQ AI</label>
          <textarea id="assistant-message" value={message} onChange={(event) => setMessage(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); void sendMessage(); } }} maxLength={4000} rows={2} placeholder="Describe a suspicious message or ask what to do…" disabled={loading} />
          <div className="assistant-composer-tools"><label>Analysis<select value={analysisMode} onChange={(event) => { const value = event.target.value as AnalysisMode; setAnalysisMode(value); if (value === "message" || value === "url") setScanOpen(true); }}><option value="auto">Separate input only</option><option value="message">Scan separate message</option><option value="url">Scan separate URL</option><option value="none">No scan</option></select></label><label>Reply language<select value={language} onChange={(event) => setLanguage(event.target.value)}>{languageOptions.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><span className="assistant-char-count">{message.length}/4000</span><button type="submit" aria-label="Send message" disabled={loading || !message.trim()}>{loading ? <LoaderCircle className="assistant-spin" size={17} /> : <ArrowUp size={17} />}</button></div>
        </form>
        <p className="assistant-chat-disclaimer">Guidance can be incomplete. Verify official instructions and never share secrets here.</p>
      </section>

      <aside className="assistant-guidance-panel" aria-label="Reporting and evidence guidance">
        <section className="assistant-emergency"><div><span><AlertTriangle size={18} /></span><p>LOST MONEY?</p></div><strong>Call 1930 promptly.</strong><p>Official cybercrime helpline. Also contact your bank through its official app or website and report at the national portal.</p><a href="https://cybercrime.gov.in/" target="_blank" rel="noreferrer">Open cybercrime.gov.in <ExternalLink size={13} /></a><small>Official Government of India guidance</small></section>
        <section className="assistant-evidence-card"><div className="assistant-side-heading"><BookOpenCheck size={16} /><strong>Evidence checklist</strong></div><ul><li>Keep original messages, emails, call logs, and screenshots.</li><li>Note the approximate date, time, and contact channel.</li><li>Save transaction reference and bank communication securely.</li><li>Do not post identity or payment details in this chat.</li></ul><p>General preparation suggestions. Follow the official portal’s current instructions.</p></section>
        <section className="assistant-resource-list"><div className="assistant-side-heading"><Globe2 size={16} /><strong>Official reporting routes</strong></div><p>Verified destinations, separate from AI-generated suggestions.</p>{officialResources.map((resource) => <ResourceCard key={resource.id} resource={resource} />)}{officialResources.length === 0 && <p className="assistant-resource-unavailable">The directory could not be loaded. Use the national portal above as the safe fallback.</p>}</section>
        <details className="assistant-ocr"><summary><span><FileImage size={15} /> Check a screenshot with OCR</span><ChevronDown size={14} /></summary><form onSubmit={(event) => void analyzeScreenshot(event)}><input aria-label="Choose screenshot" type="file" accept="image/png,image/jpeg,image/webp" onChange={(event) => setOcrFile(event.target.files?.[0] ?? null)} /><label htmlFor="assistant-ocr-text">Optional text from screenshot</label><textarea id="assistant-ocr-text" rows={3} maxLength={10000} value={ocrText} onChange={(event) => setOcrText(event.target.value)} placeholder="Paste or correct visible text…" /><button type="submit" disabled={ocrBusy || !ocrFile}>{ocrBusy ? <LoaderCircle className="assistant-spin" size={14} /> : <FileImage size={14} />}{ocrBusy ? "Reading…" : "Read and review image"}</button></form>{ocrResult && <div className="assistant-ocr-result"><strong>{ocrResult.risk_level} concern · {ocrResult.scam_category}</strong><p>{ocrResult.summary_explanation}</p><p>Review #{ocrResult.scan_id} saved to existing scan history.</p></div>}</details>
      </aside>
    </div>
  </div>;
}
