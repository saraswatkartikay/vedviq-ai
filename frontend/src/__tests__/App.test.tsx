import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";
import { api } from "../services/api";
import { INTRO_SEEN_KEY } from "../components/CyberBootIntro";

vi.mock("../services/api", () => ({
  api: {
    analyzeMessage: vi.fn(), analyzeUrl: vi.fn(), analyzeOcr: vi.fn(),
    getDashboard: vi.fn(), getHistory: vi.fn(), deleteScan: vi.fn(),
    getSystemStatus: vi.fn(), updateSettings: vi.fn(),
    getAssistantStatus: vi.fn(), getAssistantResources: vi.fn(), getAssistantConversations: vi.fn(),
    getAssistantConversation: vi.fn(), createAssistantConversation: vi.fn(), deleteAssistantConversation: vi.fn(), assistantChat: vi.fn(),
  },
}));

const report = {
  scan_id: 42, scan_type: "message", created_at: "2026-10-21T09:30:00Z",
  redacted_preview: "Bank notice asking for an OTP", raw_content_stored: false,
  risk_score: 88, risk_level: "High", scam_category: "Credential Theft",
  summary_explanation: "This is a test response from the mocked API.",
  recommended_actions: ["Contact the bank through its official app."],
  limitations_note: "Automated checks can be wrong.",
  ml_assessment: { status: "untrained", predicted_label: "unknown", calibrated_probability: null, top_features: [], model_version: null, note: "Not available" },
  rule_indicators: [], threat_intel: { provider: "None", mode: "offline", verdict: "unknown", details: "Not queried" },
  suspicious_spans: [],
};
const analytics = {
  total_scans: 1, high_or_critical_count: 1,
  risk_distribution: [{ name: "High", value: 1 }],
  category_breakdown: [{ category: "Credential Theft", count: 1 }],
  scans_over_time: [{ date: "2026-10-21", scans: 1, high_risk: 1 }],
  recent_scans: [report], model_status: { status: "untrained", disclaimer: "Development fixture" },
  threat_intel_configured: false,
};
const status = {
  api_status: "operational", app_version: "1.0.0", database_connected: true,
  ocr_engine_available: false, threat_intel_provider: "Not queried", threat_intel_configured: false,
  model_metadata: { status: "untrained", disclaimer: "Development fixture" },
  privacy_settings: { store_raw_content: false, retention_days: 30 },
};
const assistantStatus = {
  runtime: "Ollama (local)", runtime_available: false, model: "qwen2.5:3b", model_available: false, ready: false,
  setup_instructions: ["Install Ollama", "ollama pull qwen2.5:3b"], resources: [
    { id: "national-cybercrime-portal", name: "National Cyber Crime Reporting Portal", url: "https://cybercrime.gov.in/", jurisdiction: "India", purpose: "Report cybercrime.", source_urls: ["https://cybercrime.gov.in/"], verified_on: "2026-10-23", official: true },
  ],
};

function createMemoryStorage(): Storage {
  const values = new Map<string, string>();
  return {
    get length() { return values.size; },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => Array.from(values.keys())[index] ?? null,
    removeItem: (key) => values.delete(key),
    setItem: (key, value) => values.set(key, String(value)),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(window, "localStorage", { configurable: true, value: createMemoryStorage() });
  window.localStorage.removeItem("scamsathi-theme");
  document.documentElement.dataset.theme = "dark";
  window.sessionStorage.setItem(INTRO_SEEN_KEY, "true");
  vi.mocked(api.analyzeMessage).mockResolvedValue(report);
  vi.mocked(api.analyzeUrl).mockResolvedValue({ ...report, scan_type: "url" });
  vi.mocked(api.analyzeOcr).mockResolvedValue({ ...report, scan_type: "screenshot" });
  vi.mocked(api.getDashboard).mockResolvedValue(analytics);
  vi.mocked(api.getHistory).mockResolvedValue([report]);
  vi.mocked(api.getSystemStatus).mockResolvedValue(status);
  vi.mocked(api.deleteScan).mockResolvedValue({ deleted: true, scan_id: 42 });
  vi.mocked(api.updateSettings).mockResolvedValue(status.privacy_settings);
  vi.mocked(api.getAssistantStatus).mockResolvedValue(assistantStatus);
  vi.mocked(api.getAssistantResources).mockResolvedValue(assistantStatus.resources);
  vi.mocked(api.getAssistantConversations).mockResolvedValue([]);
  vi.mocked(api.getAssistantConversation).mockResolvedValue({ id: "conversation-1", title: "Help", created_at: "2026-10-21T09:30:00Z", updated_at: "2026-10-21T09:30:00Z", messages: [] });
  vi.mocked(api.createAssistantConversation).mockResolvedValue({ id: "conversation-1", title: "New conversation", created_at: "2026-10-21T09:30:00Z", updated_at: "2026-10-21T09:30:00Z" });
  vi.mocked(api.deleteAssistantConversation).mockResolvedValue({ deleted: true, conversation_id: "conversation-1" });
  vi.mocked(api.assistantChat).mockResolvedValue({ conversation_id: "conversation-1", assistant_status: "unavailable", assistant_reply: null, model: null, setup_instructions: ["ollama pull qwen2.5:3b"], analysis: null, stored_redacted: true });
});
afterEach(() => {
  cleanup();
  window.sessionStorage.removeItem(INTRO_SEEN_KEY);
});

describe("VEDVIQ AI workspace", () => {
  it("shows the welcome page on a fresh session, skips into the dashboard, and reuses its data request", async () => {
    window.sessionStorage.removeItem(INTRO_SEEN_KEY);
    render(<App />);

    expect(screen.getByRole("dialog", { name: "Pause before you trust." })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Pause before you trust." })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Enter VEDVIQ AI workspace" })).toBeInTheDocument();
    expect(screen.getByText("AI can make mistakes. Check important information independently.")).toBeInTheDocument();
    expect(api.getDashboard).toHaveBeenCalledTimes(1);

    expect(await screen.findByText("Workspace data available")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /skip intro/i }));
    expect(await screen.findByRole("heading", { name: "Your dashboard" })).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(window.sessionStorage.getItem(INTRO_SEEN_KEY)).toBe("true");
    expect(api.getDashboard).toHaveBeenCalledTimes(1);
  });

  it("replays the welcome page from navigation and enters the existing dashboard", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Replay intro" }));

    expect(screen.getByRole("dialog", { name: "Pause before you trust." })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Enter VEDVIQ AI workspace" }));
    expect(await screen.findByRole("heading", { name: "Your dashboard" })).toBeInTheDocument();
    expect(window.sessionStorage.getItem(INTRO_SEEN_KEY)).toBe("true");
  });

  it("renders the dashboard and opens dedicated review tools from quick actions", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Your dashboard" })).toBeInTheDocument();
    expect(await screen.findByText("Recent activity")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Web address/ }));
    expect(screen.getByRole("heading", { name: "URL Guard" })).toBeInTheDocument();
    expect(screen.getByPlaceholderText("https://example-bank-kyc-update.xyz/login")).toBeInTheDocument();
  });

  it("opens the existing AI Assistant route from the floating launcher", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Open VEDVIQ AI Assistant" }));
    expect(await screen.findByRole("heading", { name: "Ask before you act." })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Open VEDVIQ AI Assistant" })).not.toBeInTheDocument();
  });

  it("opens and closes the responsive navigation when a destination is chosen", () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Open navigation menu" }));
    expect(screen.getByRole("button", { name: "Close navigation menu" })).toHaveAttribute("aria-expanded", "true");
    fireEvent.click(screen.getByRole("button", { name: "Awareness" }));
    expect(screen.getByRole("button", { name: "Open navigation menu" })).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByRole("heading", { name: "Learn to spot scams" })).toBeInTheDocument();
  });

  it("submits dedicated message, URL, and screenshot scans through existing API calls", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Message Scan" }));
    fireEvent.change(screen.getByPlaceholderText("Paste suspicious SMS, WhatsApp message, or email text here..."), { target: { value: "Please share your bank OTP" } });
    fireEvent.click(screen.getByRole("button", { name: "Run Explainable Scam Analysis" }));
    await waitFor(() => expect(api.analyzeMessage).toHaveBeenCalledWith("Please share your bank OTP"));
    expect(await screen.findByText("This is a test response from the mocked API.")).toBeInTheDocument();
    expect(screen.getByText("AI can make mistakes. Verify important information independently.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Download report" })).toBeInTheDocument();
    expect(screen.getByText("Technical details").closest("details")).not.toHaveAttribute("open");

    fireEvent.click(screen.getByRole("button", { name: "VEDVIQ AI home" }));
    fireEvent.click(await screen.findByRole("button", { name: /Web address/ }));
    fireEvent.change(screen.getByLabelText("Paste the full web address"), { target: { value: "https://example.test/login" } });
    fireEvent.click(screen.getByRole("button", { name: "Inspect URL Safely" }));
    await waitFor(() => expect(api.analyzeUrl).toHaveBeenCalledWith("https://example.test/login"));

    fireEvent.click(screen.getByRole("button", { name: "VEDVIQ AI home" }));
    fireEvent.click(await screen.findByRole("button", { name: "Screenshot" }));
    const image = new File(["image"], "message.png", { type: "image/png" });
    fireEvent.change(screen.getByLabelText(/Choose a screenshot/), { target: { files: [image] } });
    fireEvent.click(screen.getByRole("button", { name: "Extract & Analyze Screenshot" }));
    await waitFor(() => expect(api.analyzeOcr).toHaveBeenCalledWith(image, ""));
  });

  it("shows backend analytics and recent records on the dashboard", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Dashboard" }));
    expect(await screen.findByText("Reviews saved", {}, { timeout: 3000 })).toBeInTheDocument();
    expect(screen.getByText("Reviews over time")).toBeInTheDocument();
    expect(screen.getByText("Risk level distribution")).toBeInTheDocument();
    expect(screen.getAllByText("Credential Theft").length).toBeGreaterThan(0);
    expect(screen.getByText(/Counts and charts below come from saved review records/)).toBeInTheDocument();
    expect(api.getDashboard).toHaveBeenCalled();
  });

  it("switches the complete workspace theme both ways and restores the saved choice", async () => {
    const firstMount = render(<App />);
    expect(await screen.findByRole("heading", { name: "Your dashboard" })).toBeInTheDocument();
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: "Switch to light theme" }));
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe("light"));
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(window.localStorage.getItem("scamsathi-theme")).toBe("light");
    expect(screen.getByRole("button", { name: "Switch to dark theme" })).toHaveAttribute("aria-pressed", "false");

    fireEvent.click(screen.getByRole("button", { name: "Message Scan" }));
    expect(await screen.findByRole("heading", { name: "Message Scan" })).toBeInTheDocument();
    expect(document.documentElement.dataset.theme).toBe("light");
    fireEvent.click(screen.getByRole("button", { name: "AI Assistant" }));
    expect(await screen.findByRole("heading", { name: "Ask before you act." })).toBeInTheDocument();
    expect(document.documentElement.dataset.theme).toBe("light");
    fireEvent.click(screen.getByRole("button", { name: "Switch to dark theme" }));
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe("dark"));
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(window.localStorage.getItem("scamsathi-theme")).toBe("dark");

    fireEvent.click(screen.getByRole("button", { name: "System Status" }));
    expect(await screen.findByRole("heading", { name: "Service & privacy" })).toBeInTheDocument();
    expect(screen.getByText("Important Notice: VEDVIQ AI can make mistakes. AI-generated results may be inaccurate or incomplete. Always verify important information independently before taking action. No scan can guarantee that a link, message, or website is completely safe.")).toBeInTheDocument();
    expect(document.documentElement.dataset.theme).toBe("dark");

    firstMount.unmount();
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Your dashboard" })).toBeInTheDocument();
    expect(document.documentElement.dataset.theme).toBe("dark");
  });

  it("keeps long category names and zero values in the chart's accessible data", async () => {
    vi.mocked(api.getDashboard).mockResolvedValue({
      ...analytics,
      category_breakdown: [{ category: "Unexpected cross-border account verification request", count: 0 }],
    });
    render(<App />);
    expect(await screen.findByText("Unexpected cross-border account verification request: 0 saved reviews")).toBeInTheDocument();
  });

  it("shows an honest empty state when the API has no category breakdown", async () => {
    vi.mocked(api.getDashboard).mockResolvedValue({ ...analytics, category_breakdown: [] });
    render(<App />);
    expect(await screen.findByText("Category breakdown is not available yet.")).toBeInTheDocument();
  });

  it("filters and expands Awareness guides and scores quiz answers", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Awareness" }));
    const search = screen.getByRole("textbox", { name: "Search scam guides" });
    fireEvent.change(search, { target: { value: "QR code" } });
    expect(screen.getByText("UPI Payment & Collect Request Fraud")).toBeInTheDocument();
    expect(screen.queryByText("Fake Customer Care & Remote Access (AnyDesk) Fraud")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /UPI Payment & Collect Request Fraud/ }));
    expect(screen.getByText("Red flag warning signs")).toBeInTheDocument();
    fireEvent.change(search, { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: /Do not share it; end the call/ }));
    expect(screen.getByText(/An OTP can authorize access or a transaction/)).toBeInTheDocument();
    expect(screen.getByText("Score: 1 correct · 1 answered")).toBeInTheDocument();
  });

  it("loads history and system status through their existing routes", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "History" }));
    expect(await screen.findByText("Review history")).toBeInTheDocument();
    expect(screen.getByText("Bank notice asking for an OTP")).toBeInTheDocument();
    fireEvent.change(screen.getByRole("textbox", { name: "Search review history" }), { target: { value: "no matching review" } });
    expect(screen.getByText("No reviews match these filters.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "System Status" }));
    expect(await screen.findByText("Service status")).toBeInTheDocument();
    expect(screen.getByText("Connected")).toBeInTheDocument();
  });

  it("keeps the status destination usable when the backend status request fails", async () => {
    vi.mocked(api.getSystemStatus).mockRejectedValueOnce(new Error("Status API is offline"));
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "System Status" }));
    expect(await screen.findByRole("heading", { name: "Service status is unavailable" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry status check" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "VEDVIQ AI home" })).toBeInTheDocument();
  });

  it("shows a retry state instead of an empty history when its request fails", async () => {
    vi.mocked(api.getHistory).mockRejectedValueOnce(new Error("History API is offline"));
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "History" }));
    expect(await screen.findByText(/Review history could not be loaded: History API is offline/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("survives repeated navigation between all app destinations", async () => {
    render(<App />);
    const destinations = ["Dashboard", "Message Scan", "URL Guard", "Screenshot OCR", "History", "Awareness", "System Status", "VEDVIQ AI home"];

    for (const destination of destinations) {
      fireEvent.click(screen.getByRole("button", { name: destination }));
      await waitFor(() => expect(document.querySelector(".app-shell main")?.textContent?.trim()).not.toBe(""));
    }

    fireEvent.click(screen.getByRole("button", { name: "Awareness" }));
    expect(screen.getByRole("heading", { name: "Learn to spot scams" })).toBeInTheDocument();
  });

  it("keeps the dedicated message, URL, and OCR screens reachable", () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Message Scan" }));
    expect(screen.getByRole("heading", { name: "Message Scan" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "URL Guard" }));
    expect(screen.getByRole("heading", { name: "URL Guard" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Screenshot OCR" }));
    expect(screen.getByRole("heading", { name: "Screenshot Scan" })).toBeInTheDocument();
  });

  it("shows honest local-model status, sends scanner analysis, and keeps reporting links available", async () => {
    vi.mocked(api.assistantChat).mockResolvedValueOnce({
      conversation_id: "conversation-1", assistant_status: "unavailable", assistant_reply: null,
      model: null, setup_instructions: ["ollama pull qwen2.5:3b"], analysis: report, stored_redacted: true,
    });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "AI Assistant" }));

    expect(await screen.findByRole("heading", { name: "Ask before you act." })).toBeInTheDocument();
    expect(screen.getByText("Local AI is not ready")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open official portal/ })).toHaveAttribute("href", "https://cybercrime.gov.in/");
    fireEvent.change(screen.getByLabelText("Message VEDVIQ AI"), { target: { value: "Please review this message" } });
    fireEvent.change(screen.getByLabelText("Analysis"), { target: { value: "message" } });
    fireEvent.change(screen.getByLabelText("Original suspicious message or URL to scan separately"), { target: { value: "Share your OTP to receive cashback" } });
    fireEvent.click(screen.getByRole("button", { name: "Send message" }));

    await waitFor(() => expect(api.assistantChat).toHaveBeenCalledWith(expect.objectContaining({ message: "Please review this message", analysis_type: "message", content_to_analyze: "Share your OTP to receive cashback" })));
    expect(await screen.findByText(/No generated answer was substituted/)).toBeInTheDocument();
    expect(screen.getByText("This is a test response from the mocked API.")).toBeInTheDocument();
  });

  it("keeps a credential safety question separate and labels its curated answer", async () => {
    vi.mocked(api.assistantChat).mockResolvedValueOnce({
      conversation_id: "conversation-1", assistant_status: "guidance", assistant_reply: null,
      model: null, setup_instructions: [], analysis: null, analysis_note: "No scan was run; chat text is kept separate from scan content.",
      safety_guidance: { title: "Protect private payment credentials", source: "curated_safety_rule", text: "Never tell anyone your UPI PIN or OTP. This question alone does not establish that a particular sender is fraudulent." },
      stored_redacted: true,
    });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "AI Assistant" }));
    await screen.findByRole("heading", { name: "Ask before you act." });
    fireEvent.click(screen.getByRole("button", { name: /Is it safe to share my UPI PIN or OTP/ }));

    await waitFor(() => expect(api.assistantChat).toHaveBeenCalledWith(expect.objectContaining({
      message: "Is it safe to share my UPI PIN or OTP with someone who asks?", analysis_type: "none",
    })));
    expect(await screen.findByText("Curated safety guidance · rule-based")).toBeInTheDocument();
    expect(screen.getByText(/This question alone does not establish that a particular sender is fraudulent/)).toBeInTheDocument();
  });

  it("renders assistant Markdown and copies a complete complaint draft in readable text", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    vi.mocked(api.assistantChat).mockResolvedValueOnce({
      conversation_id: "conversation-1", assistant_status: "ready",
      assistant_reply: "Draft for review only.\n\n### Email draft\nSubject: Unrecognized debit\n\nDear Bank Support,\nPlease review this transaction.\n\nRegards,\n[Your name]",
      model: "qwen2.5:3b", setup_instructions: [], analysis: null, stored_redacted: true,
    });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "AI Assistant" }));
    await screen.findByRole("heading", { name: "Ask before you act." });
    fireEvent.change(screen.getByLabelText("Message VEDVIQ AI"), { target: { value: "Help me draft an email" } });
    fireEvent.click(screen.getByRole("button", { name: "Send message" }));

    expect(await screen.findByRole("heading", { name: "Email draft" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Copy complete draft" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("Subject: Unrecognized debit\n\nDear Bank Support,\nPlease review this transaction.\n\nRegards,\n[Your name]"));
    expect(await screen.findByRole("button", { name: "Draft copied" })).toBeInTheDocument();
  });

  it("renders and copies a short Romanized Hinglish assistant response", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    vi.mocked(api.assistantChat).mockResolvedValueOnce({
      conversation_id: "conversation-1", assistant_status: "ready",
      assistant_reply: "Bhai, official bank app mein transaction details check karo. OTP kisi ko mat dena.",
      model: "qwen2.5:3b", setup_instructions: [], analysis: null, stored_redacted: true,
    });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "AI Assistant" }));
    await screen.findByRole("heading", { name: "Ask before you act." });
    fireEvent.change(screen.getByLabelText("Message VEDVIQ AI"), { target: { value: "bhai mere paise kat gye h account se kya karu" } });
    fireEvent.click(screen.getByRole("button", { name: "Send message" }));

    expect(await screen.findByText(/Bhai, official bank app/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Copy complete assistant response" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("Bhai, official bank app mein transaction details check karo. OTP kisi ko mat dena."));
    expect(await screen.findByRole("button", { name: "Assistant response copied" })).toBeInTheDocument();
  });

  it("retries a timed-out assistant request without adding a duplicate user message", async () => {
    vi.mocked(api.assistantChat)
      .mockResolvedValueOnce({
        conversation_id: "conversation-1", assistant_status: "timeout", assistant_reply: null,
        model: null, setup_instructions: [], analysis: null, stored_redacted: true,
      })
      .mockResolvedValueOnce({
        conversation_id: "conversation-1", assistant_status: "ready", assistant_reply: "Verify through your bank's official app.",
        model: "qwen2.5:3b", setup_instructions: [], analysis: null, stored_redacted: true,
      });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "AI Assistant" }));
    await screen.findByRole("heading", { name: "Ask before you act." });
    fireEvent.change(screen.getByLabelText("Message VEDVIQ AI"), { target: { value: "How does device fingerprinting identify a malicious login?" } });
    fireEvent.click(screen.getByRole("button", { name: "Send message" }));
    await screen.findByText(/The local model timed out/);
    const firstPayload = vi.mocked(api.assistantChat).mock.calls[0][0];
    expect(firstPayload.language_hint).toBeUndefined();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    expect(await screen.findByText("Verify through your bank's official app.")).toBeInTheDocument();
    const retryPayload = vi.mocked(api.assistantChat).mock.calls[1][0];
    expect(retryPayload.client_request_id).toBe(firstPayload.client_request_id);
    expect(document.querySelectorAll(".assistant-message.is-user")).toHaveLength(1);
  });

  it("connects screenshot OCR from the Assistant page to the existing OCR endpoint", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "AI Assistant" }));
    await screen.findByRole("heading", { name: "Ask before you act." });
    fireEvent.click(screen.getByText("Check a screenshot with OCR"));
    const image = new File(["image"], "alert.png", { type: "image/png" });
    fireEvent.change(screen.getByLabelText("Choose screenshot"), { target: { files: [image] } });
    fireEvent.click(screen.getByRole("button", { name: "Read and review image" }));

    await waitFor(() => expect(api.analyzeOcr).toHaveBeenCalledWith(image, ""));
    expect(await screen.findByText(/saved to existing scan history/i)).toBeInTheDocument();
  });
});
