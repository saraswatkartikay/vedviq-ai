import React, { lazy, Suspense, useEffect, useLayoutEffect, useRef, useState } from "react";
import {
  ShieldAlert,
  MessageSquareWarning,
  Globe,
  Image as ImageIcon,
  LayoutDashboard,
  History,
  BookOpen,
  Settings,
  Download,
  Trash2,
  AlertTriangle,
  CheckCircle2,
  Sun,
  Moon,
  ArrowRight,
  Cpu,
  Search,
  ChevronDown,
  ArrowUpRight,
  Menu,
  X,
  RotateCcw,
  Info,
  Bot,
} from "lucide-react";
import { api } from "./services/api";
import { RiskBadge, RISK_COLORS } from "./components/ScanVisuals";
import CyberBootIntro, { INTRO_SEEN_KEY } from "./components/CyberBootIntro";

const LazyDashboardScreen = lazy(() => import("./components/DashboardScreen"));
const LazyReportScreen = lazy(() => import("./components/ReportScreen"));
const LazyAssistantScreen = lazy(() => import("./components/AssistantScreen"));
import {
  AnalysisResult,
  DashboardAnalytics,
  SystemStatusResponse,
} from "./types/api";

type ScreenId =
  | "dashboard"
  | "message"
  | "url"
  | "ocr"
  | "history"
  | "report"
  | "awareness"
  | "assistant"
  | "settings";

const THEME_STORAGE_KEY = "scamsathi-theme";

function getInitialTheme() {
  try {
    const savedTheme = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (savedTheme === "light" || savedTheme === "dark") return savedTheme === "dark";
  } catch {
    // Use the operating-system preference when storage is unavailable.
  }
  return !window.matchMedia?.("(prefers-color-scheme: light)").matches;
}

function scanTypeLabel(scanType: string) {
  if (scanType === "url") return "Web address";
  if (scanType === "ocr") return "Screenshot";
  return "Message";
}

function ScanProgress() {
  return <div className="scan-progress" role="status" aria-live="polite">
    <div className="scan-radar" aria-hidden="true"><span className="scan-radar-sweep" /><span className="scan-radar-dot" /></div>
    <div className="min-w-0 flex-1"><p className="text-sm font-semibold text-white">Review in progress</p><p className="mt-1 text-xs text-slate-400">We’ll show the findings as soon as the review is complete.</p><div className="scan-progress-track"><span /></div></div>
    <span className="hidden shrink-0 text-[10px] font-semibold uppercase tracking-[.14em] text-violet-200 sm:block">Working</span>
  </div>;
}

const SAMPLE_MESSAGES = [
  {
    label: "UPI Collect / PIN Scam (Hinglish)",
    text: "Paise prapt karne ke liye QR code scan karein aur apna UPI PIN daale. Rs 15,000 cashback turant credit hoga.",
  },
  {
    label: "SBI KYC Phishing Alert",
    text: "Dear Customer your SBI YONO account will be blocked tonight. Update PAN KYC immediately at http://sbi-kyc-update.xyz and share OTP.",
  },
  {
    label: "Digital Arrest / Fake CBI Scam",
    text: "This is CBI Officer Vikram. A FedEx parcel in your Aadhaar name contained illegal contraband. Join Skype for Digital Arrest interrogation immediately.",
  },
  {
    label: "Benign College Message",
    text: "Hey Kartikay, are we still meeting at the library at 4 PM today to revise discrete mathematics proofs?",
  },
];

const AWARENESS_GUIDES = [
  {
    title: "UPI Payment & Collect Request Fraud",
    category: "Financial Fraud",
    warningSigns: [
      "Caller asks you to scan a QR code or approve a Collect Request to 'receive' a refund or OLX payment.",
      "Prompts asking you to enter your 4 or 6-digit UPI PIN to claim cashback.",
    ],
    protection: [
      "A UPI PIN is ONLY entered when money leaves your bank account. You NEVER need a PIN to receive money.",
      "Verify credit notifications inside your bank statement rather than trusting SMS lookalikes.",
    ],
  },
  {
    title: "'Digital Arrest' & Law Enforcement Impersonation",
    category: "Extortion Scam",
    warningSigns: [
      "Automated call claiming TRAI is disconnecting your mobile numbers or Customs seized a FedEx parcel with drugs/passports.",
      "Video calls on WhatsApp/Skype showing a fake police station demanding you stay on camera under 'Digital Arrest' and transfer funds to an 'RBI verification account'.",
    ],
    protection: [
      "Indian Police, CBI, ED, Customs, and Judges NEVER conduct interrogations or 'Digital Arrests' via WhatsApp or Skype video calls.",
      "Hang up immediately and report the number on cybercrime.gov.in or call 1930.",
    ],
  },
  {
    title: "Telegram Part-Time Task & Prepaid Job Scams",
    category: "Job & Investment Fraud",
    warningSigns: [
      "WhatsApp messages offering Rs 3,000–8,000 daily for liking YouTube videos or rating Google Maps locations.",
      "Initial small payouts of Rs 150–300 followed by mandatory 'Prepaid VIP Crypto/Merchant Tasks' requiring you to deposit money first.",
    ],
    protection: [
      "Never pay money to earn salary or unlock 'task commissions'.",
      "Once you deposit larger amounts, scammers freeze the fake dashboard and demand more 'tax fees'.",
    ],
  },
  {
    title: "Fake Customer Care & Remote Access (AnyDesk) Fraud",
    category: "Credential & OTP Theft",
    warningSigns: [
      "Searching customer care numbers via random web posts or social media comments instead of official apps.",
      "Support agent asks you to install AnyDesk, TeamViewer, QuickSupport, or an `.apk` file sent on WhatsApp.",
    ],
    protection: [
      "Never install screen-sharing apps or unknown `.apk` files at the request of a caller—they allow scammers to read your banking OTPs live.",
    ],
  },
];

const AWARENESS_QUIZ = [
  {
    question: "A caller says you must share an OTP to stop a bank account block. What should you do?",
    answers: ["Share it after checking the caller knows your name", "Do not share it; end the call and contact the bank through its official app or number", "Forward it to a family member to verify"],
    correct: 1,
    explanation: "An OTP can authorize access or a transaction. Keep it private and contact the bank through a channel you find independently.",
  },
  {
    question: "A buyer asks you to scan a QR code and enter your UPI PIN to receive money. What is the safer choice?",
    answers: ["Decline; a UPI PIN authorizes a payment, not receiving money", "Proceed if the QR code has the buyer’s name", "Enter only half of the PIN"],
    correct: 0,
    explanation: "A UPI PIN is used to authorize money leaving your account. Check incoming payments in your bank or UPI app instead.",
  },
  {
    question: "A message threatens arrest unless you stay on a video call and transfer funds. What should you do?",
    answers: ["Stay on the call while asking for an ID card", "Transfer a small amount to prove cooperation", "End the call and verify through an official agency contact you find yourself"],
    correct: 2,
    explanation: "Threats, secrecy, and pressure to transfer money are serious warning signs. Do not send funds; verify independently and report the contact.",
  },
  {
    question: "You receive a delivery message asking you to install an APK to reschedule a parcel. What is safest?",
    answers: ["Install it if the logo looks familiar", "Avoid the attachment and check delivery details through the courier’s official website or app", "Forward it to the delivery agent"],
    correct: 1,
    explanation: "Unexpected APK files can expose your device and accounts. Use an official app or a web address you enter yourself.",
  },
  {
    question: "A caller claiming to be support asks you to install a screen-sharing app. What should you do?",
    answers: ["Decline, end the call, and contact support through an official channel", "Install it but hide your banking app", "Share the screen only after giving your name"],
    correct: 0,
    explanation: "Screen sharing can expose private information and one-time codes. A legitimate support request should be verified independently.",
  },
];

export function App() {
  const appShellRef = useRef<HTMLDivElement>(null);
  const [showIntro, setShowIntro] = useState(() => {
    try {
      return window.sessionStorage.getItem(INTRO_SEEN_KEY) !== "true";
    } catch {
      return false;
    }
  });
  const [screen, setScreen] = useState<ScreenId>("dashboard");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [headerScrolled, setHeaderScrolled] = useState(false);
  const [darkMode, setDarkMode] = useState(getInitialTheme);
  const [activeReport, setActiveReport] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);

  // Inputs
  const [msgText, setMsgText] = useState("");
  const [urlInput, setUrlInput] = useState("");
  const [ocrFile, setOcrFile] = useState<File | null>(null);
  const [ocrManualText, setOcrManualText] = useState("");

  // Data stores
  const [dashboard, setDashboard] = useState<DashboardAnalytics | null>(null);
  const [dashboardUnavailable, setDashboardUnavailable] = useState(false);
  const [historyList, setHistoryList] = useState<AnalysisResult[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [historySearch, setHistorySearch] = useState("");
  const [historyType, setHistoryType] = useState("all");
  const [sysStatus, setSysStatus] = useState<SystemStatusResponse | null>(null);
  const [statusLoading, setStatusLoading] = useState(false);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [guideSearch, setGuideSearch] = useState("");
  const [guideCategory, setGuideCategory] = useState("All topics");
  const [openGuide, setOpenGuide] = useState<string | null>(null);
  const [quizAnswer, setQuizAnswer] = useState<number | null>(null);
  const [quizQuestion, setQuizQuestion] = useState(0);
  const [quizScore, setQuizScore] = useState(0);
  const categories = ["All topics", ...Array.from(new Set(AWARENESS_GUIDES.map((guide) => guide.category)))];
  const filteredGuides = AWARENESS_GUIDES.filter((guide) =>
    (guideCategory === "All topics" || guide.category === guideCategory) &&
    `${guide.title} ${guide.category} ${guide.warningSigns.join(" ")} ${guide.protection.join(" ")}`.toLowerCase().includes(guideSearch.toLowerCase())
  );
  const filteredHistory = historyList.filter((item) =>
    (historyType === "all" || item.scan_type === historyType) &&
    `${item.scam_category} ${item.redacted_preview} ${item.scan_id}`.toLowerCase().includes(historySearch.toLowerCase())
  );

  useLayoutEffect(() => {
    const appShell = appShellRef.current;
    if (!appShell) return;
    if (showIntro) appShell.setAttribute("inert", "");
    else appShell.removeAttribute("inert");
  }, [showIntro]);

  const completeIntro = () => {
    try {
      window.sessionStorage.setItem(INTRO_SEEN_KEY, "true");
    } catch {
      // The app remains usable when storage is unavailable.
    }
    setScreen("dashboard");
    setShowIntro(false);
    window.setTimeout(() => appShellRef.current?.querySelector<HTMLElement>("#main-content")?.focus({ preventScroll: true }), 0);
  };

  const replayIntro = () => {
    try {
      window.sessionStorage.removeItem(INTRO_SEEN_KEY);
    } catch {
      // The intro can still be replayed for the current mount.
    }
    setShowIntro(true);
    setMobileMenuOpen(false);
  };

  const toggleTheme = () => {
    const nextTheme = darkMode ? "light" : "dark";
    setDarkMode(nextTheme === "dark");
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
    } catch {
      // The theme still updates for this session when storage is disabled.
    }
  };

  useEffect(() => {
    const root = document.documentElement;
    const theme = darkMode ? "dark" : "light";
    root.dataset.theme = theme;
    root.classList.toggle("dark", darkMode);
    const themeColor = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
    themeColor?.setAttribute("content", darkMode ? "#191d1c" : "#f2f5f1");
  }, [darkMode]);

  useEffect(() => {
    const updateHeader = () => setHeaderScrolled(window.scrollY > 12);
    updateHeader();
    window.addEventListener("scroll", updateHeader, { passive: true });
    return () => window.removeEventListener("scroll", updateHeader);
  }, []);

  useEffect(() => {
    const main = document.querySelector(".app-shell main");
    if (!main || !("IntersectionObserver" in window) || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const targets = main.querySelectorAll<HTMLElement>(
      ".surface-panel, .guide-card, main > .screen-enter > section, main > .screen-enter > div > section",
    );
    if (!targets.length) return;

    const shell = main.closest(".app-shell");
    shell?.classList.add("motion-ready");
    const observer = new IntersectionObserver((entries, activeObserver) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          activeObserver.unobserve(entry.target);
        }
      });
    }, { threshold: 0.08, rootMargin: "0px 0px -36px 0px" });

    targets.forEach((target) => {
      target.classList.add("scroll-reveal");
      observer.observe(target);
    });

    return () => observer.disconnect();
  }, [screen]);

  useEffect(() => {
    setErrorBanner(null);
    let isCurrentScreen = true;
    if (screen === "dashboard") {
      setDashboardUnavailable(false);
      api.getDashboard().then((data) => { if (isCurrentScreen) { setDashboard(data); setDashboardUnavailable(false); } }).catch((e) => { if (isCurrentScreen) { setDashboardUnavailable(true); setErrorBanner(e.message); } });
    } else if (screen === "history") {
      setHistoryLoading(true);
      setHistoryError(null);
      api.getHistory().then((data) => { if (isCurrentScreen) { setHistoryList(data); setHistoryError(null); } }).catch((e) => { if (isCurrentScreen) { setHistoryError(e.message); setErrorBanner(e.message); } }).finally(() => { if (isCurrentScreen) setHistoryLoading(false); });
    } else if (screen === "settings") {
      setStatusLoading(true);
      setStatusError(null);
      api.getSystemStatus().then((data) => { if (isCurrentScreen) { setSysStatus(data); setStatusError(null); } }).catch((e) => { if (isCurrentScreen) { setStatusError(e.message); setErrorBanner(e.message); } }).finally(() => { if (isCurrentScreen) setStatusLoading(false); });
    }
    return () => { isCurrentScreen = false; };
  }, [screen]);

  const retrySystemStatus = () => {
    setStatusLoading(true);
    setStatusError(null);
    api.getSystemStatus()
      .then((data) => { setSysStatus(data); setStatusError(null); })
      .catch((error) => { setStatusError(error.message); setErrorBanner(error.message); })
      .finally(() => setStatusLoading(false));
  };

  const retryHistory = () => {
    setHistoryLoading(true);
    setHistoryError(null);
    api.getHistory()
      .then((data) => { setHistoryList(data); setHistoryError(null); })
      .catch((error) => { setHistoryError(error.message); setErrorBanner(error.message); })
      .finally(() => setHistoryLoading(false));
  };

  const handleAnalyzeMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!msgText.trim()) return;
    setLoading(true);
    setErrorBanner(null);
    try {
      const res = await api.analyzeMessage(msgText);
      setActiveReport(res);
      setScreen("report");
    } catch (err: any) {
      setErrorBanner(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyzeUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim()) return;
    setLoading(true);
    setErrorBanner(null);
    try {
      const res = await api.analyzeUrl(urlInput);
      setActiveReport(res);
      setScreen("report");
    } catch (err: any) {
      setErrorBanner(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyzeOcr = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ocrFile) {
      setErrorBanner("Please select a PNG, JPEG, or WEBP screenshot first.");
      return;
    }
    setLoading(true);
    setErrorBanner(null);
    try {
      const res = await api.analyzeOcr(ocrFile, ocrManualText);
      setActiveReport(res);
      setScreen("report");
    } catch (err: any) {
      setErrorBanner(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteRecord = async (scanId: number) => {
    try {
      await api.deleteScan(scanId);
      setHistoryList((prev) => prev.filter((item) => item.scan_id !== scanId));
      if (activeReport?.scan_id === scanId) {
        setActiveReport(null);
      }
    } catch (err: any) {
      setErrorBanner(err.message);
    }
  };

  const downloadReportPdf = async (report: AnalysisResult) => {
    const { default: jsPDF } = await import("jspdf");
    const doc = new jsPDF({ unit: "mm", format: "a4" });
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 16;
    const contentWidth = pageWidth - margin * 2;
    const footerY = pageHeight - 10;
    let y = 48;
    let page = 1;

    const riskColor: Record<string, [number, number, number]> = {
      Low: [16, 185, 129],
      Medium: [245, 158, 11],
      High: [249, 115, 22],
      Critical: [239, 68, 68],
    };
    const risk = riskColor[report.risk_level] || riskColor.Medium;
    const safe = (value: unknown, fallback = "Not available") => {
      if (value === null || value === undefined || value === "") return fallback;
      return String(value);
    };

    const drawPageHeader = (continuation = false) => {
      doc.setFillColor(9, 15, 32);
      doc.rect(0, 0, pageWidth, 34, "F");
      doc.setFillColor(190, 18, 60);
      doc.rect(0, 0, 4, 34, "F");
      doc.setTextColor(255, 255, 255);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(19);
      doc.text("VEDVIQ AI", margin, 15);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      doc.setTextColor(203, 213, 225);
      doc.text("SCAM DETECTION AND SECURITY ASSESSMENT", margin, 22);
      doc.setFontSize(9);
      doc.text(`REPORT #${report.scan_id}  |  ${safe(report.scan_type, "SCAN").toUpperCase()}`, pageWidth - margin, 15, { align: "right" });
      if (continuation) {
        doc.setTextColor(148, 163, 184);
        doc.text("CONTINUED", pageWidth - margin, 22, { align: "right" });
      }
    };

    const addPageIfNeeded = (needed: number) => {
      if (y + needed > pageHeight - 19) {
        doc.setDrawColor(226, 232, 240);
        doc.line(margin, footerY - 3, pageWidth - margin, footerY - 3);
        doc.addPage();
        page += 1;
        drawPageHeader(true);
        y = 44;
      }
    };

    const sectionTitle = (title: string, subtitle?: string) => {
      addPageIfNeeded(subtitle ? 17 : 12);
      doc.setFillColor(190, 18, 60);
      doc.roundedRect(margin, y - 5, 2, subtitle ? 12 : 9, 1, 1, "F");
      doc.setFont("helvetica", "bold");
      doc.setFontSize(12);
      doc.setTextColor(15, 23, 42);
      doc.text(title, margin + 5, y + 1);
      y += 7;
      if (subtitle) {
        doc.setFont("helvetica", "normal");
        doc.setFontSize(8.5);
        doc.setTextColor(100, 116, 139);
        doc.text(subtitle, margin + 5, y);
        y += 5;
      }
      y += 2;
    };

    const field = (label: string, value: unknown, opts: { color?: [number, number, number]; gap?: number; bold?: boolean } = {}) => {
      const valueText = safe(value);
      const labelWidth = 38;
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(71, 85, 105);
      const valueLines = doc.splitTextToSize(valueText, contentWidth - labelWidth - 3);
      const lineHeight = 4.5;
      const blockHeight = Math.max(5, valueLines.length * lineHeight);
      addPageIfNeeded(blockHeight + (opts.gap ?? 2));
      doc.text(label, margin + 2, y);
      doc.setFont("helvetica", opts.bold ? "bold" : "normal");
      doc.setTextColor(...(opts.color || [30, 41, 59]));
      doc.text(valueLines, margin + labelWidth, y);
      y += blockHeight + (opts.gap ?? 2);
    };

    const card = (title: string, body: string, accent: [number, number, number] = [190, 18, 60]) => {
      const lines = doc.splitTextToSize(body, contentWidth - 10);
      const h = 12 + lines.length * 4.5;
      addPageIfNeeded(h + 4);
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, y - 3, contentWidth, h, 2, 2, "FD");
      doc.setFillColor(...accent);
      doc.roundedRect(margin, y - 3, 2, h, 1, 1, "F");
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(30, 41, 59);
      doc.text(title, margin + 6, y + 3);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8.5);
      doc.setTextColor(71, 85, 105);
      doc.text(lines, margin + 6, y + 9);
      y += h + 5;
    };

    drawPageHeader();

    // Risk summary panel
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(margin, 40, contentWidth, 36, 3, 3, "FD");
    doc.setFillColor(...risk);
    doc.roundedRect(margin, 40, 3, 36, 1, 1, "F");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);
    doc.setTextColor(100, 116, 139);
    doc.text("OVERALL RISK", margin + 8, 48);
    doc.setTextColor(...risk);
    doc.setFontSize(16);
    doc.text(safe(report.risk_level, "Unknown").toUpperCase(), margin + 8, 57);
    doc.setFontSize(10);
    doc.text(`${safe(report.risk_score, "N/A")}/100`, margin + 8, 66);
    doc.setDrawColor(226, 232, 240);
    doc.line(margin + 49, 45, margin + 49, 71);
    doc.setTextColor(30, 41, 59);
    doc.setFontSize(10);
    doc.text(doc.splitTextToSize(safe(report.scam_category, "Unclassified scan"), contentWidth - 65), margin + 56, 49);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.5);
    doc.setTextColor(71, 85, 105);
    doc.text(doc.splitTextToSize(safe(report.summary_explanation), contentWidth - 65), margin + 56, 56);
    y = 85;

    sectionTitle("1. Evidence Assessment", "Matched signals and privacy-safe preview");
    field("Scan type", safe(report.scan_type).toUpperCase());
    field("Category", report.scam_category);
    field("Risk level", report.risk_level, { color: risk, bold: true });
    field("Evidence score", `${safe(report.risk_score, "N/A")}/100`, { bold: true });
    card("Redacted preview", safe(report.redacted_preview, "No preview available."), [225, 29, 72]);

    sectionTitle("2. Security Rule Indicators", "Deterministic signals matched against the submitted content");
    if (!report.rule_indicators?.length) {
      card("No explicit rule matched", "No known deterministic security signature was identified. This does not prove the content is safe.", [16, 185, 129]);
    } else {
      report.rule_indicators.forEach((item, index) => {
        const severity = safe(item.severity, "unknown").toUpperCase();
        card(`${index + 1}. ${safe(item.name)}  |  ${severity}`, `${safe(item.description)}${item.matched_text ? `\nMatched text: ${item.matched_text}` : ""}`, severity === "HIGH" || severity === "CRITICAL" ? [239, 68, 68] : severity === "MEDIUM" ? [245, 158, 11] : [225, 29, 72]);
      });
    }

    sectionTitle("3. Development Classifier", "Uncalibrated output is excluded from the evidence score");
    field("Pipeline status", report.ml_assessment?.status);
    field("Predicted class", report.ml_assessment?.predicted_label, { bold: true });
    field("Classifier probability", "Not displayed: this development estimate is uncalibrated.");
    field("Top TF-IDF signals", report.ml_assessment?.top_features?.length ? report.ml_assessment.top_features.join(", ") : "No feature explanation returned by the model.");
    field("Model note", report.ml_assessment?.note);

    sectionTitle("4. Threat Intelligence", "External reputation checks, when configured and available");
    field("Provider", report.threat_intel?.provider);
    field("Lookup mode", report.threat_intel?.mode);
    card("Lookup details", safe(report.threat_intel?.details, "No additional threat-intelligence details returned."), [225, 29, 72]);

    sectionTitle("5. Recommended Actions", "Practical next steps based on this scan");
    if (report.recommended_actions?.length) {
      report.recommended_actions.forEach((action, index) => card(`Action ${index + 1}`, safe(action), [16, 185, 129]));
    } else {
      card("Stay cautious", "Verify the sender through an independently obtained official channel before taking action.", [16, 185, 129]);
    }
    card("Important limitations", safe(report.limitations_note, "This assessment is not a guarantee. Low risk does not mean risk-free, and false positives or false negatives are possible."), [245, 158, 11]);

    const totalPages = doc.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i);
      doc.setDrawColor(226, 232, 240);
      doc.line(margin, pageHeight - 15, pageWidth - margin, pageHeight - 15);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(7.5);
      doc.setTextColor(100, 116, 139);
      doc.text("VEDVIQ AI | Privacy-conscious scan report | Independently verify findings", margin, pageHeight - 9);
      doc.text(`Page ${i} of ${totalPages}`, pageWidth - margin, pageHeight - 9, { align: "right" });
    }
    doc.save(`vedviq-ai-report-${report.scan_id}.pdf`);
  };

  return (
    <>
    <div ref={appShellRef} aria-hidden={showIntro || undefined} className={`app-shell theme-${darkMode ? "dark" : "light"} min-h-screen flex flex-col`}>
      {/* Top Navigation */}
      <header className={`site-header sticky top-0 z-30 border-b backdrop-blur-xl ${headerScrolled ? "is-scrolled" : ""}`}>
        <div className="mx-auto flex min-h-16 max-w-7xl flex-wrap items-center justify-between px-4">
          <button
            onClick={() => { setScreen("dashboard"); setMobileMenuOpen(false); }}
            aria-label="VEDVIQ AI home"
            className="flex items-center gap-2.5 rounded-lg text-left focus:outline-none"
          >
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-violet-500 to-cyan-400 flex items-center justify-center shadow-lg shadow-violet-600/20">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div>
              <span className="font-bold tracking-tight text-lg text-white">VEDVIQ AI</span>
              <span className="hidden sm:inline-block ml-2 text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-violet-500/15 text-violet-200 border border-violet-500/30">
                Digital safety
              </span>
            </div>
          </button>

          <div className="flex items-center gap-1 lg:order-2">
            <button
              aria-label="Replay intro"
              title="Replay intro"
              onClick={replayIntro}
              className="rounded-xl p-2.5 text-slate-300 transition-colors hover:bg-slate-800 hover:text-white"
            >
              <RotateCcw className="h-4 w-4" />
            </button>
            <button
              type="button"
              aria-label={darkMode ? "Switch to light theme" : "Switch to dark theme"}
              title={darkMode ? "Switch to light theme" : "Switch to dark theme"}
              aria-pressed={darkMode}
              onClick={toggleTheme}
              className="rounded-xl p-2.5 text-slate-300 transition-colors hover:bg-slate-800 hover:text-white"
            >
              {darkMode ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
            <button
              aria-label={mobileMenuOpen ? "Close navigation menu" : "Open navigation menu"}
              aria-expanded={mobileMenuOpen}
              aria-controls="primary-navigation"
              onClick={() => setMobileMenuOpen((open) => !open)}
              className="rounded-xl p-2.5 text-slate-200 transition-colors hover:bg-slate-800 lg:hidden"
            >
              {mobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
          </div>

          <nav id="primary-navigation" aria-label="Primary navigation" className={`${mobileMenuOpen ? "flex" : "hidden"} mobile-navigation order-3 w-full flex-col gap-1 border-t border-slate-800 py-3 lg:order-1 lg:flex lg:w-auto lg:flex-row lg:items-center lg:gap-1 lg:border-0 lg:py-0`}>
            {[
              { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
              { id: "message", label: "Message Scan", icon: MessageSquareWarning },
              { id: "url", label: "URL Guard", icon: Globe },
              { id: "ocr", label: "Screenshot OCR", icon: ImageIcon },
              { id: "history", label: "History", icon: History },
              { id: "awareness", label: "Awareness", icon: BookOpen },
              { id: "assistant", label: "AI Assistant", icon: Bot },
              { id: "settings", label: "System Status", icon: Settings },
            ].map((item) => {
              const Icon = item.icon;
              const active = screen === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => { setScreen(item.id as ScreenId); setMobileMenuOpen(false); }}
                  aria-current={active ? "page" : undefined}
                  className={`flex w-full items-center gap-2.5 rounded-xl px-3 py-2.5 text-sm font-medium transition-colors lg:w-auto lg:gap-1.5 lg:px-2.5 lg:py-2 ${
                    active
                      ? "bg-violet-600 text-white shadow-sm"
                      : "text-slate-300 hover:bg-slate-800/80 hover:text-white"
                  }`}
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main id="main-content" tabIndex={-1} className="flex-1 max-w-7xl w-full mx-auto px-4 py-8">
        {errorBanner && (
          <div className="mb-6 p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
              <span className="text-sm">{errorBanner}</span>
            </div>
            <button onClick={() => setErrorBanner(null)} className="text-xs underline">
              Dismiss
            </button>
          </div>
        )}

        {loading && ["message", "url", "ocr"].includes(screen) && <ScanProgress />}

        {/* Message scanner */}
        {screen === "message" && (
          <div className="max-w-4xl mx-auto space-y-6">
            <div>
              <h1 className="text-2xl font-bold">Message Scan</h1>
              <p className="text-sm text-slate-400 mt-1">
                Review suspicious texts, WhatsApp messages, or emails in English, Hindi, or Hinglish.
                Do not paste real passwords or live OTPs.
              </p>
            </div>

            <div className="flex flex-wrap gap-2">
              {SAMPLE_MESSAGES.map((s, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => setMsgText(s.text)}
                  className="text-xs px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-red-500/50 text-slate-300"
                >
                  Try Sample: {s.label}
                </button>
              ))}
            </div>

            <form onSubmit={handleAnalyzeMessage} className="space-y-4">
              <label htmlFor="message-scan-input" className="block text-sm font-medium text-slate-200">Message or email to review</label>
              <textarea
                id="message-scan-input"
                rows={6}
                value={msgText}
                onChange={(e) => setMsgText(e.target.value)}
                placeholder="Paste suspicious SMS, WhatsApp message, or email text here..."
                className="w-full rounded-xl bg-slate-900 border border-slate-800 p-4 text-sm text-slate-100 focus:outline-none focus:border-red-500"
                required
              />
              <button
                type="submit"
                disabled={loading}
                className="px-6 py-2.5 rounded-xl bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white font-semibold text-sm"
              >
                {loading ? "Analyzing Patterns..." : "Run Explainable Scam Analysis"}
              </button>
            </form>
          </div>
        )}

        {/* 3. URL ANALYZER */}
        {screen === "url" && (
          <div className="max-w-4xl mx-auto space-y-6">
            <div>
              <h1 className="text-2xl font-bold">URL Guard</h1>
              <p className="text-sm text-slate-400 mt-1">
                Check for unusual web addresses and signs of impersonation without opening the link.
              </p>
            </div>

            <div className="flex flex-wrap gap-2">
              {[
                "http://sbi-kyc-verify.login.update.xyz/netbanking",
                "https://bit.ly/claim-25lakh-kbc",
                "https://onlinesbi.sbi",
                "http://127.0.0.1:8000/admin",
              ].map((u) => (
                <button
                  key={u}
                  type="button"
                  onClick={() => setUrlInput(u)}
                  className="text-xs font-mono px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-rose-500/50 text-slate-300"
                >
                  {u}
                </button>
              ))}
            </div>

            <form onSubmit={handleAnalyzeUrl} className="space-y-4">
              <label htmlFor="url-scan-input" className="block text-sm font-medium text-slate-200">Paste the full web address</label>
              <input
                id="url-scan-input"
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://example-bank-kyc-update.xyz/login"
                className="w-full rounded-xl bg-slate-900 border border-slate-800 p-4 text-sm font-mono text-slate-100 focus:outline-none focus:border-rose-500"
                required
              />
              <button
                type="submit"
                disabled={loading}
                className="px-6 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white font-semibold text-sm"
              >
                {loading ? "Inspecting URL..." : "Inspect URL Safely"}
              </button>
            </form>
          </div>
        )}

        {/* 4. SCREENSHOT OCR ANALYZER */}
        {screen === "ocr" && (
          <div className="max-w-4xl mx-auto space-y-6">
            <div>
              <h1 className="text-2xl font-bold">Screenshot Scan</h1>
              <p className="text-sm text-slate-400 mt-1">
                Upload a PNG, JPEG, or WEBP screenshot (up to 5 MB) to review the text it contains.
              </p>
            </div>

            <form onSubmit={handleAnalyzeOcr} className="space-y-5 p-6 rounded-xl border border-slate-800 bg-slate-900/60">
              <div>
                <label htmlFor="screenshot-file" className="block text-sm font-medium text-slate-300 mb-2">
                  Choose a screenshot (PNG, JPEG or WEBP)
                </label>
                <input
                  id="screenshot-file"
                  type="file"
                  accept="image/png,image/jpeg,image/webp"
                  onChange={(e) => setOcrFile(e.target.files?.[0] || null)}
                  className="block w-full text-sm text-slate-300 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-red-600 file:text-white hover:file:bg-red-500"
                />
              </div>

              <div>
                <label htmlFor="screenshot-text" className="block text-sm font-medium text-slate-300 mb-2">
                  Optional: add or correct text from the screenshot
                </label>
                <textarea
                  id="screenshot-text"
                  rows={3}
                  value={ocrManualText}
                  onChange={(e) => setOcrManualText(e.target.value)}
                  placeholder="Paste or correct the text from the screenshot here…"
                  className="w-full rounded-xl bg-slate-950 border border-slate-800 p-3 text-sm text-slate-100"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="px-6 py-2.5 rounded-xl bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white font-semibold text-sm"
              >
                {loading ? "Processing Screenshot..." : "Extract & Analyze Screenshot"}
              </button>
            </form>
          </div>
        )}

        {screen === "report" && (activeReport
          ? <Suspense fallback={<div role="status" className="py-16 text-center text-sm text-slate-400">Loading scan report…</div>}><LazyReportScreen report={activeReport} onDownload={downloadReportPdf} /></Suspense>
          : <div className="screen-enter empty-state rounded-2xl border border-slate-800 bg-slate-900/40 p-10 text-center"><h1 className="text-xl font-semibold text-white">No review is selected</h1><p className="mt-2 text-sm text-slate-400">Return to your dashboard or review history to open a saved report.</p><button onClick={() => setScreen("dashboard")} className="mt-5 rounded-xl bg-violet-600 px-4 py-2.5 text-sm font-semibold text-white">Back to dashboard</button></div>)}

        {screen === "dashboard" && <Suspense fallback={<div role="status" className="py-16 text-center text-sm text-slate-400">Loading your workspace…</div>}><LazyDashboardScreen dashboard={dashboard} unavailable={dashboardUnavailable} onRetry={() => api.getDashboard().then((data) => { setDashboard(data); setDashboardUnavailable(false); }).catch((error) => { setDashboardUnavailable(true); setErrorBanner(error.message); })} onNewScan={() => setScreen("message")} onOpenTool={setScreen} onOpenHistory={() => setScreen("history")} onOpenReport={(item) => { setActiveReport(item); setScreen("report"); }} /></Suspense>}

        {screen === "assistant" && <Suspense fallback={<div role="status" className="py-16 text-center text-sm text-slate-400">Opening the cyber safety assistant…</div>}><LazyAssistantScreen /></Suspense>}

        {/* 7. SCAN HISTORY */}
        {screen === "history" && (
          <div className="screen-enter space-y-6">
            <div>
              <p className="eyebrow">YOUR ACTIVITY</p><h1 className="text-2xl font-bold">Review history</h1>
              <p className="text-sm text-slate-400">Find previous checks, open a report, download it, or remove it from your history.</p>
            </div>

            <div className="history-filters"><label><Search aria-hidden="true" /><input value={historySearch} onChange={(event) => setHistorySearch(event.target.value)} aria-label="Search review history" placeholder="Search category, text, or ID" /></label><label className="history-type-label"><span>Type</span><select aria-label="Filter reviews by type" value={historyType} onChange={(event) => setHistoryType(event.target.value)}><option value="all">All reviews</option><option value="message">Messages</option><option value="url">Web addresses</option><option value="ocr">Screenshots</option></select></label></div>

            {historyLoading ? (
              <div role="status" className="empty-state rounded-xl border border-slate-800 bg-slate-900/40 p-10 text-center text-sm text-slate-400">Loading review history…</div>
            ) : historyList.length === 0 && historyError ? (
              <div className="empty-state rounded-xl border border-slate-800 bg-slate-900/40 p-10 text-center"><p className="text-sm text-slate-300">Review history could not be loaded: {historyError}</p><button onClick={retryHistory} className="mt-3 rounded-lg border border-slate-700 px-3 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-800">Try again</button></div>
            ) : historyList.length === 0 ? (
              <div className="p-10 rounded-xl border border-slate-800 bg-slate-900/40 text-center text-sm text-slate-400">
                No review history yet. Your saved checks will appear here.
              </div>
            ) : filteredHistory.length === 0 ? (
              <div className="p-10 rounded-xl border border-slate-800 bg-slate-900/40 text-center text-sm text-slate-400">No reviews match these filters.</div>
            ) : (
              <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/60">
                <div className="overflow-x-auto"><table className="w-full min-w-[760px] border-collapse text-left">
                  <thead><tr className="border-b border-slate-800 bg-slate-950/50 text-[10px] uppercase tracking-[.14em] text-slate-500"><th className="px-5 py-3 font-semibold">Scan</th><th className="px-4 py-3 font-semibold">Assessment</th><th className="px-4 py-3 font-semibold">Evidence score</th><th className="px-4 py-3 font-semibold">Redacted preview</th><th className="px-5 py-3 text-right font-semibold">Actions</th></tr></thead>
                  <tbody className="divide-y divide-slate-800/80">{filteredHistory.map((item) => (
                    <tr key={item.scan_id} className="history-row hover:bg-slate-800/35">
                      <td className="whitespace-nowrap px-5 py-4"><span className="block text-xs font-semibold text-slate-200">#{item.scan_id} · {scanTypeLabel(item.scan_type)}</span><time dateTime={item.created_at} className="mt-1 block text-[11px] text-slate-500">{new Date(item.created_at).toLocaleString()}</time></td>
                      <td className="px-4 py-4"><div className="flex flex-wrap items-center gap-2"><RiskBadge level={item.risk_level} /><span className="text-xs font-medium text-slate-200">{item.scam_category}</span></div></td>
                      <td className="whitespace-nowrap px-4 py-4"><span className="font-mono text-sm font-semibold" style={{ color: RISK_COLORS[item.risk_level] || "#cbd5e1" }}>{item.risk_score}<span className="ml-1 text-[10px] text-slate-500">/100</span></span></td>
                      <td className="max-w-[260px] truncate px-4 py-4 text-xs text-slate-400" title={item.redacted_preview}>{item.redacted_preview}</td>
                      <td className="whitespace-nowrap px-5 py-4"><div className="flex justify-end gap-2">
                        <button onClick={() => { setActiveReport(item); setScreen("report"); }} className="rounded-lg border border-slate-700 px-3 py-2 text-xs font-semibold text-slate-200 hover:border-red-400/50 hover:bg-red-500/10">View report</button>
                        <button aria-label={`Download PDF report for scan ${item.scan_id}`} onClick={() => downloadReportPdf(item)} className="rounded-lg border border-slate-700 p-2 text-slate-300 hover:border-rose-400/40 hover:text-rose-200" title="Download PDF Report"><Download className="h-4 w-4" /></button>
                        <button aria-label={`Delete scan ${item.scan_id}`} onClick={() => handleDeleteRecord(item.scan_id)} className="rounded-lg border border-rose-500/20 bg-rose-500/5 p-2 text-rose-300 hover:bg-rose-500/15" title="Delete Record"><Trash2 className="h-4 w-4" /></button>
                      </div></td>
                    </tr>
                  ))}</tbody>
                </table></div>
              </div>
            )}
          </div>
        )}

        {/* 8. SCAM AWARENESS CENTER */}
        {screen === "awareness" && (
          <div className="awareness-view screen-enter">
            <div className="awareness-heading">
              <h1 className="text-2xl font-bold">Learn to spot scams</h1>
              <p className="text-sm text-slate-400 mt-1">
                Learn how to spot common cyber frauds targeting Indian students, families, and UPI users.
              </p>
            </div>

            <aside className="reporting-banner" aria-label="Report cybercrime in India"><div><span>NEED TO REPORT A CYBERCRIME?</span><strong>Call 1930 as soon as possible if money was lost.</strong></div><a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer">Go to the official reporting portal <ArrowUpRight aria-hidden="true" /></a></aside>

            <div className="awareness-controls">
              <label className="awareness-search"><Search aria-hidden="true" /><input aria-label="Search scam guides" value={guideSearch} onChange={(e) => setGuideSearch(e.target.value)} placeholder="Search signs, topics, or safety steps" /></label>
              <div className="awareness-category-filters" aria-label="Scam guide categories">{categories.map((category) => <button key={category} onClick={() => setGuideCategory(category)} aria-pressed={guideCategory === category} className={guideCategory === category ? "is-active" : ""}>{category}</button>)}</div>
            </div>
            <div className="awareness-guide-grid">
              {filteredGuides.map((guide) => (
                <article key={guide.title} className={`guide-card awareness-guide ${openGuide === guide.title ? "is-open" : ""}`}>
                  <button type="button" aria-expanded={openGuide === guide.title} aria-controls={`guide-${categories.indexOf(guide.category)}-${AWARENESS_GUIDES.indexOf(guide)}`} onClick={() => setOpenGuide(openGuide === guide.title ? null : guide.title)} className="awareness-guide-trigger">
                    <div>
                    <span className="awareness-guide-category">
                      {guide.category}
                    </span>
                    <h2>{guide.title}</h2>
                    </div><ChevronDown className={`mt-2 h-5 w-5 shrink-0 text-rose-300 transition-transform ${openGuide === guide.title ? "rotate-180" : ""}`} />
                  </button>
                  <div id={`guide-${categories.indexOf(guide.category)}-${AWARENESS_GUIDES.indexOf(guide)}`} className={`awareness-guide-accordion ${openGuide === guide.title ? "is-expanded" : ""}`} aria-hidden={openGuide !== guide.title}>
                    <div className="awareness-guide-content">
                      <div className="awareness-guide-section is-warning">
                        <h3>Red flag warning signs</h3>
                        <ul>{guide.warningSigns.map((w, i) => (<li key={i}>{w}</li>))}</ul>
                      </div>
                      <div className="awareness-guide-section is-protection">
                        <h3>How to protect yourself</h3>
                        <ul>{guide.protection.map((p, i) => (<li key={i}>{p}</li>))}</ul>
                      </div>
                    </div>
                  </div>
                </article>
              ))}
            </div>
            {filteredGuides.length === 0 && <div className="awareness-empty">No guides match that search. Try a different keyword or category.</div>}
            <section className="awareness-resources">
              <div className="awareness-quiz-card">
                <div className="awareness-quiz-meta"><p>Quick knowledge check</p><span>Score: {quizScore} correct · {Math.min(AWARENESS_QUIZ.length, quizQuestion + (quizAnswer !== null ? 1 : 0))} answered</span></div>
                {quizQuestion < AWARENESS_QUIZ.length ? <>
                  <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-slate-800"><div className="h-full rounded-full bg-rose-400 transition-all" style={{width:`${((quizQuestion+(quizAnswer!==null?1:0))/AWARENESS_QUIZ.length)*100}%`}} /></div>
                  <p className="awareness-quiz-step">Question {quizQuestion+1} of {AWARENESS_QUIZ.length}</p>
                  <h2 className="awareness-quiz-question">{AWARENESS_QUIZ[quizQuestion].question}</h2>
                  <div className="awareness-quiz-answers">{AWARENESS_QUIZ[quizQuestion].answers.map((answer,i)=><button key={answer} disabled={quizAnswer!==null} onClick={()=>{setQuizAnswer(i);if(i===AWARENESS_QUIZ[quizQuestion].correct)setQuizScore((score)=>score+1);}} className={`awareness-quiz-answer ${quizAnswer===null?"is-unanswered":i===AWARENESS_QUIZ[quizQuestion].correct?"is-correct":quizAnswer===i?"is-incorrect":"is-muted"}`}>{answer}</button>)}</div>
                  {quizAnswer!==null&&<div role="status" className={`awareness-quiz-feedback ${quizAnswer===AWARENESS_QUIZ[quizQuestion].correct?"is-correct":"is-incorrect"}`}><strong>{quizAnswer===AWARENESS_QUIZ[quizQuestion].correct?"Correct. ":"Not quite. "}</strong>{AWARENESS_QUIZ[quizQuestion].explanation}</div>}
                  {quizAnswer!==null&&<button onClick={()=>{setQuizQuestion((q)=>q+1);setQuizAnswer(null);}} className="mt-4 rounded-lg bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-500">{quizQuestion===AWARENESS_QUIZ.length-1?"See score":"Next question"}<ArrowRight className="ml-1 inline h-4 w-4" /></button>}
                </> : <div className="mt-5 rounded-xl border border-slate-700 bg-slate-950/50 p-4"><p className="text-xl font-bold text-white">You scored {quizScore} out of {AWARENESS_QUIZ.length}</p><p className="mt-1 text-sm text-slate-400">{quizScore===AWARENESS_QUIZ.length?"Great work. Keep applying these checks when a message creates urgency.":"Review the guides above and try again to reinforce safer habits."}</p><button onClick={()=>{setQuizQuestion(0);setQuizAnswer(null);setQuizScore(0);}} className="mt-4 rounded-lg border border-slate-700 px-3 py-2 text-sm font-semibold text-slate-200 hover:bg-slate-800">Try again</button></div>}
              </div>
              <div className="awareness-help-card"><p>If money was lost</p><h2>Act quickly and preserve evidence.</h2><ol><li>Call India’s cybercrime helpline at <strong>1930</strong> as soon as possible.</li><li>Report online at <strong>cybercrime.gov.in</strong>.</li><li>Contact your bank through its official channel and save transaction details and messages.</li></ol><p className="awareness-help-note">Never pay someone who promises guaranteed recovery of lost funds.</p></div>
            </section>
          </div>
        )}

        {/* 9. SETTINGS & SYSTEM STATUS */}
        {screen === "settings" && !sysStatus && (
          <div className="screen-enter empty-state mx-auto max-w-4xl rounded-2xl border border-slate-800 bg-slate-900/40 p-10 text-center" role={statusLoading ? "status" : undefined}>
            <p className="eyebrow">VEDVIQ AI SETTINGS</p>
            <h1 className="mt-2 text-xl font-semibold text-white">{statusLoading ? "Checking service status…" : "Service status is unavailable"}</h1>
            <p className="mt-2 text-sm text-slate-400">{statusLoading ? "Your workspace remains available while this check runs." : statusError || "The status check did not return data. You can try again."}</p>
            {!statusLoading && <button onClick={retrySystemStatus} className="mt-5 rounded-xl border border-slate-700 px-4 py-2.5 text-sm font-semibold text-slate-200 hover:border-violet-300/40 hover:bg-slate-800">Retry status check</button>}
          </div>
        )}

        {screen === "settings" && sysStatus && (
          <div className="screen-enter max-w-4xl mx-auto space-y-8">
            <div>
              <p className="eyebrow">VEDVIQ AI SETTINGS</p><h1 className="text-2xl font-bold">Service &amp; privacy</h1>
              <p className="text-sm text-slate-400">Check service availability and choose how long review data is kept.</p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 space-y-2 text-xs">
                <div className="flex items-center gap-2 text-sm font-bold text-white">
                  <span className={`service-status-dot ${sysStatus.api_status === "operational" ? "is-operational" : "is-degraded"}`} aria-hidden="true" /> Service status
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Application service:</span>
                  <span className={`font-semibold ${sysStatus.api_status === "operational" ? "text-emerald-300" : "text-rose-300"}`}>{sysStatus.api_status}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Service version:</span>
                  <span className="font-mono">{sysStatus.app_version}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Review storage:</span>
                  <span className="text-emerald-400 font-semibold">
                    {sysStatus.database_connected ? "Connected" : "Error"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Screenshot text reading:</span>
                  <span className="font-mono">
                    {sysStatus.ocr_engine_available ? "Available" : "Manual text available"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Web reputation lookup:</span>
                  <span className="text-right" title={sysStatus.threat_intel_provider}>
                    {sysStatus.threat_intel_configured ? "Configured; not queried" : "Not configured"}
                  </span>
                </div>
              </div>

              <details className="technical-details surface-panel">
                <summary><span><Info aria-hidden="true" /><span><strong>About automated checks</strong><small>Technical and evaluation details</small></span></span><span className="details-chevron">⌄</span></summary>
                <div className="technical-content">
                <div className="flex items-center gap-2 text-sm font-bold text-white">
                  <Cpu className="w-4 h-4 text-rose-400" /> Trained ML Artifact Metadata
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Status:</span>
                  <span className="font-mono text-rose-300">{sysStatus.model_metadata.status}</span>
                </div>
                {sysStatus.model_metadata.metrics_heldout_test && (
                  <>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Held-Out Macro F1:</span>
                      <span className="font-mono">
                        {sysStatus.model_metadata.metrics_heldout_test.f1_macro} (vs Baseline:{" "}
                        {sysStatus.model_metadata.metrics_heldout_test.baseline_dummy_f1})
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Macro Precision / Recall:</span>
                      <span className="font-mono">
                        {sysStatus.model_metadata.metrics_heldout_test.precision_macro} /{" "}
                        {sysStatus.model_metadata.metrics_heldout_test.recall_macro}
                      </span>
                    </div>
                  </>
                )}
                <p className="text-[11px] text-slate-400">{sysStatus.model_metadata.disclaimer}</p>
                <p className="text-[11px] text-slate-400">Important Notice: VEDVIQ AI can make mistakes. AI-generated results may be inaccurate or incomplete. Always verify important information independently before taking action. No scan can guarantee that a link, message, or website is completely safe.</p>
                </div>
              </details>
            </div>

            <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 space-y-4">
              <h2 className="text-base font-bold">Review data &amp; privacy</h2>
              <p className="text-sm text-slate-400">
                By default, VEDVIQ AI stores a content hash and a short preview with personal information redacted. Full message storage is disabled unless you enable it below.
              </p>
              <div className="flex items-center justify-between pt-2">
                <label className="text-sm font-medium flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={sysStatus.privacy_settings.store_raw_content}
                    onChange={async (e) => {
                      try {
                        const updated = await api.updateSettings({
                          store_raw_content: e.target.checked,
                          retention_days: sysStatus.privacy_settings.retention_days,
                        });
                        setSysStatus({ ...sysStatus, privacy_settings: updated });
                      } catch (error) {
                        setErrorBanner(error instanceof Error ? error.message : "Could not update the privacy setting.");
                      }
                    }}
                    className="rounded border-slate-700"
                  />
                  Save full message text with review history
                </label>
              </div>
              <div className="retention-control"><label htmlFor="retention-days">Keep review history for</label><select id="retention-days" value={sysStatus.privacy_settings.retention_days} onChange={async (event) => {
                const retentionDays = Number(event.target.value);
                try {
                  const updated = await api.updateSettings({ store_raw_content: sysStatus.privacy_settings.store_raw_content, retention_days: retentionDays });
                  setSysStatus({ ...sysStatus, privacy_settings: updated });
                } catch (error) {
                  setErrorBanner(error instanceof Error ? error.message : "Could not update the retention period.");
                }
              }}>{![1, 7, 30, 60, 90, 180, 365].includes(sysStatus.privacy_settings.retention_days) && <option value={sysStatus.privacy_settings.retention_days}>{sysStatus.privacy_settings.retention_days} days</option>}<option value={1}>1 day</option><option value={7}>7 days</option><option value={30}>30 days</option><option value={60}>60 days</option><option value={90}>90 days</option><option value={180}>180 days</option><option value={365}>365 days</option></select></div>
            </div>
          </div>
        )}
      </main>
      <footer className="border-t border-slate-800/70 px-4 py-4 text-center text-xs text-slate-400">AI can make mistakes. Check important information independently.</footer>
    </div>
    {!showIntro && screen !== "assistant" && <button type="button" className="assistant-launcher" onClick={() => { setScreen("assistant"); setMobileMenuOpen(false); }} aria-label="Open VEDVIQ AI Assistant" title="Open VEDVIQ AI Assistant"><Bot aria-hidden="true" /><span>Ask VEDVIQ AI</span></button>}
    {showIntro && <CyberBootIntro apiStatus={dashboardUnavailable ? "unavailable" : dashboard ? "responded" : "checking"} onComplete={completeIntro} />}
    </>
  );
}
