import React, { useEffect, useState } from "react";
import { ArrowRight, Clock3, History, Image as ImageIcon, MessageSquareWarning, ShieldAlert, ShieldCheck, Sparkles, Globe } from "lucide-react";
import {
  Bar, BarChart, CartesianGrid, Cell, LabelList, Line, LineChart, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { DashboardAnalytics, AnalysisResult } from "../types/api";
import { RiskBadge, RISK_COLORS } from "./ScanVisuals";
import "./DashboardScreen.css";

type Props = {
  dashboard: DashboardAnalytics | null;
  unavailable: boolean;
  onRetry: () => void;
  onNewScan: () => void;
  onOpenTool: (tool: "message" | "url" | "ocr") => void;
  onOpenHistory: () => void;
  onOpenReport: (item: AnalysisResult) => void;
};

const compactDate = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(date);
};

const categoryColorTokens = ["--ss-cat-financial", "--ss-cat-digital", "--ss-cat-rewards", "--ss-cat-impersonation", "--ss-cat-employment"];
function categoryColor(category: string, index: number) {
  const name = category.toLowerCase();
  if (/upi|bank|payment|account|credential|financial|kyc/.test(name)) return "var(--ss-cat-financial)";
  if (/url|link|web|phish|malware|digital|tech/.test(name)) return "var(--ss-cat-digital)";
  if (/prize|lottery|reward|cashback|gift|lotto/.test(name)) return "var(--ss-cat-rewards)";
  if (/imperson|extortion|arrest|police|authority|blackmail/.test(name)) return "var(--ss-cat-impersonation)";
  if (/job|employment|investment|loan|trading|crypto/.test(name)) return "var(--ss-cat-employment)";
  // Unknown labels keep a stable, coordinated color based on their category name.
  const hash = Array.from(name).reduce((total, character) => total + character.charCodeAt(0), 0);
  return `var(${categoryColorTokens[hash % categoryColorTokens.length] || categoryColorTokens[index % categoryColorTokens.length]})`;
}

function wrapAxisLabel(value: string, maxChars = 19) {
  const words = value.split(/\s+/).flatMap((word) => {
    const characters = Array.from(word);
    const parts: string[] = [];
    while (characters.length > maxChars) parts.push(characters.splice(0, maxChars).join(""));
    if (characters.length) parts.push(characters.join(""));
    return parts;
  });
  const lines: string[] = [];
  let line = "";
  words.forEach((word) => {
    if (line && `${line} ${word}`.length > maxChars) {
      lines.push(line);
      line = word;
    } else line = line ? `${line} ${word}` : word;
  });
  if (line) lines.push(line);
  return lines;
}

function CategoryTick({ x = 0, y = 0, payload, maxChars = 22 }: { x?: number; y?: number; payload?: { value?: string }; maxChars?: number }) {
  const lines = wrapAxisLabel(String(payload?.value ?? ""), maxChars);
  const startY = -((lines.length - 1) * 7);
  return <g transform={`translate(${x},${y})`} aria-hidden="true">
    <text textAnchor="end" fill="var(--ss-muted)" fontSize="12" fontWeight="500">
      {lines.map((line, index) => <tspan key={`${line}-${index}`} x="-10" dy={index === 0 ? startY : 15}>{line}</tspan>)}
    </text>
  </g>;
}

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name?: string; value?: number | string; color?: string; payload?: { name?: string; category?: string } }>; label?: string }) {
  if (!active || !payload?.length) return null;
  const title = label || payload[0].payload?.name || payload[0].payload?.category || "Recorded scans";
  return <div className="dash-tooltip"><span className="dash-tooltip-title">{title}</span>{payload.map((entry, index) => <div className="dash-tooltip-row" key={`${entry.name}-${index}`}><i style={{ backgroundColor: entry.color || "var(--ss-cyan)" }} /><span>{entry.name || "Reviews"}</span><strong>{entry.value}</strong></div>)}</div>;
}

function ChartEmpty({ children }: { children: React.ReactNode }) {
  return <div className="dash-chart-empty"><span className="dash-chart-empty-mark"><ShieldCheck size={19} /></span><p>{children}</p></div>;
}

function ChartLoading() {
  return <div className="dash-chart-loading" aria-hidden="true">{[36, 58, 45, 77, 52, 68, 41].map((height, index) => <i key={index} style={{ height: `${height}%`, animationDelay: `${index * 65}ms` }} />)}</div>;
}

function QuickActions({ onOpenTool }: Pick<Props, "onOpenTool">) {
  return <section className="dash-quick-actions" aria-label="Start a review">
    <div className="dash-quick-heading"><h2>Start a review</h2><p>Choose the content you want to check.</p></div>
    <div className="dash-quick-list">
      <button type="button" onClick={() => onOpenTool("message")}><span><MessageSquareWarning size={18} /></span><strong>Message</strong><ArrowRight size={15} /></button>
      <button type="button" onClick={() => onOpenTool("url")}><span><Globe size={18} /></span><strong>Web address</strong><ArrowRight size={15} /></button>
      <button type="button" onClick={() => onOpenTool("ocr")}><span><ImageIcon size={18} /></span><strong>Screenshot</strong><ArrowRight size={15} /></button>
    </div>
  </section>;
}

export default function DashboardScreen({ dashboard, unavailable, onRetry, onNewScan, onOpenTool, onOpenHistory, onOpenReport }: Props) {
  const [viewportWidth, setViewportWidth] = useState(() => window.innerWidth);
  const [reduceMotion, setReduceMotion] = useState(() => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false);
  useEffect(() => {
    const resize = () => setViewportWidth(window.innerWidth);
    window.addEventListener("resize", resize, { passive: true });
    return () => window.removeEventListener("resize", resize);
  }, []);
  useEffect(() => {
    const preference = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    if (!preference) return;
    const update = () => setReduceMotion(preference.matches);
    preference.addEventListener?.("change", update);
    return () => preference.removeEventListener?.("change", update);
  }, []);
  const compactChart = viewportWidth <= 560;
  const categoryLabelWidth = compactChart ? 144 : viewportWidth <= 950 ? 178 : 202;
  const categoryLabelCharacters = compactChart ? 15 : viewportWidth <= 950 ? 19 : 23;
  const distributionTotal = dashboard?.risk_distribution.reduce((total, item) => total + item.value, 0) ?? 0;
  const categoryData = dashboard?.category_breakdown ?? [];
  const categoryLineCount = Math.max(1, ...categoryData.map((item) => wrapAxisLabel(item.category, categoryLabelCharacters).length));
  const categoryChartHeight = Math.max(238, categoryData.length * Math.max(52, categoryLineCount * 17 + 14));

  return <div className="dashboard-view screen-enter">
    <header className="dash-header">
      <div>
        <p className="dash-kicker"><span /> VEDVIQ AI / INTELLIGENCE</p>
        <h1>Your dashboard</h1>
        <p className="dash-description">A clear view of the reviews saved in your workspace.</p>
      </div>
      <div className="dash-header-actions">
        <span className={`dash-live-label ${unavailable ? "is-offline" : dashboard ? "is-online" : "is-checking"}`} role="status"><i />{unavailable ? "Workspace unavailable" : dashboard ? "Workspace data loaded" : "Loading workspace data"}</span>
        <button type="button" className="dash-primary-action" onClick={onNewScan}>New review <ArrowRight size={15} /></button>
      </div>
    </header>

    {unavailable ? <section className="dash-offline" role="status"><span className="dash-offline-icon"><ShieldAlert size={22} /></span><div><h2>Analytics aren’t available right now</h2><p>VEDVIQ AI could not load your saved review data from the backend.</p></div><button type="button" onClick={onRetry}>Try again <ArrowRight size={14} /></button></section>
      : !dashboard ? <section className="dash-loading" role="status"><div><p className="dash-kicker">CONNECTING TO YOUR WORKSPACE</p><h2>Preparing your overview</h2><p>Your saved review data will appear here.</p></div><ChartLoading /></section>
      : dashboard.total_scans === 0 ? <><section className="dash-empty"><div className="dash-empty-orbit"><ShieldCheck size={26} /></div><p className="dash-kicker">YOUR WORKSPACE IS READY</p><h2>Your first review starts here.</h2><p>Run a message, link, or screenshot review to build your personal activity overview. Charts use saved backend records only.</p><button type="button" className="dash-primary-action" onClick={onNewScan}>Start a review <ArrowRight size={15} /></button></section><QuickActions onOpenTool={onOpenTool} /></>
      : <>
        <section className="dash-summary" aria-label="Review summary">
          <article className="dash-metric dash-metric-total"><span className="dash-metric-icon"><History size={16} /></span><p>Reviews saved</p><strong>{dashboard.total_scans.toLocaleString()}</strong><small>Across messages, links and screenshots</small></article>
          <article className="dash-metric dash-metric-risk"><span className="dash-metric-icon"><ShieldAlert size={16} /></span><p>High concern</p><strong>{dashboard.high_or_critical_count.toLocaleString()}</strong><small>Marked high or critical by the review</small></article>
          <aside className="dash-summary-note"><Sparkles size={17} /><div><strong>Activity from this workspace</strong><p>Counts and charts below come from saved review records returned by VEDVIQ AI.</p></div></aside>
        </section>

        <QuickActions onOpenTool={onOpenTool} />

        <section className="dash-chart-grid" aria-label="Analytics charts">
          <article className="dash-chart-card dash-risk-card">
            <header className="dash-card-heading"><div><p className="dash-kicker">RISK PROFILE</p><h2>Risk level distribution</h2><p>Saved reviews grouped by backend risk level</p></div><span className="dash-card-index">01</span></header>
            {dashboard.risk_distribution.length === 0 ? <ChartEmpty>Risk distribution is not available yet.</ChartEmpty> : <>
              <div className="dash-donut-wrap">
                <ResponsiveContainer width="100%" height="100%"><PieChart>
                  <Pie data={dashboard.risk_distribution} dataKey="value" nameKey="name" innerRadius="67%" outerRadius="88%" paddingAngle={3} stroke="none" isAnimationActive={!reduceMotion}>
                    {dashboard.risk_distribution.map((entry) => <Cell key={entry.name} fill={RISK_COLORS[entry.name] || "#879690"} />)}
                  </Pie>
                  <Tooltip content={<ChartTooltip />} />
                  <text x="50%" y="46%" textAnchor="middle" className="dash-donut-total">{distributionTotal.toLocaleString()}</text>
            <text x="50%" y="56%" textAnchor="middle" className="dash-donut-caption">SAVED REVIEWS</text>
                </PieChart></ResponsiveContainer>
              </div>
              <div className="dash-legend">{dashboard.risk_distribution.map((entry) => <div className="dash-legend-item" key={entry.name}><i style={{ backgroundColor: RISK_COLORS[entry.name] || "#879690" }} /><span>{entry.name}</span><strong>{entry.value.toLocaleString()}</strong></div>)}</div>
            </>}
          </article>

          <article className="dash-chart-card dash-category-card">
            <header className="dash-card-heading"><div><p className="dash-kicker">WHAT YOU’RE SEEING</p><h2>Scan categories</h2><p>Classification counts from saved reviews</p></div><span className="dash-card-index">02</span></header>
            {categoryData.length === 0 ? <ChartEmpty>Category breakdown is not available yet.</ChartEmpty> : <div className="dash-category-plot" role="group" aria-label="Scan category counts">
              <div className="sr-only"><ul>{categoryData.map((item) => <li key={`accessible-${item.category}`}>{item.category}: {item.count.toLocaleString()} saved reviews</li>)}</ul></div>
              <div style={{ height: categoryChartHeight }}>
              <ResponsiveContainer width="100%" height="100%"><BarChart data={categoryData} layout="vertical" margin={{ top: 10, right: 34, bottom: 10, left: 4 }} barCategoryGap="30%">
                <CartesianGrid strokeDasharray="3 5" stroke="var(--dash-grid)" horizontal={false} />
                <XAxis type="number" allowDecimals={false} domain={[0, (max: number) => Math.max(1, max * 1.22)]} tick={{ fill: "var(--dash-muted)", fontSize: 11 }} axisLine={false} tickLine={false} tickMargin={10} />
                <YAxis type="category" dataKey="category" width={categoryLabelWidth} tick={<CategoryTick maxChars={categoryLabelCharacters} />} axisLine={false} tickLine={false} interval={0} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: "var(--dash-grid)" }} />
                <Bar dataKey="count" name="Saved reviews" fill="var(--ss-cat-financial)" radius={[0, 4, 4, 0]} maxBarSize={17} isAnimationActive={!reduceMotion}>
                  {categoryData.map((entry, index) => <Cell key={entry.category} fill={categoryColor(entry.category, index)} />)}
                  <LabelList dataKey="count" position="right" offset={8} formatter={(value: number) => Number(value).toLocaleString()} className="dash-category-count" />
                </Bar>
              </BarChart></ResponsiveContainer>
              </div>
            </div>}
          </article>
        </section>

        <section className="dash-chart-card dash-timeline-card">
          <header className="dash-card-heading"><div><p className="dash-kicker">ACTIVITY</p><h2>Reviews over time</h2><p>Daily totals from your saved scan history</p></div><span className="dash-card-index"><Clock3 size={15} /></span></header>
          {dashboard.scans_over_time.length === 0 ? <ChartEmpty>There is no saved activity to chart yet.</ChartEmpty> : <div className="dash-timeline-plot"><ResponsiveContainer width="100%" height="100%"><LineChart data={dashboard.scans_over_time} margin={{ top: 12, right: 14, bottom: 4, left: -12 }}>
            <CartesianGrid strokeDasharray="3 5" stroke="var(--dash-grid)" vertical={false} />
            <XAxis dataKey="date" tickFormatter={compactDate} tick={{ fill: "var(--dash-muted)", fontSize: 11 }} axisLine={false} tickLine={false} tickMargin={12} minTickGap={22} />
            <YAxis allowDecimals={false} width={38} tick={{ fill: "var(--dash-muted)", fontSize: 11 }} axisLine={false} tickLine={false} />
            <Tooltip content={<ChartTooltip />} labelFormatter={(value) => compactDate(String(value))} />
            <Line type="monotone" dataKey="scans" name="All reviews" stroke="var(--ss-cyan)" strokeWidth={2.5} dot={{ r: 3, fill: "var(--ss-cyan)", stroke: "var(--ss-panel)", strokeWidth: 2 }} activeDot={{ r: 5 }} isAnimationActive={!reduceMotion} />
            <Line type="monotone" dataKey="high_risk" name="High concern" stroke="var(--ss-risk-high)" strokeWidth={2} dot={{ r: 2.5, fill: "var(--ss-risk-high)", stroke: "var(--ss-panel)", strokeWidth: 2 }} activeDot={{ r: 4 }} isAnimationActive={!reduceMotion} />
          </LineChart></ResponsiveContainer></div>}
          <div className="dash-line-legend"><span><i className="is-all" />All reviews</span><span><i className="is-risk" />High concern</span></div>
        </section>

        <section className="dash-recent-card">
          <header className="dash-recent-heading"><div><p className="dash-kicker">LATEST RECORDS</p><h2>Recent activity</h2><p>The latest saved reviews in your workspace</p></div><button type="button" onClick={onOpenHistory}>Open history <ArrowRight size={14} /></button></header>
          {dashboard.recent_scans.length === 0 ? <div className="dash-recent-empty"><History size={19} /><p>No recent review records</p></div> : <div className="dash-recent-list">{dashboard.recent_scans.slice(0, 6).map((item) => <article className="dash-recent-row" key={item.scan_id}>
            <span className="dash-recent-type">{item.scan_type === "url" ? "URL" : item.scan_type === "ocr" ? "OCR" : "MSG"}</span>
            <div className="dash-recent-copy"><strong>{item.scam_category}</strong><span>#{item.scan_id} · {compactDate(item.created_at)} · {item.redacted_preview}</span></div>
            <RiskBadge level={item.risk_level} />
            <button type="button" className="dash-open-report" onClick={() => onOpenReport(item)} aria-label={`Open report for scan ${item.scan_id}`}><ArrowRight size={15} /></button>
          </article>)}</div>}
        </section>
      </>}
  </div>;
}
