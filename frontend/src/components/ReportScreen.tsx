import React from "react";
import { CheckCircle2, Download, Info, ShieldAlert } from "lucide-react";
import { AnalysisResult } from "../types/api";
import { RiskBadge, RiskGauge } from "./ScanVisuals";

type Props = { report: AnalysisResult; onDownload: (report: AnalysisResult) => void };

export default function ReportScreen({ report, onDownload }: Props) {
  const hasEvidence = report.rule_indicators.length > 0 || report.suspicious_spans.length > 0;

  return <div className="screen-enter report-screen">
    <div className="report-topbar">
      <div><p className="eyebrow">REVIEW SUMMARY · #{report.scan_id}</p><h1>{report.scam_category}</h1><p className="report-date">{new Date(report.created_at).toLocaleString()} <span>·</span> {report.scan_type === "ocr" ? "Screenshot" : report.scan_type === "url" ? "Web address" : "Message"}</p></div>
      <div className="report-actions"><RiskBadge level={report.risk_level} /><button onClick={() => onDownload(report)} className="secondary-action"><Download aria-hidden="true" /> Download report</button></div>
    </div>

    <section className="report-overview surface-panel" aria-label="Risk assessment">
      <div className="report-gauge"><RiskGauge score={report.risk_score} level={report.risk_level} scanId={report.scan_id} /></div>
      <div className="report-summary"><span className="eyebrow">WHAT WE FOUND</span><h2>{report.risk_level} level of concern</h2><p>{report.summary_explanation}</p><p>AI can make mistakes. Verify important information independently.</p><div className="report-preview"><span>CONTENT REVIEWED</span><p>{report.redacted_preview}</p></div></div>
    </section>

    <div className="report-columns">
      <section className="report-section surface-panel">
        <div className="section-heading"><span className="section-icon is-warning"><ShieldAlert aria-hidden="true" /></span><div><h2>Warning signs</h2><p>Signals identified in the content you shared</p></div><span className="section-count">{report.rule_indicators.length + report.suspicious_spans.length}</span></div>
        {!hasEvidence ? <div className="report-empty"><CheckCircle2 aria-hidden="true" /><p>No specific warning signs were identified in this review.</p></div> : <div className="evidence-list">
          {report.rule_indicators.map((indicator) => <article className="evidence-item" key={indicator.id}><div className="evidence-title"><h3>{indicator.name}</h3><span>{indicator.severity}</span></div><p>{indicator.description}</p>{indicator.matched_text && <blockquote>“{indicator.matched_text}”</blockquote>}</article>)}
          {report.suspicious_spans.filter((span) => !report.rule_indicators.some((indicator) => indicator.matched_text === span)).map((span, index) => <article className="evidence-item" key={`${span}-${index}`}><div className="evidence-title"><h3>Content to review</h3></div><blockquote>“{span}”</blockquote></article>)}
        </div>}
      </section>

      <section className="report-section recommendations-panel surface-panel">
        <div className="section-heading"><span className="section-icon is-safe"><CheckCircle2 aria-hidden="true" /></span><div><h2>What to do next</h2><p>Practical steps based on this review</p></div></div>
        {report.recommended_actions.length ? <ol className="recommendation-list">{report.recommended_actions.map((action, index) => <li key={`${index}-${action}`}><span>{String(index + 1).padStart(2, "0")}</span><p>{action}</p></li>)}</ol> : <p className="report-empty-copy">Verify the sender through an official channel you find independently before taking action.</p>}
        <div className="report-caution"><Info aria-hidden="true" /><p>{report.limitations_note}</p></div>
      </section>
    </div>

    <details className="technical-details surface-panel">
      <summary><span><Info aria-hidden="true" /><span><strong>Technical details</strong><small>Optional information about how this assessment was produced</small></span></span><span className="details-chevron">⌄</span></summary>
      <div className="technical-content">
        <div className="technical-grid"><div><span>Evidence score</span><strong>Matched rule weights · {report.risk_score}/100</strong></div><div><span>Text classifier</span><strong>{report.ml_assessment.status.replace(/_/g, " ")}</strong></div><div><span>Predicted category</span><strong>{report.ml_assessment.predicted_label.replace(/_/g, " ")}</strong></div><div><span>Classifier probability</span><strong>Not displayed · uncalibrated development output</strong></div><div><span>Threat lookup</span><strong>{report.threat_intel.provider} · {report.threat_intel.mode}</strong></div></div>
        {report.ml_assessment.top_features.length > 0 && <div className="technical-features"><span>Classifier signals</span><div>{report.ml_assessment.top_features.map((feature) => <code key={feature}>{feature}</code>)}</div></div>}
        <p className="technical-note">{report.ml_assessment.note} {report.threat_intel.details}</p>
      </div>
    </details>
  </div>;
}
