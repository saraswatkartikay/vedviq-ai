import React from "react";

export const RISK_COLORS: Record<string, string> = {
  Low: "var(--ss-risk-low)",
  Medium: "var(--ss-risk-medium)",
  High: "var(--ss-risk-high)",
  Critical: "var(--ss-risk-critical)",
};

export function RiskBadge({ level }: { level: string }) {
  const normalizedLevel = level.toLowerCase();
  return <span className={`risk-badge risk-${normalizedLevel}`}><span aria-hidden="true" />{level} Risk</span>;
}

export function RiskGauge({ score, level, scanId }: { score: number; level: string; scanId: number }) {
  const radius = 58;
  const circumference = 2 * Math.PI * radius;
  const boundedScore = Math.max(0, Math.min(100, score));
  const gradientId = `risk-gauge-${scanId}`;
  return (
    <div className="risk-gauge-wrap" role="img" aria-label={`Evidence score ${boundedScore} out of 100, ${level} risk`}>
      <svg className="risk-gauge" viewBox="0 0 144 144" aria-hidden="true">
        <defs><linearGradient id={gradientId} x1="0" y1="1" x2="1" y2="0"><stop offset="0%" stopColor={RISK_COLORS[level] || "var(--ss-risk-critical)"} /><stop offset="100%" stopColor={RISK_COLORS[level] || "var(--ss-risk-critical)"} /></linearGradient></defs>
        <circle className="risk-gauge-track" cx="72" cy="72" r={radius} />
        <circle className="risk-gauge-value" cx="72" cy="72" r={radius} stroke={`url(#${gradientId})`} strokeDasharray={circumference} strokeDashoffset={circumference * (1 - boundedScore / 100)} />
      </svg>
      <div className="risk-gauge-copy"><span className="risk-gauge-score">{boundedScore}<small>/100</small></span><span className="risk-gauge-label">Evidence score</span></div>
    </div>
  );
}
