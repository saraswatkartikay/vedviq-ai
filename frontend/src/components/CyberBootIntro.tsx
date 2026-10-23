import React, { useEffect, useRef, useState } from "react";
import { ArrowRight, Bot, Globe2, Image as ImageIcon, MessageSquareText, ShieldCheck } from "lucide-react";
import "./cyber-boot-intro.css";

export const INTRO_SEEN_KEY = "scamsathi-intro-seen";

type Props = {
  apiStatus: "checking" | "responded" | "unavailable";
  onComplete: () => void;
};

function getApiLabel(status: Props["apiStatus"]) {
  if (status === "responded") return "Workspace data available";
  if (status === "unavailable") return "Workspace service unavailable";
  return "Checking workspace service";
}

const features = [
  { title: "Message Scan", description: "Understand warning signs in a text.", icon: MessageSquareText },
  { title: "URL Guard", description: "Review a link without opening it.", icon: Globe2 },
  { title: "Screenshot OCR", description: "Read and review an image.", icon: ImageIcon },
  { title: "AI Assistant", description: "Get practical cyber safety guidance.", icon: Bot },
];

export default function CyberBootIntro({ apiStatus, onComplete }: Props) {
  const [leaving, setLeaving] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);
  const enterRef = useRef<HTMLButtonElement>(null);
  const skipRef = useRef<HTMLButtonElement>(null);
  const exitTimer = useRef<number | null>(null);

  useEffect(() => {
    const isReduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
    setReducedMotion(isReduced);
    enterRef.current?.focus({ preventScroll: true });
  }, []);

  useEffect(() => {
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previousOverflow;
      if (exitTimer.current !== null) window.clearTimeout(exitTimer.current);
    };
  }, []);

  const leaveIntro = () => {
    if (leaving) return;
    setLeaving(true);
    exitTimer.current = window.setTimeout(onComplete, reducedMotion ? 0 : 360);
  };

  const handleKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      leaveIntro();
      return;
    }
    if (event.key !== "Tab") return;
    if (event.shiftKey && document.activeElement === enterRef.current) {
      event.preventDefault();
      skipRef.current?.focus();
    } else if (!event.shiftKey && document.activeElement === skipRef.current) {
      event.preventDefault();
      enterRef.current?.focus();
    }
  };

  return (
    <div className={`cyber-boot ${leaving ? "is-leaving" : ""} ${reducedMotion ? "is-reduced-motion" : ""}`} onKeyDown={handleKeyDown}>
      <div className="cyber-boot__backdrop" aria-hidden="true">
        <div className="cyber-boot__grid" />
        <div className="cyber-boot__glow cyber-boot__glow--violet" />
        <div className="cyber-boot__glow cyber-boot__glow--cyan" />
        <div className="cyber-boot__orbit cyber-boot__orbit--one" />
        <div className="cyber-boot__orbit cyber-boot__orbit--two" />
      </div>

      <section className="cyber-boot__dialog" role="dialog" aria-modal="true" aria-labelledby="cyber-boot-title" aria-describedby="cyber-boot-description">
        <header className="cyber-boot__header">
          <div className="cyber-boot__brand">
            <span className="cyber-boot__brand-mark"><ShieldCheck aria-hidden="true" /></span>
            <span className="cyber-boot__brand-name">VEDVIQ AI</span>
            <span className="cyber-boot__brand-divider" aria-hidden="true" />
            <span className="cyber-boot__descriptor">CYBER SAFETY WORKSPACE</span>
          </div>
          <div className={`cyber-boot__service-status is-${apiStatus}`} role="status" aria-live="polite"><i />{getApiLabel(apiStatus)}</div>
        </header>

        <main className="cyber-boot__main">
          <div className="cyber-boot__hero">
            <div className="cyber-boot__hero-emblem" aria-hidden="true"><ShieldCheck /></div>
            <p className="cyber-boot__eyebrow">A CLEARER SIGNAL IN A NOISY WORLD</p>
            <h1 id="cyber-boot-title">Pause before <span>you trust.</span></h1>
            <p id="cyber-boot-description" className="cyber-boot__description">Get a second look at suspicious messages, links and screenshots, with practical steps for what to do next.</p>
            <div className="cyber-boot__actions">
              <button ref={enterRef} type="button" className="cyber-boot__enter" onClick={leaveIntro} aria-label="Enter VEDVIQ AI workspace"><span>Enter VEDVIQ AI</span><ArrowRight aria-hidden="true" /></button>
              <button ref={skipRef} type="button" className="cyber-boot__skip" onClick={leaveIntro}>Skip intro</button>
            </div>
            <p className="cyber-boot__privacy"><ShieldCheck aria-hidden="true" /> Results are guidance, not a guarantee.</p>
          </div>

          <section className="cyber-boot__features" aria-label="VEDVIQ AI tools">
            {features.map(({ title, description, icon: Icon }, index) => <article className="cyber-boot__feature" key={title} style={{ animationDelay: `${index * 60}ms` }}>
              <span><Icon aria-hidden="true" /></span><div><h2>{title}</h2><p>{description}</p></div>
            </article>)}
          </section>
          <div className="cyber-boot__footer"><span>VEDVIQ AI</span><span>Review carefully. Decide confidently.</span><span>INDIA · DIGITAL SAFETY</span></div>
        </main>
      </section>
    </div>
  );
}
