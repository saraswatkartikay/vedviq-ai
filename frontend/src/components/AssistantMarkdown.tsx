import React from "react";
import ReactMarkdown from "react-markdown";

export function safeMarkdownUrl(url: string): string {
  const value = url.trim();
  if (/^(https?:|mailto:)/i.test(value) || /^(\/|#|\.\.?\/)/.test(value)) return value;
  return "";
}

export function MarkdownResponse({ content }: { content: string }) {
  return <ReactMarkdown
    skipHtml
    urlTransform={safeMarkdownUrl}
    components={{
      a: ({ children, href }) => href ? <a href={href} target={href.startsWith("http") ? "_blank" : undefined} rel={href.startsWith("http") ? "noreferrer" : undefined}>{children}</a> : <span>{children}</span>,
      pre: ({ children }) => <pre className="assistant-markdown-code">{children}</pre>,
    }}
  >{content}</ReactMarkdown>;
}

export function isStructuredDraft(content: string): boolean {
  return /(?:^|\n)\s*(?:#{1,3}\s*)?(?:(?:formal\s+)?complaint draft|email draft|draft complaint|draft email|subject\s*:)/i.test(content);
}

export function draftTextFromMarkdown(content: string): string {
  const draftMarker = /(?:^|\n)\s*(?:#{1,3}\s*)?(?:(?:formal\s+)?complaint draft|email draft|draft complaint|draft email)\s*:?\s*\n/i;
  const marker = content.match(draftMarker);
  if (marker && marker.index !== undefined) return content.slice(marker.index + marker[0].length).trim();
  const subject = content.match(/(?:^|\n)\s*(?:#{1,3}\s*)?subject\s*:/i);
  return subject?.index !== undefined ? content.slice(subject.index).trim() : content.trim();
}

export function markdownToPlainText(markdown: string): string {
  return markdown
    .replace(/\r\n?/g, "\n")
    .replace(/```[^\n]*\n([\s\S]*?)```/g, (_match, code: string) => code.trimEnd())
    .replace(/`([^`]+)`/g, "$1")
    .replace(/!?\[([^\]]*)\]\(([^)]+)\)/g, (_match, label: string, url: string) => {
      const destination = safeMarkdownUrl(url);
      if (!label) return destination;
      return destination && destination !== label ? `${label} (${destination})` : label;
    })
    .replace(/^\s{0,3}#{1,6}\s+/gm, "")
    .replace(/^\s*>\s?/gm, "")
    .replace(/^\s*[-*+]\s+/gm, "• ")
    .replace(/^\s*(\d+)[.)]\s+/gm, "$1. ")
    .replace(/^\s*(?:---+|___+|\*\*\*+)\s*$/gm, "────────────────────")
    .replace(/\*\*(.*?)\*\*/gs, "$1")
    .replace(/__(.*?)__/gs, "$1")
    .replace(/\*(.*?)\*/gs, "$1")
    .replace(/_(.*?)_/gs, "$1")
    .replace(/~~(.*?)~~/gs, "$1")
    .replace(/<[^>]*>/g, "")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export async function copyAssistantText(text: string): Promise<void> {
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Use the legacy selection-based path when browser permissions deny async clipboard access.
    }
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = typeof document.execCommand === "function" && document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("Clipboard access is unavailable.");
}
