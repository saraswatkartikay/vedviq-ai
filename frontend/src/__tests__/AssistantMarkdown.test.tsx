import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { copyAssistantText, draftTextFromMarkdown, isStructuredDraft, MarkdownResponse, markdownToPlainText, safeMarkdownUrl } from "../components/AssistantMarkdown";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("assistant Markdown", () => {
  it("renders headings, emphasis, paragraphs, ordered and unordered lists, links, rules, and code", () => {
    render(<MarkdownResponse content={"# Safety\n\n**Never** share secrets.\n\n- Keep evidence\n- Verify first\n\n1. Contact your bank\n2. Report\n\n[Official route](https://cybercrime.gov.in/)\n\n---\n\n\`UPI PIN\`"} />);
    expect(screen.getByRole("heading", { name: "Safety" })).toBeInTheDocument();
    expect(screen.getByText("Never").tagName).toBe("STRONG");
    expect(screen.getAllByRole("list")).toHaveLength(2);
    expect(screen.getByRole("link", { name: "Official route" })).toHaveAttribute("href", "https://cybercrime.gov.in/");
    expect(document.querySelector("hr")).not.toBeNull();
    expect(screen.getByText("UPI PIN").tagName).toBe("CODE");
  });

  it("drops raw HTML and rejects unsafe link schemes", () => {
    render(<MarkdownResponse content={'<script>alert(1)</script>\n\n[unsafe](javascript:alert(1))'} />);
    expect(document.querySelector("script")).toBeNull();
    expect(screen.queryByRole("link", { name: "unsafe" })).toBeNull();
    expect(safeMarkdownUrl("data:text/html,<script>bad</script>")).toBe("");
    expect(safeMarkdownUrl("https://example.test/path")).toBe("https://example.test/path");
  });

  it("copies long multilingual Markdown as readable plain text with list and link content", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const response = "## शिकायत का मसौदा\n\n**विषय:** अनधिकृत लेन-देन\n\n- बैंक से संपर्क करें\n- OTP साझा न करें\n\n[आधिकारिक पोर्टल](https://cybercrime.gov.in/)\n\n" + "अतिरिक्त विवरण। ".repeat(80);
    const plain = markdownToPlainText(response);
    await copyAssistantText(plain);
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining("• बैंक से संपर्क करें"));
    expect(writeText.mock.calls[0][0]).toContain("आधिकारिक पोर्टल (https://cybercrime.gov.in/)");
    expect(writeText.mock.calls[0][0].length).toBeGreaterThan(800);
    expect(writeText.mock.calls[0][0]).not.toContain("**");
  });

  it("detects a document-style draft and copies the draft without its preface", () => {
    const content = "Draft for review only:\n\n### Email draft\nSubject: Unrecognized debit\n\nDear Bank Support,\nPlease review this transaction.\n\nRegards,\n[Your name]";
    expect(isStructuredDraft(content)).toBe(true);
    expect(draftTextFromMarkdown(content)).toBe("Subject: Unrecognized debit\n\nDear Bank Support,\nPlease review this transaction.\n\nRegards,\n[Your name]");
    expect(markdownToPlainText(draftTextFromMarkdown(content))).toContain("Subject: Unrecognized debit");
  });

  it("falls back to document copy when clipboard permission is denied and reports failure if both methods fail", async () => {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: vi.fn().mockRejectedValue(new Error("denied")) } });
    Object.defineProperty(document, "execCommand", { configurable: true, value: vi.fn().mockReturnValue(true) });
    await expect(copyAssistantText("Short answer")).resolves.toBeUndefined();
    Object.defineProperty(document, "execCommand", { configurable: true, value: vi.fn().mockReturnValue(false) });
    await expect(copyAssistantText("Short answer")).rejects.toThrow("Clipboard access is unavailable.");
  });
});
