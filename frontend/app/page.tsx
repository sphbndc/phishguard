"use client";

import { FormEvent, useMemo, useState } from "react";
import { Check, ChevronRight, Clipboard, Download, Info, ScanSearch, ShieldCheck, Trash2, X } from "lucide-react";
import { jsPDF } from "jspdf";
import { SiteFooter } from "@/components/site-footer";
import { SiteHeader } from "@/components/site-header";

type Severity = "Critical" | "Warning" | "Informational";
type Result = {
  overall_score: number;
  risk_level: "Safe" | "Moderate Risk" | "Dangerous Phishing";
  flagged_issues: { category: string; severity: Severity; description: string }[];
  uncloaked_urls: { original_url: string; final_url: string; is_suspicious: boolean }[];
  educational_advice: string;
};

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const severityStyles: Record<Severity, string> = {
  Critical: "border-red-200 bg-red-50 text-red-800 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-200",
  Warning: "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-200",
  Informational: "border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-700 dark:bg-zinc-900 dark:text-slate-200",
};

function Gauge({ score, level }: { score: number; level: Result["risk_level"] }) {
  const color = score >= 65 ? "#dc2626" : score >= 30 ? "#d97706" : "#16a34a";
  return (
    <div className="flex items-center gap-5">
      <div
        className="gauge-ring h-32 w-32 shrink-0"
        style={{ background: `conic-gradient(${color} ${score * 3.6}deg, #e5e7eb 0deg)` }}
        role="img"
        aria-label={`${score} percent phishing risk`}
      >
        <div className="absolute inset-0 z-10 flex flex-col items-center justify-center">
          <strong className="text-3xl tracking-tight">{score}%</strong>
          <span className="text-[10px] font-bold uppercase tracking-[.18em] text-slate-500">risk</span>
        </div>
      </div>
      <div>
        <p className="mb-1 text-xs font-bold uppercase tracking-[.18em] text-slate-500">Analysis complete</p>
        <h2 className="text-2xl font-semibold tracking-tight" style={{ color }}>{level}</h2>
        <p className="mt-2 max-w-sm text-sm leading-6 text-slate-600 dark:text-slate-300">A combined score from local language analysis, sender checks, authentication, and link inspection.</p>
      </div>
    </div>
  );
}

export default function Home() {
  const [sender, setSender] = useState("");
  const [body, setBody] = useState("");
  const [header, setHeader] = useState("");
  const [showHeader, setShowHeader] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [copied, setCopied] = useState(false);
  const [showHeaderGuide, setShowHeaderGuide] = useState(false);

  const grouped = useMemo(() => {
    const groups: Record<Severity, Result["flagged_issues"]> = { Critical: [], Warning: [], Informational: [] };
    result?.flagged_issues.forEach((issue) => groups[issue.severity].push(issue));
    return groups;
  }, [result]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const response = await fetch(`${API_URL}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sender, body, header }),
      });
      const data = await response.json().catch(() => null);
      if (!response.ok) {
        const detail = Array.isArray(data?.detail) ? data.detail[0]?.msg : data?.detail;
        throw new Error(detail || "The analyzer could not process this email.");
      }
      setResult(data as Result);
      requestAnimationFrame(() => document.getElementById("results")?.scrollIntoView({ behavior: "smooth", block: "start" }));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not reach the PhishGuard API.");
    } finally {
      setLoading(false);
    }
  }

  async function copyReport() {
    if (!result) return;
    await navigator.clipboard.writeText(formatReport(result));
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  }

  function formatReport(report: Result) {
    const lines = [
      "PHISHGUARD SECURITY REPORT",
      "Scanned by PhishGuard | Crafted by savicst",
      `Generated: ${new Date().toLocaleString()}`,
      "=".repeat(64),
      `RISK ASSESSMENT: ${report.risk_level.toUpperCase()}`,
      `Phishing risk score: ${report.overall_score}%`,
      "",
      "FLAGGED ISSUES",
      ...((report.flagged_issues.length ? report.flagged_issues : [{ category: "None", severity: "Informational", description: "No notable anomalies were detected." }]).flatMap((issue, index) => [
        `${index + 1}. [${issue.severity}] ${issue.category}`,
        `   ${issue.description}`,
      ])),
      "",
      "UNCLOAKED LINKS",
      ...(report.uncloaked_urls.length ? report.uncloaked_urls.flatMap((url, index) => [
        `${index + 1}. ${url.original_url}`,
        `   Final target: ${url.final_url}`,
        `   Verdict: ${url.is_suspicious ? "Suspicious" : "Clear"}`,
      ]) : ["No web links were found in this message."]),
      "",
      "EDUCATIONAL GUIDANCE",
      report.educational_advice,
      "",
      "This report is an advisory security assessment generated locally by PhishGuard. Verify high-impact requests through an independent channel.",
    ];
    return lines.join("\n");
  }

  function downloadPdf() {
    if (!result) return;
    const pdf = new jsPDF({ unit: "pt", format: "a4" });
    const pageWidth = pdf.internal.pageSize.getWidth();
    const pageHeight = pdf.internal.pageSize.getHeight();
    const margin = 48;
    let y = 54;
    const addWatermark = () => {
      pdf.setTextColor(226, 232, 240);
      pdf.setFontSize(30);
      pdf.setFont("helvetica", "bold");
      pdf.text("PHISHGUARD", pageWidth / 2, pageHeight / 2, { align: "center", angle: 35 });
      pdf.setTextColor(15, 23, 42);
    };
    const ensureSpace = (height: number) => {
      if (y + height > pageHeight - 52) {
        pdf.addPage();
        y = 54;
        addWatermark();
      }
    };
    addWatermark();
    pdf.setFillColor(16, 185, 129);
    pdf.roundedRect(margin, y - 24, pageWidth - margin * 2, 58, 10, 10, "F");
    pdf.setTextColor(3, 7, 18);
    pdf.setFont("helvetica", "bold");
    pdf.setFontSize(18);
    pdf.text("PHISHGUARD SECURITY REPORT", margin + 18, y + 2);
    pdf.setFont("helvetica", "normal");
    pdf.setFontSize(9);
    pdf.text("Scanned by PhishGuard | Crafted by savicst", margin + 18, y + 20);
    y += 62;
    const heading = (text: string) => { ensureSpace(32); pdf.setTextColor(5, 150, 105); pdf.setFont("helvetica", "bold"); pdf.setFontSize(11); pdf.text(text, margin, y); y += 18; };
    const paragraph = (text: string, color: [number, number, number] = [51, 65, 85]) => { const wrapped = pdf.splitTextToSize(text, pageWidth - margin * 2); ensureSpace(wrapped.length * 14 + 8); pdf.setTextColor(...color); pdf.setFont("helvetica", "normal"); pdf.setFontSize(10); pdf.text(wrapped, margin, y, { lineHeightFactor: 1.35 }); y += wrapped.length * 14 + 8; };
    heading("RISK ASSESSMENT");
    paragraph(`${result.risk_level} — Phishing risk score: ${result.overall_score}%`, result.overall_score >= 65 ? [185, 28, 28] : result.overall_score >= 30 ? [180, 83, 9] : [5, 150, 105]);
    heading("FLAGGED ISSUES");
    (result.flagged_issues.length ? result.flagged_issues : [{ category: "None", severity: "Informational", description: "No notable anomalies were detected." }]).forEach((issue, index) => paragraph(`${index + 1}. [${issue.severity}] ${issue.category}: ${issue.description}`));
    heading("UNCLOAKED LINKS");
    (result.uncloaked_urls.length ? result.uncloaked_urls.map((url, index) => `${index + 1}. ${url.original_url} → ${url.final_url} (${url.is_suspicious ? "Suspicious" : "Clear"})`) : ["No web links were found in this message."]).forEach((item) => paragraph(item));
    heading("EDUCATIONAL GUIDANCE");
    paragraph(result.educational_advice);
    heading("ADVISORY NOTICE");
    paragraph("This report is an advisory security assessment generated locally by PhishGuard. Verify high-impact requests through an independent channel.");
    const pages = pdf.getNumberOfPages();
    for (let page = 1; page <= pages; page += 1) { pdf.setPage(page); pdf.setTextColor(100, 116, 139); pdf.setFontSize(8); pdf.text(`PhishGuard • Confidential scan report • ${page}/${pages}`, margin, pageHeight - 24); }
    pdf.save(`phishguard-report-${new Date().toISOString().slice(0, 10)}.pdf`);
  }

  function clearAll() {
    setSender("");
    setBody("");
    setHeader("");
    setShowHeader(false);
    setResult(null);
    setError("");
  }

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-50 via-emerald-50/60 to-slate-50 text-slate-900 transition-colors duration-200 dark:from-zinc-950 dark:via-emerald-950/35 dark:to-zinc-950 dark:text-slate-100">
      <SiteHeader />

      <section className="mx-auto max-w-7xl px-5 pb-20 pt-14 lg:px-8 lg:pt-20">
        <div className="mb-12 grid gap-8 lg:grid-cols-[1fr_.58fr] lg:items-end">
          <div>
            <p className="mb-4 text-xs font-bold uppercase tracking-[.24em] text-emerald-600">Email threat intelligence</p>
            <h1 className="max-w-3xl text-4xl font-semibold leading-[1.05] tracking-[-.04em] text-slate-950 dark:text-white sm:text-6xl">
              Stop the click.<br /><span className="text-slate-400">See what&apos;s hiding.</span>
            </h1>
          </div>
          <p className="max-w-xl border-l-2 border-emerald-400 pl-5 text-base leading-7 text-slate-600 dark:text-slate-300">
            Paste a suspicious email. PhishGuard inspects its language, identity signals, authentication trail, and destinations&mdash;without sending it to a paid AI service.
          </p>
        </div>

        <form onSubmit={submit} className="overflow-visible rounded-3xl border border-slate-200 bg-white shadow-panel backdrop-blur-sm dark:border-zinc-800 dark:bg-zinc-900">
          <div className="grid lg:grid-cols-[.72fr_1.28fr]">
            <div className="flex flex-col border-b border-slate-200 p-6 lg:border-b-0 lg:border-r lg:p-8 dark:border-zinc-800">
              <label htmlFor="sender" className="mb-3 block text-sm font-semibold">Sender identity</label>
              <input
                id="sender"
                type="email"
                required
                maxLength={320}
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                placeholder="security@paypa1.com"
                className="w-full rounded-xl border border-slate-300 bg-slate-100 px-4 py-3.5 text-sm text-slate-900 transition placeholder:text-slate-500 hover:border-slate-400 focus:border-slate-500 focus:bg-slate-100 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:placeholder:text-zinc-400 dark:focus:border-zinc-500 dark:focus:bg-zinc-800"
              />
              <div className="mt-auto rounded-2xl bg-slate-950 p-5 pt-8 text-white dark:bg-emerald-950/60">
                <ShieldCheck className="mb-5 h-8 w-8 text-emerald-400" />
                <p className="text-sm font-semibold">Privacy by design</p>
                <p className="mt-2 text-xs leading-5 text-white/65">Your email is processed by your own backend and local open-source model. PhishGuard does not store scan contents.</p>
              </div>
            </div>

            <div className="p-6 lg:p-8">
              <div className="mb-3 flex items-center justify-between gap-4">
                <label htmlFor="body" className="text-sm font-semibold">Email content</label>
                <span className="text-xs text-slate-400">Plain text or pasted rich text</span>
              </div>
              <textarea
                id="body"
                required
                maxLength={200000}
                rows={10}
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder={"Dear customer,\n\nWe detected unusual activity. Verify now to prevent your account from being suspended..."}
                className="w-full resize-y rounded-xl border border-slate-300 bg-slate-100 px-4 py-4 text-sm leading-6 text-slate-900 transition placeholder:text-slate-500 hover:border-slate-400 focus:border-slate-500 focus:bg-slate-100 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:placeholder:text-zinc-400 dark:focus:border-zinc-500 dark:focus:bg-zinc-800"
              />

              <div className="relative mt-4 flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
              <button type="button" onClick={() => setShowHeader(!showHeader)} aria-expanded={showHeader} className="flex items-center gap-2 text-sm font-semibold text-emerald-700 hover:text-emerald-500 dark:text-emerald-300">
                <ChevronRight className={`h-4 w-4 transition-transform ${showHeader ? "rotate-90" : ""}`} aria-hidden="true" />
                {showHeader ? "Hide raw headers" : "Raw Headers (Optional)"}
              </button>
                <button type="button" onClick={() => { setShowHeader(true); setShowHeaderGuide(!showHeaderGuide); }} aria-expanded={showHeaderGuide} aria-label="How to get raw headers" title="How to get raw headers" className="text-emerald-500 transition hover:text-emerald-600"><Info className="h-4 w-4 cursor-pointer" /></button>
                </div>
                <span className="max-w-[18rem] text-right text-xs text-slate-400">Authentication and delivery metadata</span>
              {showHeaderGuide && <div role="dialog" aria-label="Raw header instructions" className="absolute left-0 top-9 z-30 w-full max-w-md rounded-2xl border border-slate-200 bg-white p-5 text-xs leading-5 text-slate-700 shadow-2xl dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200"><div className="mb-3 flex items-center justify-between"><strong className="font-mono text-sm text-slate-900 dark:text-zinc-100">How to get raw headers</strong><button type="button" onClick={() => setShowHeaderGuide(false)} aria-label="Close instructions" className="text-slate-400 hover:text-slate-700 dark:hover:text-white"><X size={16} /></button></div><p className="mb-3 rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2 font-sans text-emerald-800 dark:border-emerald-900/70 dark:bg-emerald-950/40 dark:text-emerald-200"><strong>Recommended:</strong> Include raw headers for better scan results and stronger authentication checks.</p><div className="space-y-2 font-mono"><p><strong>Gmail:</strong> Open email &rarr; 3 dots (&#8942;) &rarr; <em>Show original</em> &rarr; <em>Copy to clipboard</em>.</p><p><strong>Outlook:</strong> View message details, or File &rarr; Properties &rarr; <em>Internet headers</em>.</p><p><strong>Apple Mail:</strong> View &rarr; Message &rarr; <em>Raw Source</em> (&#8984; + Option + U).</p></div></div>}
              </div>
              {showHeader && (
                <div className="mt-3">
                  <textarea
                    aria-label="Raw email headers"
                    rows={7}
                    maxLength={200000}
                    value={header}
                    onChange={(e) => setHeader(e.target.value)}
                    placeholder="Paste Authentication-Results, Received-SPF, DKIM-Signature, and other raw headers..."
                    className="w-full resize-y rounded-xl border border-slate-300 bg-slate-100 px-4 py-4 font-mono text-xs leading-5 text-slate-800 placeholder:text-slate-500 focus:border-slate-500 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-200 dark:placeholder:text-zinc-400"
                  />
                </div>
              )}

              {error && <p role="alert" className="mt-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>}
              <div className="mt-6 flex flex-col items-start justify-between gap-4 border-t border-slate-100 pt-6 sm:flex-row sm:items-center">
                <p className="text-xs leading-5 text-slate-400">Results are advisory. Verify high-impact requests independently.</p>
                <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row">
                <button type="button" onClick={clearAll} disabled={loading} className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-200 bg-transparent px-4 py-3.5 text-sm font-semibold text-slate-600 transition hover:border-red-300 hover:text-red-600 disabled:opacity-50 dark:border-slate-700 dark:text-slate-300 dark:hover:border-red-800 dark:hover:text-red-300"><Trash2 size={17} />Clear all</button>
                <button disabled={loading} className="group inline-flex min-w-52 items-center justify-center gap-2 rounded-xl bg-emerald-500 px-5 py-3.5 text-sm font-bold text-slate-950 shadow-lg shadow-emerald-500/15 transition hover:-translate-y-0.5 hover:bg-emerald-400 disabled:cursor-wait disabled:opacity-70">
                  {loading ? <><span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950/30 border-t-slate-950" />Scanning signals&hellip;</> : <><ScanSearch className="h-5 w-5 transition group-hover:rotate-6" />Scan email for threat</>}
                </button>
                </div>
              </div>
            </div>
          </div>
        </form>

        {result && (
          <section id="results" className="card-enter scroll-mt-6 pt-12" aria-live="polite">
            <div className="mb-5 flex items-center gap-3">
              <span className="text-xs font-bold uppercase tracking-[.22em] text-emerald-600">Threat report</span>
              <span className="h-px flex-1 bg-emerald-500/20" />
              <div className="flex items-center gap-2"><button type="button" onClick={copyReport} title="Copy formatted report" className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-2 text-xs font-semibold text-slate-600 transition hover:border-emerald-400 hover:text-emerald-700 dark:border-slate-700 dark:bg-zinc-900 dark:text-slate-300">{copied ? <Check size={14} /> : <Clipboard size={14} />}{copied ? "Copied" : "Copy report"}</button><button type="button" onClick={downloadPdf} title="Download branded PDF" className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-200 bg-emerald-50 px-2.5 py-2 text-xs font-semibold text-emerald-700 transition hover:border-emerald-400 dark:border-emerald-900/70 dark:bg-emerald-950/40 dark:text-emerald-300"><Download size={14} />Download PDF</button></div>
            </div>

            <div className="grid gap-5 lg:grid-cols-[.85fr_1.15fr]">
              <div className="rounded-3xl border border-slate-200 bg-white p-7 shadow-panel dark:border-zinc-800 dark:bg-zinc-900">
                <Gauge score={result.overall_score} level={result.risk_level} />
              </div>
              <div className="rounded-3xl bg-slate-950 p-7 text-white shadow-panel dark:bg-emerald-950/60">
                <p className="text-xs font-bold uppercase tracking-[.18em] text-emerald-400">What to do next</p>
                <p className="mt-4 text-base leading-7 text-white/80">{result.educational_advice}</p>
              </div>
            </div>

            <div className="mt-5 grid gap-5 lg:grid-cols-2">
              <div className="rounded-3xl border border-slate-200 bg-white p-7 shadow-panel dark:border-zinc-800 dark:bg-zinc-900">
                <div className="mb-6 flex items-end justify-between">
                  <div>
                    <p className="text-xs font-bold uppercase tracking-[.18em] text-slate-400">Evidence</p>
                    <h3 className="mt-1 text-xl font-semibold tracking-tight">Pinpointed anomalies</h3>
                  </div>
                  <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-600 dark:bg-slate-800 dark:text-slate-300">{result.flagged_issues.length} signals</span>
                </div>
                <div className="max-h-[31rem] space-y-3 overflow-y-auto pr-1">
                  {(["Critical", "Warning", "Informational"] as Severity[]).flatMap((severity) =>
                    grouped[severity].map((issue, index) => (
                      <article key={`${severity}-${index}`} className={`rounded-2xl border p-4 ${severityStyles[severity]}`}>
                        <div className="mb-1.5 flex items-center justify-between gap-3">
                          <h4 className="text-sm font-semibold">{issue.category}</h4>
                          <span className="text-[10px] font-bold uppercase tracking-wider">{severity}</span>
                        </div>
                        <p className="text-xs leading-5 opacity-80">{issue.description}</p>
                      </article>
                    )),
                  )}
                  {!result.flagged_issues.length && <p className="rounded-2xl bg-emerald-50 p-4 text-sm text-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-200">No notable anomalies were detected.</p>}
                </div>
              </div>

              <div className="rounded-3xl border border-slate-200 bg-white p-7 shadow-panel dark:border-zinc-800 dark:bg-zinc-900">
                <p className="text-xs font-bold uppercase tracking-[.18em] text-slate-400">Destination analysis</p>
                <h3 className="mt-1 text-xl font-semibold tracking-tight">Uncloaked links</h3>
                <div className="mt-6 overflow-hidden rounded-2xl border border-slate-200">
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[520px] text-left text-xs">
                      <thead className="bg-slate-50 text-[10px] uppercase tracking-wider text-slate-500 dark:bg-slate-800 dark:text-slate-300">
                        <tr><th className="px-4 py-3 font-semibold">Original</th><th className="px-4 py-3 font-semibold">Final target</th><th className="px-4 py-3 font-semibold">Verdict</th></tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {result.uncloaked_urls.map((url, index) => (
                          <tr key={index} className="align-top">
                            <td className="max-w-40 break-all px-4 py-4 text-slate-500">{url.original_url}</td>
                            <td className="max-w-48 break-all px-4 py-4 font-medium text-ink dark:text-slate-100">{url.final_url}</td>
                            <td className="px-4 py-4"><span className={`rounded-full px-2.5 py-1 font-bold ${url.is_suspicious ? "bg-red-100 text-red-700" : "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300"}`}>{url.is_suspicious ? "Suspicious" : "Clear"}</span></td>
                          </tr>
                        ))}
                        {!result.uncloaked_urls.length && <tr><td colSpan={3} className="px-4 py-10 text-center text-slate-400">No web links found in this message.</td></tr>}
                      </tbody>
                    </table>
                  </div>
                </div>
                <div className="mt-5 rounded-2xl border border-emerald-200 bg-emerald-50 p-4 dark:border-emerald-900/70 dark:bg-emerald-950/30">
                  <h4 className="text-sm font-semibold text-emerald-900 dark:text-emerald-200">Legitimate-link practice</h4>
                  <p className="mt-1 text-xs leading-5 text-emerald-900/70 dark:text-emerald-200/70">Trusted brands generally link directly to their official HTTPS domain. Open the organization&apos;s app or type its known address yourself instead of following an unexpected email link.</p>
                </div>
              </div>
            </div>
          </section>
        )}
      </section>

      <SiteFooter />
    </main>
  );
}

