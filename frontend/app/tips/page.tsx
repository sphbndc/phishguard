import { AlertTriangle, BadgeCheck, BookOpen, ExternalLink, Fingerprint, ListChecks, MailCheck, Newspaper, ShieldCheck } from "lucide-react";
import { SiteFooter } from "@/components/site-footer";
import { SiteHeader } from "@/components/site-header";
import StackSpread from "@/components/ui/stack-spread";

const sources = {
  apwg: "https://apwg.org/trendsreports",
  verizon: "https://www.verizon.com/business/resources/T1e0/reports/2026-dbir-data-breach-investigations-report.pdf",
  cisa: "https://www.cisa.gov/sites/default/files/2023-01/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf",
  spf: "https://www.rfc-editor.org/rfc/rfc7208.html",
  dkim: "https://www.rfc-editor.org/rfc/rfc6376.html",
  dmarc: "https://www.rfc-editor.org/rfc/rfc7489.html",
  iso: "https://www.iso.org/standard/27001",
  iso27002: "https://www.iso.org/standard/75652.html",
  itu: "https://www.itu.int/rec/t-rec-x.1205-200804-i",
  oecd: "https://www.oecd.org/en/publications/2006/09/oecd-anti-spam-toolkit-of-recommended-policies-and-measures_g1gh741e.html",
};

const standards = [
  { icon: MailCheck, code: "SPF", title: "Sender Policy Framework", copy: "An SPF TXT policy identifies hosts authorized to send for a domain. A receiver evaluates the SMTP MAIL FROM identity; DMARC then checks whether that identity aligns with the visible From domain.", href: sources.spf, ref: "RFC 7208" },
  { icon: Fingerprint, code: "DKIM", title: "DomainKeys Identified Mail", copy: "DKIM attaches a cryptographic signature to selected headers and the body. The receiver retrieves the public key from DNS and verifies that the signing domain takes responsibility for an unaltered message.", href: sources.dkim, ref: "RFC 6376" },
  { icon: BadgeCheck, code: "DMARC", title: "Domain-based Message Authentication", copy: "DMARC compares the RFC5322.From domain with passing SPF or DKIM identifiers and publishes a receiver policy: monitor, quarantine, or reject. Alignment is the key anti-spoofing signal.", href: sources.dmarc, ref: "RFC 7489" },
];

const frameworks = [
  ["ISO/IEC 27001:2022", "Requirements for an Information Security Management System (ISMS): risk treatment, leadership, continual improvement, and protection of confidentiality, integrity, and availability.", sources.iso],
  ["ISO/IEC 27002:2022", "Implementation guidance and control objectives that complement an ISO/IEC 27001 ISMS, including organizational, people, physical, and technological controls.", sources.iso27002],
  ["ITU-T X.1205", "An internationally recognized overview of cybersecurity concepts, safeguards, risk-management approaches, and threat mitigation for the cyber environment.", sources.itu],
  ["OECD Anti-Spam Toolkit", "A cross-border policy framework combining regulation, enforcement cooperation, technical measures, education, metrics, industry practice, and international exchange.", sources.oecd],
];

const checklist = ["Pause before responding; urgency is a persuasion technique, not proof.", "Inspect the full sender address and the domain after the @, not only the display name.", "Open the organization's app or type a known address yourself instead of using an unexpected link.", "Never share passwords, PINs, recovery phrases, payment data, or one-time codes by email.", "Report the message through your organization's phishing process, then delete or quarantine it."];

function SourceLink({ href, children }: { href: string; children: React.ReactNode }) {
  return <a href={href} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-semibold text-emerald-700 underline decoration-emerald-300 underline-offset-2 hover:text-emerald-500 dark:text-emerald-300">{children}<ExternalLink size={12} /></a>;
}

export default function TipsPage() {
  return <main className="min-h-screen bg-gradient-to-br from-slate-50 via-emerald-50/60 to-slate-50 text-slate-900 transition-colors duration-200 dark:from-zinc-950 dark:via-emerald-950/35 dark:to-zinc-950 dark:text-slate-100"><SiteHeader /><section className="mx-auto max-w-7xl px-5 pb-20 pt-14 lg:px-8 lg:pt-20">
    <div className="max-w-3xl"><p className="mb-4 text-xs font-bold uppercase tracking-[.24em] text-emerald-600">Security knowledge base</p><h1 className="text-4xl font-semibold leading-tight tracking-[-.04em] text-slate-950 dark:text-white sm:text-6xl">The signals behind<br /><span className="text-emerald-500">safer inboxes.</span></h1><p className="mt-6 max-w-2xl text-base leading-7 text-slate-600 dark:text-slate-300">A practical field guide to phishing trends, email authentication, international security frameworks, and the habits that prevent social engineering.</p></div>

    <section className="mt-14"><div className="mb-6 flex items-center gap-3"><Newspaper className="text-emerald-500" size={20} /><div><p className="text-xs font-bold uppercase tracking-[.18em] text-emerald-600">Threat landscape</p><h2 className="text-2xl font-semibold text-slate-950 dark:text-white">Phishing is a volume and trust problem</h2></div></div><div className="grid gap-4 md:grid-cols-3">
      <article className="rounded-3xl border border-slate-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900"><p className="font-mono text-3xl font-bold text-emerald-500">1,003,924</p><h3 className="mt-3 font-semibold text-slate-950 dark:text-white">phishing attacks observed</h3><p className="mt-2 text-sm leading-6 text-slate-600 dark:text-slate-300">APWG&rsquo;s Q1 2025 report recorded its largest quarterly total since late 2023.</p><p className="mt-4 text-xs"><SourceLink href={sources.apwg}>APWG Q1 2025 report</SourceLink></p></article>
      <article className="rounded-3xl border border-slate-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900"><p className="font-mono text-3xl font-bold text-emerald-500">+33%</p><h3 className="mt-3 font-semibold text-slate-950 dark:text-white">wire-transfer BEC growth</h3><p className="mt-2 text-sm leading-6 text-slate-600 dark:text-slate-300">APWG reported wire-transfer BEC attacks increased quarter-over-quarter in Q1 2025.</p><p className="mt-4 text-xs"><SourceLink href={sources.apwg}>APWG trend data</SourceLink></p></article>
      <article className="rounded-3xl border border-slate-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900"><p className="font-mono text-3xl font-bold text-emerald-500">16%</p><h3 className="mt-3 font-semibold text-slate-950 dark:text-white">of breaches in the social-engineering pattern</h3><p className="mt-2 text-sm leading-6 text-slate-600 dark:text-slate-300">Verizon&rsquo;s 2026 DBIR describes social engineering as a major breach pattern and reports 5,302 related incidents.</p><p className="mt-4 text-xs"><SourceLink href={sources.verizon}>Verizon 2026 DBIR</SourceLink></p></article>
    </div><p className="mt-4 max-w-3xl text-xs leading-5 text-slate-500">These are observed reports, not a universal probability of clicking or compromise. CISA recommends phishing-resistant MFA as a defense-in-depth control; <SourceLink href={sources.cisa}>CISA guidance</SourceLink>.</p></section>

    <section className="mt-16"><StackSpread scrollLength={185} /></section>

    <section className="mt-16"><div className="mb-6 flex items-center gap-3"><BookOpen className="text-emerald-500" size={20} /><h2 className="text-2xl font-semibold text-slate-950 dark:text-white">Global email authentication standards</h2></div><div className="grid gap-4 md:grid-cols-3">{standards.map(({ icon: Icon, code, title, copy, href, ref }) => <article key={code} className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-zinc-900"><div className="mb-7 flex items-center justify-between"><span className="grid h-10 w-10 place-items-center rounded-xl bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300"><Icon size={20} /></span><span className="font-mono text-xs font-bold tracking-widest text-emerald-600">{code}</span></div><h3 className="text-lg font-semibold text-slate-950 dark:text-white">{title}</h3><p className="mt-3 text-sm leading-6 text-slate-600 dark:text-slate-300">{copy}</p><p className="mt-5 text-xs"><SourceLink href={href}>{ref}</SourceLink></p></article>)}</div></section>

    <div className="mt-16 grid gap-5 lg:grid-cols-[1.1fr_.9fr]"><section className="rounded-3xl bg-slate-950 p-7 text-white dark:bg-zinc-900"><p className="text-xs font-bold uppercase tracking-[.18em] text-emerald-400">International frameworks &amp; policies</p><h2 className="mt-2 text-2xl font-semibold">Trust is a system, not a single check.</h2><div className="mt-7 divide-y divide-white/10">{frameworks.map(([name, copy, href]) => <details key={name} className="group py-4"><summary className="flex cursor-pointer list-none items-center justify-between gap-4 font-semibold"><span>{name}</span><span className="text-emerald-400">+</span></summary><p className="mt-3 max-w-xl text-sm leading-6 text-white/60">{copy} <span className="ml-1"><SourceLink href={href}>Official documentation</SourceLink></span></p></details>)}</div></section><section className="rounded-3xl border border-emerald-200 bg-emerald-50 p-7 dark:border-emerald-900/70 dark:bg-emerald-950/30"><ListChecks className="text-emerald-600 dark:text-emerald-400" size={25} /><h2 className="mt-4 text-2xl font-semibold text-slate-950 dark:text-white">Suspicious email checklist</h2><ol className="mt-6 space-y-4">{checklist.map((item, i) => <li key={item} className="flex gap-3 text-sm leading-6 text-slate-700 dark:text-slate-200"><span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-emerald-500 text-xs font-bold text-slate-950">{i + 1}</span><span>{item}</span></li>)}</ol></section></div>

    <section className="mt-5 rounded-2xl border border-slate-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900"><div className="flex items-center gap-3"><ShieldCheck className="text-emerald-500" size={20} /><h2 className="text-lg font-semibold text-slate-950 dark:text-white">References &amp; regulatory documentation</h2></div><p className="mt-3 text-sm leading-6 text-slate-600 dark:text-slate-300">Official technical and policy sources used in this guide: <SourceLink href={sources.spf}>RFC 7208</SourceLink>, <SourceLink href={sources.dkim}>RFC 6376</SourceLink>, <SourceLink href={sources.dmarc}>RFC 7489</SourceLink>, <SourceLink href={sources.iso}>ISO/IEC 27001</SourceLink>, <SourceLink href={sources.iso27002}>ISO/IEC 27002</SourceLink>, <SourceLink href={sources.itu}>ITU-T X.1205</SourceLink>, and <SourceLink href={sources.oecd}>OECD Anti-Spam Toolkit</SourceLink>.</p></section>
    <div className="mt-5 flex gap-4 rounded-2xl border border-amber-200 bg-amber-50 p-5 text-sm leading-6 text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200"><AlertTriangle className="mt-0.5 shrink-0" size={18} /><p><strong>Remember:</strong> authentication confirms infrastructure and alignment; it does not prove that a request is appropriate. Use context, least privilege, and an independent channel for high-impact actions.</p></div>
  </section><SiteFooter /></main>;
}

