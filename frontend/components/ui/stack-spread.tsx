"use client";

import {
  Fingerprint,
  Globe2,
  Link2,
  LockKeyhole,
  MailCheck,
  ScanSearch,
  ShieldCheck,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import {
  motion,
  useReducedMotion,
  useScroll,
  useSpring,
  useTransform,
  type MotionValue,
} from "motion/react";
import { useEffect, useRef, useState } from "react";

type SignalCard = {
  title: string;
  detail: string;
  icon: LucideIcon;
  tone: [string, string];
  x: number;
  y: number;
  rotate: number;
};

const SIGNALS: SignalCard[] = [
  { title: "DMARC", detail: "Domain alignment", icon: ShieldCheck, tone: ["#6ee7b7", "#059669"], x: -38, y: -32, rotate: -13 },
  { title: "DKIM", detail: "Signed content", icon: Fingerprint, tone: ["#67e8f9", "#0891b2"], x: 30, y: -33, rotate: 15 },
  { title: "Sender", detail: "Identity check", icon: MailCheck, tone: ["#c4b5fd", "#7c3aed"], x: -32, y: -4, rotate: -5 },
  { title: "SPF", detail: "Authorized host", icon: Globe2, tone: ["#7dd3fc", "#0284c7"], x: 31, y: -5, rotate: 5 },
  { title: "Links", detail: "Destination scan", icon: Link2, tone: ["#fcd34d", "#f59e0b"], x: -31, y: 23, rotate: 7 },
  { title: "Intent", detail: "Language signals", icon: ScanSearch, tone: ["#f0abfc", "#c026d3"], x: 28, y: 23, rotate: -6 },
  { title: "Secrets", detail: "Harvesting cues", icon: LockKeyhole, tone: ["#fda4af", "#e11d48"], x: -12, y: 39, rotate: 3 },
  { title: "Verdict", detail: "Action guidance", icon: TriangleAlert, tone: ["#5eead4", "#0d9488"], x: 13, y: 39, rotate: -4 },
];

function SignalTile({ signal, progress, index, reduced, mobile }: { signal: SignalCard; progress: MotionValue<number>; index: number; reduced: boolean; mobile: boolean }) {
  const Icon = signal.icon;
  const targetX = signal.x * (mobile ? 0.58 : 1);
  const targetY = signal.y * (mobile ? 0.72 : 1);
  const translate = useTransform(progress, (value) => `translate(-50%, -50%) translate(${targetX * value}vw, ${targetY * value}vh)`);
  const rotate = useTransform(progress, [0, 0.28, 1], [signal.rotate, signal.rotate * 0.15, signal.rotate]);
  const scale = useTransform(progress, [0, 0.25, 1], [0.86, 1, 1]);

  return (
    <motion.article
      className="absolute left-1/2 top-1/2 h-28 w-40 rounded-2xl border border-white/30 p-3.5 text-zinc-950 shadow-2xl shadow-black/30 sm:h-40 sm:w-60 sm:p-5"
      style={{ background: `linear-gradient(135deg, ${signal.tone[0]}, ${signal.tone[1]})`, transform: translate, rotate: reduced ? 0 : rotate, scale, zIndex: index + 1 }}
    >
      <div className="flex items-start justify-between"><span className="grid h-9 w-9 place-items-center rounded-xl bg-white/35"><Icon size={18} /></span><span className="font-mono text-[10px] font-bold uppercase tracking-widest opacity-60">0{index + 1}</span></div>
      <h3 className="mt-5 text-base font-bold tracking-tight sm:mt-6 sm:text-xl">{signal.title}</h3>
      <p className="mt-1 text-xs font-medium opacity-70">{signal.detail}</p>
    </motion.article>
  );
}

export default function StackSpread({ scrollLength = 210 }: { scrollLength?: number }) {
  const stageRef = useRef<HTMLDivElement>(null);
  const [mobile, setMobile] = useState(false);
  const reduced = useReducedMotion() === true;
  useEffect(() => {
    const query = window.matchMedia("(max-width: 640px)");
    const update = () => setMobile(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);
  const { scrollYProgress } = useScroll({ target: stageRef, offset: ["start start", "end end"] });
  const progress = useSpring(scrollYProgress, { stiffness: 80, damping: 24, mass: 0.7 });
  const copyOpacity = useTransform(progress, [0.18, 0.5], [0, 1]);
  const copyY = useTransform(progress, [0.18, 0.55], [22, 0]);
  const hintOpacity = useTransform(progress, [0, 0.12], [1, 0]);

  return (
    <section ref={stageRef} className="relative w-full" style={{ height: `${scrollLength}vh` }} aria-label="PhishGuard security signal overview">
      <div className="sticky top-0 flex h-screen w-full items-center justify-center overflow-hidden rounded-3xl bg-zinc-950 px-6 text-center ring-1 ring-emerald-500/20">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(16,185,129,0.18),transparent_52%)]" />
        <motion.div className="pointer-events-none relative z-20 max-w-xl" style={{ opacity: copyOpacity, y: reduced ? 0 : copyY }}>
          <p className="text-xs font-bold uppercase tracking-[.24em] text-emerald-400">Signal stack</p>
          <h2 className="mt-4 text-4xl font-semibold tracking-[-.05em] text-zinc-100 sm:text-6xl">Trust is built from signals.</h2>
          <p className="mx-auto mt-5 max-w-md text-sm leading-6 text-zinc-400 sm:text-base">Scroll to separate the layers PhishGuard checks before it recommends your next safe action.</p>
        </motion.div>
        <div className="absolute inset-0 z-10">
          {SIGNALS.map((signal, index) => <SignalTile key={signal.title} signal={signal} progress={progress} index={index} reduced={reduced} mobile={mobile} />)}
        </div>
        <motion.p className="absolute bottom-8 z-30 text-[10px] font-bold uppercase tracking-[.25em] text-emerald-300/70" style={{ opacity: hintOpacity }}>Scroll to inspect</motion.p>
      </div>
    </section>
  );
}
