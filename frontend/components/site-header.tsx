import Link from "next/link";
import { ShieldCheck } from "lucide-react";
import { ThemeToggle } from "./theme-toggle";

export function SiteHeader() {
  return (
    <nav className="border-b border-emerald-200/70 bg-gradient-to-r from-white/95 via-emerald-50/90 to-white/95 backdrop-blur transition-colors duration-200 dark:border-emerald-900/60 dark:from-zinc-950/95 dark:via-emerald-950/70 dark:to-zinc-950/95">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4 lg:px-8">
        <Link href="/scanner" className="flex items-center gap-2.5 font-semibold tracking-tight text-slate-950 dark:text-white">
          <span className="grid h-9 w-9 place-items-center rounded-xl bg-emerald-500 text-slate-950"><ShieldCheck size={21} /></span>
          <span>PhishGuard <small className="ml-1 align-middle text-[11px] font-semibold tracking-normal text-emerald-600">by savicst</small></span>
        </Link>
        <div className="flex items-center gap-1.5 sm:gap-3">
          <Link href="/scanner" className="rounded-lg px-3 py-2 text-xs font-semibold text-slate-600 hover:bg-emerald-50 hover:text-emerald-700 dark:text-slate-300 dark:hover:bg-emerald-950/50 dark:hover:text-emerald-300">Scanner</Link>
          <Link href="/tips" className="rounded-lg px-3 py-2 text-xs font-semibold text-slate-600 hover:bg-emerald-50 hover:text-emerald-700 dark:text-slate-300 dark:hover:bg-emerald-950/50 dark:hover:text-emerald-300">Standards</Link>
          <ThemeToggle />
        </div>
      </div>
    </nav>
  );
}
