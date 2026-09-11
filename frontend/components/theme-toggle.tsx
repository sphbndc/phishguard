"use client";

import { Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";
import { useSyncExternalStore } from "react";

export function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();
  const mounted = useSyncExternalStore(() => () => {}, () => true, () => false);
  if (!mounted) return <span className="h-11 w-11" aria-hidden="true" />;
  const dark = resolvedTheme === "dark";
  return (
    <button type="button" onClick={() => setTheme(dark ? "light" : "dark")} aria-label={`Switch to ${dark ? "light" : "dark"} mode`} title={`Switch to ${dark ? "light" : "dark"} mode`} className="grid h-11 w-11 place-items-center rounded-xl border border-slate-200 bg-white text-slate-600 transition hover:border-emerald-400 hover:text-emerald-600 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300">
      {dark ? <Sun size={17} /> : <Moon size={17} />}
    </button>
  );
}
