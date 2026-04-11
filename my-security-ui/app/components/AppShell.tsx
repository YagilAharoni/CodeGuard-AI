"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { clearAuthSession, getStoredUser } from "../lib/auth";

interface AppShellProps {
  title: string;
  subtitle?: string;
  children: ReactNode;
}

const navItems = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/history", label: "History" },
  { href: "/reports", label: "Reports" },
  { href: "/settings", label: "Settings" },
];

export default function AppShell({ title, subtitle, children }: AppShellProps) {
  const pathname = usePathname();
  const router = useRouter();
  const username = getStoredUser()?.username ?? "anonymous";

  const logout = () => {
    clearAuthSession();
    router.push("/");
  };

  return (
    <div className="min-h-screen bg-[#0A0C10] text-[#c9d1d9]">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_20%_20%,rgba(0,240,255,0.08),transparent_40%),radial-gradient(circle_at_85%_10%,rgba(138,43,226,0.12),transparent_35%),radial-gradient(circle_at_70%_80%,rgba(11,94,215,0.1),transparent_45%)]" />
      <nav className="relative border-b border-[#30363d] bg-[#161b22]/85 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-6 py-4 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <div className="text-white font-bold text-2xl">{title}</div>
            {subtitle ? <div className="text-sm text-gray-400 mt-1">{subtitle}</div> : null}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {navItems.map((item) => {
              const active = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`px-3 py-2 rounded-lg text-sm border transition ${
                    active
                      ? "bg-cyan-500/20 border-cyan-500/40 text-cyan-300"
                      : "border-[#30363d] hover:bg-[#1d232b]"
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
            <div className="ml-1 px-3 py-2 rounded-lg border border-[#30363d] bg-[#0d1117] text-sm text-cyan-300">
              {username}
            </div>
            <button
              onClick={logout}
              className="px-3 py-2 rounded-lg border border-[#30363d] hover:bg-red-500/20 hover:border-red-500/40 text-sm"
            >
              Logout
            </button>
          </div>
        </div>
      </nav>
      <main className="relative max-w-7xl mx-auto px-6 py-8">{children}</main>
    </div>
  );
}
