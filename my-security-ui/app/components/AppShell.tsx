"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { getStoredUser, logoutSession } from "../lib/auth";

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

  const logout = async () => {
    await logoutSession();
    router.push("/");
  };

  return (
    <div className="min-h-screen bg-[#050505] text-[#A1A1AA] font-sans selection:bg-[#E8FF5A] selection:text-[#000]">
      {/* Dynamic crypto-style neon glow backgrounds */}
      <div className="fixed inset-0 pointer-events-none z-0">
        <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-[#E8FF5A]/10 blur-[150px] rounded-full" />
        <div className="absolute top-[20%] right-[-10%] w-[40%] h-[60%] bg-[#8B5CF6]/10 blur-[150px] rounded-full" />
        <div className="absolute bottom-[-10%] left-[20%] w-[60%] h-[40%] bg-[#06B6D4]/10 blur-[150px] rounded-full" />
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI4IiBoZWlnaHQ9IjgiPjxyZWN0IHdpZHRoPSI4IiBoZWlnaHQ9IjgiIGZpbGw9IiNmZmYiIGZpbGwtb3BhY2l0eT0iMC4wMSIvPjxwYXRoIGQ9Ik0wIDBMOCA4Wk04IDBMMCA4WiIgc3Ryb2tlPSIjZmZmIiBzdHJva2Utb3BhY2l0eT0iMC4wMiIvPjwvc3ZnPg==')] opacity-40 mix-blend-overlay pointer-events-none" />
      </div>
      
      <nav className="relative z-40 border-b border-white/5 bg-[#0A0A0A]/60 backdrop-blur-xl sticky top-0 px-6 py-4">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center md:justify-between gap-6">
          <div className="flex flex-col">
            <h1 className="text-white font-black text-3xl tracking-tight flex items-center gap-2">
              <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-[#E8FF5A] to-[#22D3EE] flex items-center justify-center">
                <div className="w-3 h-3 bg-black rounded-sm rotate-45" />
              </div>
              {title}
            </h1>
            {subtitle && <p className="text-sm text-[#A1A1AA] mt-1 font-medium">{subtitle}</p>}
          </div>
          
          <div className="flex flex-wrap items-center gap-3">
            <div className="hidden md:flex bg-[#121212] border border-white/10 rounded-full p-1">
              {navItems.map((item) => {
                const active = pathname === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`px-5 py-2 rounded-full text-sm font-semibold transition-all duration-300 ${
                      active
                        ? "bg-white text-black shadow-[0_0_15px_rgba(255,255,255,0.3)]"
                        : "text-[#A1A1AA] hover:text-white hover:bg-white/5"
                    }`}
                  >
                    {item.label}
                  </Link>
                );
              })}
            </div>
            
            {/* Mobile Nav Only */}
            <div className="flex md:hidden gap-1 flex-wrap w-full mt-2">
              {navItems.map((item) => {
                const active = pathname === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`px-4 py-2 rounded-full text-xs font-semibold ${
                      active ? "bg-white text-black" : "bg-[#121212] border border-white/10 text-[#A1A1AA]"
                    }`}
                  >
                    {item.label}
                  </Link>
                );
              })}
            </div>

            <div className="flex items-center gap-3 ml-2 border-l border-white/10 pl-4">
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-[#E8FF5A]/30 bg-[#E8FF5A]/5 text-xs font-mono text-[#E8FF5A]">
                <div className="w-1.5 h-1.5 rounded-full bg-[#E8FF5A] animate-pulse" />
                {username}
              </div>
              <button
                onClick={logout}
                className="px-4 py-2 rounded-full border border-white/10 bg-[#121212] text-white hover:bg-red-500 hover:border-red-500 transition-colors text-sm font-semibold"
              >
                Sign Out
              </button>
            </div>
          </div>
        </div>
      </nav>
      
      <main className="relative z-10 max-w-7xl mx-auto px-6 py-10">{children}</main>
    </div>
  );
}
