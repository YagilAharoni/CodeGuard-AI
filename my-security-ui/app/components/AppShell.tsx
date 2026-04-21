"use client";

import { useEffect, useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { getStoredUser, logoutSession } from "../lib/auth";

interface AppShellProps {
  title: string;
  subtitle?: string;
  children: ReactNode;
}

const navItems = [
  { href: "/dashboard", label: "Scanner" },
  { href: "/history", label: "History" },
  { href: "/reports", label: "Reports" },
  { href: "/settings", label: "Settings" },
];

export default function AppShell({ title, subtitle, children }: AppShellProps) {
  const pathname = usePathname();
  const router = useRouter();
  const [username, setUsername] = useState("anonymous");

  useEffect(() => {
    const user = getStoredUser();
    if (user) setUsername(user.username);
  }, []);

  const logout = async () => {
    await logoutSession();
    router.push("/");
  };

  return (
    <div className="min-h-screen bg-[#030303] text-[#A1A1AA] font-sans selection:bg-[#E8FF5A] selection:text-[#000]">
      {/* Dynamic crypto-style neon glow backgrounds */}
      <div className="fixed inset-0 pointer-events-none z-0">
        <div className="absolute top-[-10%] left-[-10%] w-[60%] h-[60%] bg-[#E8FF5A]/5 blur-[150px] rounded-full animate-float" />
        <div className="absolute top-[20%] right-[-10%] w-[40%] h-[60%] bg-[#8B5CF6]/5 blur-[150px] rounded-full animate-float" style={{ animationDelay: '2s' }} />
        <div className="absolute bottom-[-10%] left-[20%] w-[60%] h-[40%] bg-[#00F0FF]/5 blur-[150px] rounded-full animate-float" style={{ animationDelay: '4s' }} />
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI4IiBoZWlnaHQ9IjgiPjxyZWN0IHdpZHRoPSI4IiBoZWlnaHQ9IjgiIGZpbGw9IiNmZmYiIGZpbGwtb3BhY2l0eT0iMC4wMSIvPjxpbGluZSB4MT0iMCIgeTE9IjgiIHgyPSI4IiB5Mj0iMCIgc3Ryb2tlPSIjZmZmIiBzdHJva2Utb3BhY2l0eT0iMC4wMSIvPjwvc3ZnPg==')] opacity-40 mix-blend-overlay pointer-events-none" />
      </div>
      
      <nav className="relative z-40 border-b border-white/5 bg-[#050505]/70 backdrop-blur-2xl sticky top-0 px-6 py-4 shadow-[0_4px_30px_rgba(0,0,0,0.5)]">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center md:justify-between gap-6">
          <div className="flex flex-col animate-slide-up">
            <h1 className="text-white font-black text-3xl tracking-tight flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-[#E8FF5A] to-[#22D3EE] flex items-center justify-center shadow-[0_0_15px_rgba(232,255,90,0.2)]">
                <div className="w-4 h-4 bg-black rounded-sm rotate-45" />
              </div>
              {title}
            </h1>
            {subtitle && <p className="text-sm text-[#A1A1AA] mt-1.5 font-medium ml-1">{subtitle}</p>}
          </div>
          
          <div className="flex flex-wrap items-center gap-4 animate-slide-up" style={{ animationDelay: '0.1s' }}>
            <div className="hidden md:flex bg-[#0A0A0A] border border-white/10 rounded-2xl p-1.5 shadow-inner">
              {navItems.map((item) => {
                const active = pathname === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`px-5 py-2.5 rounded-xl text-sm font-bold transition-all duration-300 ${
                      active
                        ? "bg-white text-black shadow-[0_0_20px_rgba(255,255,255,0.4)] scale-[1.02]"
                        : "text-[#A1A1AA] hover:text-white hover:bg-white/10"
                    }`}
                  >
                    {item.label}
                  </Link>
                );
              })}
            </div>
            
            {/* Mobile Nav Only */}
            <div className="flex md:hidden gap-2 flex-wrap w-full mt-2">
              {navItems.map((item) => {
                const active = pathname === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`px-4 py-2.5 rounded-xl text-xs font-bold ${
                      active ? "bg-white text-black shadow-lg" : "bg-[#0A0A0A] border border-white/10 text-[#A1A1AA]"
                    }`}
                  >
                    {item.label}
                  </Link>
                );
              })}
            </div>

            <div className="flex items-center gap-3 ml-2 md:border-l border-white/10 md:pl-4">
              <div className="flex items-center gap-2 px-4 py-2 bg-[#0A0A0A] rounded-xl border border-[#E8FF5A]/20 text-xs font-mono font-bold text-[#E8FF5A] shadow-[inset_0_0_10px_rgba(232,255,90,0.05)]">
                <div className="w-2 h-2 rounded-full bg-[#E8FF5A] animate-pulse-glow" />
                {username}
              </div>
              <button
                onClick={logout}
                className="px-5 py-2.5 rounded-xl border border-white/10 bg-[#0A0A0A] text-white hover:bg-red-500 hover:border-red-500 hover:shadow-[0_0_20px_rgba(239,68,68,0.4)] transition-all duration-300 text-sm font-bold"
              >
                Sign Out
              </button>
            </div>
          </div>
        </div>
      </nav>
      
      <main className="relative z-10 max-w-7xl mx-auto px-4 md:px-6 py-10 animate-slide-up" style={{ animationDelay: '0.2s' }}>
        {children}
      </main>
    </div>
  );
}
