"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import AppShell from "../components/AppShell";
import { getStoredUser, isAuthenticated, logoutSession } from "../lib/auth";

const SETTINGS_KEY = "codeguard_preferences";

type Persona = "Student" | "Professional";

interface Preferences {
  defaultPersona: Persona;
}

const defaultPreferences: Preferences = {
  defaultPersona: "Student",
};

export default function SettingsPage() {
  const router = useRouter();
  const user = getStoredUser();

  const [preferences, setPreferences] = useState<Preferences>(defaultPreferences);
  const [savedMessage, setSavedMessage] = useState("");

  useEffect(() => {
    if (!isAuthenticated()) {
      router.replace("/");
      return;
    }

    try {
      const raw = localStorage.getItem(SETTINGS_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as Partial<Preferences>;
        setPreferences({
          defaultPersona:
            parsed.defaultPersona === "Professional" ? "Professional" : "Student",
        });
      }
    } catch {
      setPreferences(defaultPreferences);
    }
  }, [router]);

  const saveSettings = () => {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(preferences));
    setSavedMessage("saved");
    window.setTimeout(() => setSavedMessage(""), 2000);
  };

  const logoutEverywhere = async () => {
    await logoutSession();
    router.replace("/");
  };

  const personaOptions: { value: Persona; label: string; desc: string; color: string; glow: string }[] = [
    {
      value: "Student",
      label: "Student",
      desc: "Simplified explanations, more context on each finding.",
      color: "border-[#00F0FF]/40 bg-[#00F0FF]/10 text-[#00F0FF]",
      glow: "shadow-[0_0_20px_rgba(0,240,255,0.2)]",
    },
    {
      value: "Professional",
      label: "Professional",
      desc: "Dense technical output, minimal explanations, raw CVE data.",
      color: "border-purple-500/40 bg-purple-500/10 text-purple-300",
      glow: "shadow-[0_0_20px_rgba(168,85,247,0.2)]",
    },
  ];

  return (
    <AppShell title="Settings" subtitle="Control default scan behavior and account session">
      <div className="w-full max-w-4xl mx-auto space-y-8">

        {/* Header */}
        <section className="glass-panel rounded-[2rem] p-8 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-48 h-full bg-gradient-to-l from-purple-500/5 to-transparent pointer-events-none" />
          <p className="text-xs tracking-[0.2em] font-bold text-purple-400 uppercase mb-3">Configuration</p>
          <h2 className="text-3xl font-black text-white mb-2">User Preferences</h2>
          <p className="text-gray-400 text-sm">Customize how CodeGuard AI behaves during scans and sessions.</p>
        </section>

        {/* Persona Selector */}
        <section className="glass-panel rounded-[2rem] p-8 space-y-6">
          <div>
            <h3 className="text-lg font-bold text-white mb-1">Default Scan Persona</h3>
            <p className="text-gray-500 text-sm">Controls AI verbosity and output depth for all scans.</p>
          </div>

          <div className="grid md:grid-cols-2 gap-4">
            {personaOptions.map((option) => {
              const active = preferences.defaultPersona === option.value;
              return (
                <button
                  key={option.value}
                  onClick={() => setPreferences((prev) => ({ ...prev, defaultPersona: option.value }))}
                  className={`text-left p-6 rounded-2xl border transition-all duration-300 ${
                    active
                      ? `${option.color} ${option.glow}`
                      : "border-white/10 bg-[#0A0A0A] text-gray-400 hover:border-white/20"
                  }`}
                >
                  <div className="flex items-center justify-between mb-3">
                    <span className="font-black text-lg">{option.label}</span>
                    <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center transition-all ${
                      active ? "border-current" : "border-white/20"
                    }`}>
                      {active && <div className="w-2.5 h-2.5 rounded-full bg-current" />}
                    </div>
                  </div>
                  <p className="text-xs leading-relaxed opacity-70">{option.desc}</p>
                </button>
              );
            })}
          </div>

          <div className="flex items-center gap-4 pt-2">
            <button
              onClick={saveSettings}
              className="px-8 py-3 rounded-2xl bg-[#E8FF5A] text-black font-black hover:brightness-110 hover:shadow-[0_0_20px_rgba(232,255,90,0.4)] transition-all text-sm uppercase tracking-wide"
            >
              Save Preferences
            </button>
            {savedMessage && (
              <span className="flex items-center gap-2 text-[#E8FF5A] text-sm font-bold animate-slide-up">
                <span className="w-4 h-4 rounded-full bg-[#E8FF5A]/20 border border-[#E8FF5A]/40 flex items-center justify-center text-xs">✓</span>
                Preferences saved
              </span>
            )}
          </div>
        </section>

        {/* Account Info */}
        <section className="glass-panel rounded-[2rem] p-8 space-y-6">
          <div>
            <h3 className="text-lg font-bold text-white mb-1">Account Information</h3>
            <p className="text-gray-500 text-sm">Your current session details.</p>
          </div>

          <div className="flex items-center gap-4 p-5 rounded-2xl bg-[#050505] border border-white/5">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-[#E8FF5A]/20 to-[#00F0FF]/20 flex items-center justify-center text-white font-black text-lg border border-white/10">
              {(user?.username?.[0] || "?").toUpperCase()}
            </div>
            <div>
              <p className="text-white font-bold">{user?.username || "Unknown"}</p>
              <p className="text-gray-500 text-xs font-mono">Session Active</p>
            </div>
            <div className="ml-auto flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#E8FF5A]/10 border border-[#E8FF5A]/20">
              <span className="w-2 h-2 rounded-full bg-[#E8FF5A] animate-pulse-glow" />
              <span className="text-[#E8FF5A] text-xs font-bold font-mono">Online</span>
            </div>
          </div>
        </section>

        {/* Danger Zone */}
        <section className="rounded-[2rem] p-8 border border-red-500/20 bg-red-500/5 space-y-4">
          <div>
            <h3 className="text-lg font-bold text-red-300 mb-1">Danger Zone</h3>
            <p className="text-gray-500 text-sm">Actions here cannot be undone and will terminate your session.</p>
          </div>
          <div className="flex items-center justify-between p-5 rounded-2xl bg-[#050505] border border-red-500/10">
            <div>
              <p className="text-white font-bold text-sm">Sign Out</p>
              <p className="text-gray-500 text-xs mt-0.5">Terminate this session and clear all local credentials.</p>
            </div>
            <button
              onClick={logoutEverywhere}
              className="px-6 py-2.5 rounded-xl border border-red-500/40 bg-red-500/10 text-red-300 hover:bg-red-500/20 hover:shadow-[0_0_20px_rgba(239,68,68,0.3)] transition-all text-sm font-bold whitespace-nowrap"
            >
              Sign Out
            </button>
          </div>
        </section>

      </div>
    </AppShell>
  );
}
