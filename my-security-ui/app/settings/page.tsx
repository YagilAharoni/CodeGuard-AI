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
    setSavedMessage("Settings saved.");
    window.setTimeout(() => setSavedMessage(""), 1800);
  };

  const logoutEverywhere = async () => {
    await logoutSession();
    router.replace("/");
  };

  return (
    <AppShell title="Settings" subtitle="Control default scan behavior and account session">
      <div className="grid gap-6 lg:grid-cols-2">
        <section className="rounded-2xl border border-[#30363d] bg-[#161b22] p-6 space-y-5">
          <div>
            <h2 className="text-xl font-bold text-white">Preferences</h2>
            <p className="text-sm text-gray-400 mt-1">These preferences apply to your dashboard experience.</p>
          </div>

          <div className="space-y-2">
            <label className="text-sm text-gray-300">Default Persona</label>
            <div className="flex gap-2">
              <button
                onClick={() => setPreferences((prev) => ({ ...prev, defaultPersona: "Student" }))}
                className={`px-4 py-2 rounded-lg border text-sm ${
                  preferences.defaultPersona === "Student"
                    ? "border-cyan-500/40 bg-cyan-500/20 text-cyan-300"
                    : "border-[#30363d]"
                }`}
              >
                Student
              </button>
              <button
                onClick={() => setPreferences((prev) => ({ ...prev, defaultPersona: "Professional" }))}
                className={`px-4 py-2 rounded-lg border text-sm ${
                  preferences.defaultPersona === "Professional"
                    ? "border-purple-500/40 bg-purple-500/20 text-purple-300"
                    : "border-[#30363d]"
                }`}
              >
                Professional
              </button>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={saveSettings}
              className="px-4 py-2 rounded-lg bg-cyan-600 text-white text-sm hover:bg-cyan-500"
            >
              Save Preferences
            </button>
            {savedMessage ? <span className="text-sm text-green-400">{savedMessage}</span> : null}
          </div>
        </section>

        <section className="rounded-2xl border border-[#30363d] bg-[#161b22] p-6 space-y-5">
          <div>
            <h2 className="text-xl font-bold text-white">Account & Session</h2>
            <p className="text-sm text-gray-400 mt-1">Session security and account metadata.</p>
          </div>

          <div className="rounded-xl border border-[#30363d] bg-[#0d1117] p-4">
            <div className="text-xs text-gray-500 uppercase tracking-wide">Current Username</div>
            <div className="text-lg font-semibold text-cyan-300 mt-1">{user?.username || "Unknown"}</div>
          </div>

          <button
            onClick={logoutEverywhere}
            className="px-4 py-2 rounded-lg border border-red-500/40 bg-red-500/10 text-red-300 hover:bg-red-500/20 text-sm"
          >
            Sign Out
          </button>
        </section>
      </div>
    </AppShell>
  );
}
