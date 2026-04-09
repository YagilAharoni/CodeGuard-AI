"use client";

import React, { Suspense, useEffect, useMemo, useState } from "react";
import axios from "axios";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useRouter } from "next/navigation";
import AppShell from "../components/AppShell";
import { getAuthHeaders, getStoredUser, isAuthenticated } from "../lib/auth";
import { validateScanId } from "../lib/validation";

const formatDate = (timestamp: string) =>
  new Date(timestamp).toLocaleString("en-US", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });

function HistoryPageContent() {
  const router = useRouter();
  const username = getStoredUser()?.username || "anonymous";

  const [history, setHistory] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selectedA, setSelectedA] = useState<string>("");
  const [selectedB, setSelectedB] = useState<string>("");
  const [comparison, setComparison] = useState<any>(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    if (!isAuthenticated()) {
      router.replace("/");
    }
  }, [router]);

  useEffect(() => {
    if (!mounted || !isAuthenticated()) return;

    const fetchHistory = async () => {
      try {
        const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
        const response = await axios.get(`${apiBase}/history`, {
          headers: {
            ...getAuthHeaders(),
          },
        });
        setHistory(response.data.history || []);
      } catch {
        setError("Unable to retrieve scan history. Please login again.");
      }
    };

    fetchHistory();
  }, [mounted]);

  const chartData = useMemo(
    () =>
      history.map((entry) => ({
        timestamp: formatDate(entry.timestamp),
        High: entry.stats?.High || 0,
        Medium: entry.stats?.Medium || 0,
        Low: entry.stats?.Low || 0,
      })),
    [history],
  );

  const compareScans = async () => {
    if (!selectedA || !selectedB) {
      setError("Please select two scans for comparison.");
      return;
    }

    if (!validateScanId(selectedA) || !validateScanId(selectedB)) {
      setError("Invalid scan ID selection.");
      return;
    }

    try {
      const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const response = await axios.get(`${apiBase}/compare`, {
        params: { scan_a: selectedA, scan_b: selectedB },
        headers: {
          ...getAuthHeaders(),
        },
      });
      setComparison(response.data);
      setError(null);
    } catch {
      setError("Unable to compare these scans.");
    }
  };

  if (!mounted) {
    return <div className="min-h-screen bg-[#0d1117]" />;
  }

  return (
    <AppShell title="Scan History" subtitle={`Account: ${username}`}>
      <div className="space-y-8">
        {error && <div className="rounded-xl bg-red-500/10 border border-red-500/30 p-4 text-red-200">{error}</div>}

        <section className="rounded-3xl border border-white/10 bg-[#111722]/80 p-6 md:p-7 backdrop-blur-md relative overflow-hidden">
          <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(130deg,rgba(255,255,255,0.04),transparent_35%,rgba(0,240,255,0.06)_70%,transparent)]" />
          <div className="relative z-10">
            <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300 mb-2">Timeline Intelligence</div>
            <h2 className="text-3xl md:text-4xl font-black text-white leading-tight">Track Security Progress Over Time</h2>
            <p className="text-sm text-gray-400 mt-2 max-w-3xl">
              Compare scan snapshots, monitor risk movement, and verify whether remediation is reducing your attack surface.
            </p>
          </div>
        </section>

        <section className="grid gap-4 md:grid-cols-3">
          <div className="rounded-2xl border border-[#30363d] bg-[#161b22]/85 p-5 backdrop-blur-sm relative overflow-hidden">
            <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(120deg,rgba(255,255,255,0.02),transparent_45%,rgba(34,211,238,0.05)_90%)]" />
            <div className="text-xs text-gray-400 uppercase tracking-wide">Total Scans</div>
            <div className="text-3xl font-black text-white mt-2">{history.length}</div>
          </div>
          <div className="rounded-2xl border border-[#30363d] bg-[#161b22]/85 p-5 backdrop-blur-sm relative overflow-hidden">
            <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(120deg,rgba(255,255,255,0.02),transparent_45%,rgba(168,85,247,0.05)_90%)]" />
            <div className="text-xs text-gray-400 uppercase tracking-wide">Latest Scan</div>
            <div className="text-sm text-gray-200 mt-2">{history[0]?.timestamp ? formatDate(history[0].timestamp) : "Not available"}</div>
          </div>
          <div className="rounded-2xl border border-[#30363d] bg-[#161b22]/85 p-5 backdrop-blur-sm relative overflow-hidden">
            <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(120deg,rgba(255,255,255,0.02),transparent_45%,rgba(59,130,246,0.05)_90%)]" />
            <div className="text-xs text-gray-400 uppercase tracking-wide">Status Mix</div>
            <div className="text-sm text-gray-200 mt-2">{history.filter((h) => h.status === "SAFE").length} safe / {history.filter((h) => h.status !== "SAFE").length} vulnerable</div>
          </div>
        </section>

        <section className="rounded-3xl border border-[#30363d] bg-[#161b22]/85 p-6 backdrop-blur-sm relative overflow-hidden">
          <div className="absolute inset-0 pointer-events-none opacity-35 bg-[radial-gradient(circle_at_1px_1px,rgba(255,255,255,0.12)_1px,transparent_0)] [background-size:14px_14px]" />
          <h2 className="text-xl font-bold text-white mb-4">Vulnerability Trend</h2>
          <div style={{ minHeight: 360, height: 360 }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <CartesianGrid stroke="#30363d" strokeDasharray="3 3" />
                <XAxis dataKey="timestamp" stroke="#8b949e" tick={{ fill: "#c9d1d9", fontSize: 12 }} />
                <YAxis stroke="#8b949e" tick={{ fill: "#c9d1d9", fontSize: 12 }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0d1117",
                    border: "1px solid #30363d",
                    borderRadius: 8,
                    color: "#c9d1d9",
                  }}
                />
                <Legend />
                <Line type="monotone" dataKey="High" stroke="#ef4444" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="Medium" stroke="#eab308" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="Low" stroke="#3b82f6" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="rounded-3xl border border-[#30363d] bg-[#161b22]/85 p-6 space-y-4 backdrop-blur-sm relative overflow-hidden">
          <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(140deg,rgba(255,255,255,0.03),transparent_35%,rgba(34,211,238,0.04)_80%,transparent)]" />
          <h2 className="text-xl font-bold text-white">Compare Two Scans</h2>
          <div className="grid gap-3 md:grid-cols-3">
            <select
              value={selectedA}
              onChange={(e) => setSelectedA(e.target.value)}
              className="w-full rounded-xl border border-[#30363d] bg-[#0d1117] p-3 text-white"
            >
              <option value="">Select first scan</option>
              {history.map((entry) => (
                <option key={`a-${entry.scan_id}`} value={entry.scan_id}>
                  {entry.timestamp} | {entry.status}
                </option>
              ))}
            </select>
            <select
              value={selectedB}
              onChange={(e) => setSelectedB(e.target.value)}
              className="w-full rounded-xl border border-[#30363d] bg-[#0d1117] p-3 text-white"
            >
              <option value="">Select second scan</option>
              {history.map((entry) => (
                <option key={`b-${entry.scan_id}`} value={entry.scan_id}>
                  {entry.timestamp} | {entry.status}
                </option>
              ))}
            </select>
            <button
              onClick={compareScans}
              className="w-full rounded-xl bg-gradient-to-r from-cyan-600 to-purple-600 px-4 py-3 text-white font-semibold hover:from-cyan-500 hover:to-purple-500 transition"
            >
              Compare
            </button>
          </div>

          {comparison && (
            <div className="grid gap-4 md:grid-cols-3">
              <div className="rounded-xl border border-[#30363d] bg-[#0d1117] p-4">
                <div className="text-xs text-gray-400 uppercase">Resolved</div>
                <div className="text-2xl font-black text-green-400 mt-1">{comparison.comparison.resolved_count}</div>
              </div>
              <div className="rounded-xl border border-[#30363d] bg-[#0d1117] p-4">
                <div className="text-xs text-gray-400 uppercase">New</div>
                <div className="text-2xl font-black text-red-400 mt-1">{comparison.comparison.new_count}</div>
              </div>
              <div className="rounded-xl border border-[#30363d] bg-[#0d1117] p-4">
                <div className="text-xs text-gray-400 uppercase">Unchanged</div>
                <div className="text-2xl font-black text-blue-400 mt-1">{comparison.comparison.unchanged_count}</div>
              </div>
            </div>
          )}
        </section>
      </div>
    </AppShell>
  );
}

export default function HistoryPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#0d1117]" />}>
      <HistoryPageContent />
    </Suspense>
  );
}
