"use client";

import React, { useEffect, useMemo, useState } from "react";
import axios from "axios";
import { useRouter } from "next/navigation";
import AppShell from "../components/AppShell";
import { getAuthHeaders, isAuthenticated } from "../lib/auth";
import { sanitizeQueryText, validateScanId } from "../lib/validation";

export default function ReportsPage() {
  const router = useRouter();
  const [history, setHistory] = useState<any[]>([]);
  const [query, setQuery] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const formatReportFilename = (timestamp?: string) => {
    const date = timestamp ? new Date(timestamp) : new Date();
    const safeDate = Number.isNaN(date.getTime()) ? new Date() : date;
    const year = safeDate.getFullYear();
    const month = String(safeDate.getMonth() + 1).padStart(2, "0");
    const day = String(safeDate.getDate()).padStart(2, "0");
    const hours = String(safeDate.getHours()).padStart(2, "0");
    const minutes = String(safeDate.getMinutes()).padStart(2, "0");
    return `Security_Report_${year}-${month}-${day}_${hours}-${minutes}.pdf`;
  };

  const formatDate = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleString("en-US", {
        year: "numeric", month: "short", day: "numeric",
        hour: "2-digit", minute: "2-digit",
      });
    } catch {
      return timestamp;
    }
  };

  useEffect(() => {
    if (!isAuthenticated()) {
      router.replace("/");
      return;
    }

    const fetchReports = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
        const response = await axios.get(`${apiBase}/history`, {
          headers: { ...getAuthHeaders() },
        });
        setHistory(response.data.history || []);
      } catch {
        setError("Unable to load reports. Please sign in again.");
      } finally {
        setIsLoading(false);
      }
    };

    fetchReports();
  }, [router]);

  const downloadReport = async (reportId: string) => {
    const normalizedReportId = (reportId || "").trim();
    if (!validateScanId(normalizedReportId)) {
      setError("Invalid report ID format.");
      return;
    }
    setDownloadingId(reportId);
    try {
      const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const response = await axios.get(`${apiBase}/export-pdf`, {
        params: { report_id: normalizedReportId },
        responseType: "blob",
        headers: { ...getAuthHeaders() },
      });
      const blob = new Blob([response.data]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const report = history.find((item) => item.scan_id === normalizedReportId);
      a.download = formatReportFilename(report?.timestamp);
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      setError("Failed to download this report.");
    } finally {
      setDownloadingId(null);
    }
  };

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return history;
    return history.filter((item) => {
      const source = (item.source || "").toLowerCase();
      const status = (item.status || "").toLowerCase();
      const id = (item.scan_id || "").toLowerCase();
      return source.includes(q) || status.includes(q) || id.includes(q);
    });
  }, [history, query]);

  const totalVuln = history.filter((h) => h.status === "VULNERABLE").length;
  const totalSafe = history.filter((h) => h.status !== "VULNERABLE").length;

  return (
    <AppShell title="Reports" subtitle="Search, filter & export security audit reports">
      <div className="space-y-8 w-full max-w-5xl mx-auto">

        {/* Header banner */}
        <section className="glass-panel rounded-[2rem] p-8 md:p-10 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-full bg-gradient-to-l from-[#E8FF5A]/5 to-transparent pointer-events-none" />
          <div className="relative z-10">
            <p className="text-xs tracking-[0.2em] font-bold text-[#E8FF5A] uppercase mb-3">Report Library</p>
            <h2 className="text-3xl md:text-4xl font-black text-white leading-tight mb-3">
              Security Audit Archive
            </h2>
            <p className="text-gray-400 text-sm max-w-2xl leading-relaxed">
              Filter historical scans, inspect findings, and export professional PDF reports or code patch files.
            </p>
          </div>
        </section>

        {/* Stats row */}
        <div className="grid grid-cols-3 gap-4">
          {[
            { label: "Total Reports", value: history.length, color: "text-white" },
            { label: "Vulnerable", value: totalVuln, color: "text-red-400" },
            { label: "Secure", value: totalSafe, color: "text-[#E8FF5A]" },
          ].map((stat) => (
            <div key={stat.label} className="glass-panel rounded-2xl p-6 text-center">
              <p className="text-xs text-gray-500 uppercase tracking-widest font-mono mb-2">{stat.label}</p>
              <p className={`text-4xl font-black ${stat.color}`}>{stat.value}</p>
            </div>
          ))}
        </div>

        {/* Search + list */}
        <section className="glass-panel rounded-[2rem] p-6 md:p-8">
          <div className="flex flex-col md:flex-row gap-4 md:items-center md:justify-between mb-6">
            <h2 className="text-xl font-bold text-white">All Reports</h2>
            <input
              value={query}
              onChange={(e) => setQuery(sanitizeQueryText(e.target.value))}
              placeholder="Search by scan ID, source, or status…"
              className="w-full md:w-80 rounded-2xl border border-white/10 bg-[#050505] px-5 py-3 text-sm text-white focus:outline-none focus:border-[#E8FF5A]/40 placeholder:text-gray-600 font-mono transition-colors"
            />
          </div>

          {error && (
            <div className="mb-6 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-red-300 font-mono text-sm animate-slide-up">
              <span className="font-bold text-red-400 mr-2">ERR:</span>{error}
            </div>
          )}

          {isLoading && (
            <div className="flex items-center gap-3 text-gray-400 font-mono text-sm py-8 justify-center">
              <span className="w-5 h-5 rounded-full border-2 border-white/20 border-t-[#E8FF5A] animate-spin" />
              Loading reports…
            </div>
          )}

          <div className="space-y-4">
            {!isLoading && filtered.length === 0 && (
              <div className="flex flex-col items-center justify-center py-16 border border-dashed border-white/10 rounded-2xl text-center">
                <div className="w-14 h-14 rounded-full border border-white/10 flex items-center justify-center mb-4 text-2xl">📂</div>
                <p className="text-gray-400 font-mono text-sm">No reports found.</p>
                <p className="text-gray-600 text-xs mt-1">Run a scan from the Dashboard to generate one.</p>
              </div>
            )}

            {filtered.map((item) => {
              const isVuln = item.status === "VULNERABLE";
              const high = item.stats?.High || 0;
              const med = item.stats?.Medium || 0;
              const low = item.stats?.Low || 0;
              const total = high + med + low || 1;
              const isDownloading = downloadingId === item.scan_id;

              return (
                <div
                  key={item.scan_id}
                  className="rounded-2xl border border-white/5 bg-[#0A0A0A] p-6 hover:border-white/20 transition-all group relative overflow-hidden"
                >
                  {/* left accent bar */}
                  <div className={`absolute left-0 top-0 w-1 h-full ${isVuln ? "bg-red-500" : "bg-[#E8FF5A]"} opacity-40 group-hover:opacity-100 transition-opacity`} />

                  <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4 pl-3">
                    <div className="space-y-2 flex-1 min-w-0">
                      <div className="flex items-center gap-3 flex-wrap">
                        {/* Status badge */}
                        <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-widest ${
                          isVuln
                            ? "bg-red-500/10 border border-red-500/30 text-red-400"
                            : "bg-[#E8FF5A]/10 border border-[#E8FF5A]/30 text-[#E8FF5A]"
                        }`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${isVuln ? "bg-red-400 animate-pulse" : "bg-[#E8FF5A]"}`} />
                          {isVuln ? "Vulnerable" : "Secure"}
                        </span>
                        <span className="text-gray-400 text-xs font-mono">{formatDate(item.timestamp)}</span>
                      </div>

                      <p className="text-gray-300 text-sm font-mono truncate">{item.source || "local_upload"}</p>
                      <p className="text-gray-600 text-xs font-mono">ID: {item.scan_id}</p>

                      {/* Severity bar */}
                      {(high + med + low) > 0 && (
                        <div className="mt-3">
                          <div className="flex gap-1 text-xs text-gray-500 mb-1.5 font-mono">
                            <span className="text-red-400">{high}H</span>
                            <span className="mx-1 text-white/20">·</span>
                            <span className="text-yellow-400">{med}M</span>
                            <span className="mx-1 text-white/20">·</span>
                            <span className="text-blue-400">{low}L</span>
                          </div>
                          <div className="flex h-1.5 rounded-full overflow-hidden bg-white/5 w-full max-w-xs">
                            {high > 0 && <div className="bg-red-500" style={{ width: `${(high / total) * 100}%` }} />}
                            {med > 0 && <div className="bg-yellow-400" style={{ width: `${(med / total) * 100}%` }} />}
                            {low > 0 && <div className="bg-blue-400" style={{ width: `${(low / total) * 100}%` }} />}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Action buttons */}
                    <div className="flex items-center gap-2 flex-shrink-0 flex-wrap">
                      <button
                        onClick={() => router.push("/history")}
                        className="px-4 py-2.5 rounded-xl border border-white/10 bg-[#111] text-white text-xs font-bold hover:bg-white/10 transition-colors"
                      >
                        Inspect
                      </button>
                      <button
                        onClick={async () => {
                          try {
                            const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
                            const response = await axios.get(`${apiBase}/export-patch`, {
                              params: { report_id: item.scan_id },
                              responseType: "blob",
                              headers: { ...getAuthHeaders() },
                            });
                            const blob = new Blob([response.data]);
                            const url = window.URL.createObjectURL(blob);
                            const a = document.createElement("a");
                            a.href = url;
                            a.download = `remediations_${item.scan_id}.patch`;
                            document.body.appendChild(a);
                            a.click();
                            a.remove();
                            window.URL.revokeObjectURL(url);
                          } catch {
                            setError("Failed to download code patches for this report.");
                          }
                        }}
                        className="px-4 py-2.5 rounded-xl bg-[#00F0FF]/10 border border-[#00F0FF]/30 text-[#00F0FF] text-xs font-bold hover:bg-[#00F0FF]/20 hover:shadow-[0_0_15px_rgba(0,240,255,0.2)] transition-all whitespace-nowrap"
                      >
                        Export Patch
                      </button>
                      <button
                        onClick={() => downloadReport(item.scan_id)}
                        disabled={isDownloading}
                        className="px-4 py-2.5 rounded-xl bg-[#E8FF5A]/10 border border-[#E8FF5A]/30 text-[#E8FF5A] text-xs font-bold hover:bg-[#E8FF5A]/20 hover:shadow-[0_0_15px_rgba(232,255,90,0.3)] transition-all whitespace-nowrap disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                      >
                        {isDownloading ? (
                          <><span className="w-3 h-3 border border-[#E8FF5A]/30 border-t-[#E8FF5A] rounded-full animate-spin" />Exporting…</>
                        ) : "Export PDF"}
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      </div>
    </AppShell>
  );
}
