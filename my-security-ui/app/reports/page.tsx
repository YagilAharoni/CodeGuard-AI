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
          headers: {
            ...getAuthHeaders(),
          },
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

    try {
      const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const response = await axios.get(`${apiBase}/export-pdf`, {
        params: { report_id: normalizedReportId },
        responseType: "blob",
        headers: {
          ...getAuthHeaders(),
        },
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

  return (
    <AppShell title="Reports Center" subtitle="Search, filter, and export previous security reports">
      <div className="space-y-6">
        <section className="rounded-3xl border border-white/10 bg-[#111722]/80 p-6 md:p-7 backdrop-blur-md relative overflow-hidden">
          <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(130deg,rgba(255,255,255,0.04),transparent_35%,rgba(138,43,226,0.07)_70%,transparent)]" />
          <div className="relative z-10">
            <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300 mb-2">Report Library</div>
            <h2 className="text-3xl md:text-4xl font-black text-white leading-tight">Security Reports With Fast Export</h2>
            <p className="text-sm text-gray-400 mt-2 max-w-3xl">
              Filter historical scans, inspect context quickly, and export professional PDF reports for documentation and review.
            </p>
          </div>
        </section>

        <section className="rounded-2xl border border-[#30363d] bg-[#161b22]/85 p-5 grid gap-4 md:grid-cols-3 backdrop-blur-sm">
          <div>
            <div className="text-xs text-gray-400 uppercase tracking-wide">Total Reports</div>
            <div className="text-3xl font-black text-white mt-2">{history.length}</div>
          </div>
          <div>
            <div className="text-xs text-gray-400 uppercase tracking-wide">Vulnerable Reports</div>
            <div className="text-3xl font-black text-red-400 mt-2">{history.filter((h) => h.status === "VULNERABLE").length}</div>
          </div>
          <div>
            <div className="text-xs text-gray-400 uppercase tracking-wide">Safe Reports</div>
            <div className="text-3xl font-black text-green-400 mt-2">{history.filter((h) => h.status === "SAFE").length}</div>
          </div>
        </section>

        <section className="rounded-3xl border border-[#30363d] bg-[#161b22]/85 p-5 backdrop-blur-sm relative overflow-hidden">
          <div className="absolute inset-0 pointer-events-none opacity-30 bg-[radial-gradient(circle_at_1px_1px,rgba(255,255,255,0.12)_1px,transparent_0)] [background-size:14px_14px]" />
          <div className="flex flex-col md:flex-row gap-3 md:items-center md:justify-between mb-4">
            <h2 className="text-xl font-bold text-white">All Reports</h2>
            <input
              value={query}
              onChange={(e) => setQuery(sanitizeQueryText(e.target.value))}
              placeholder="Search by scan ID, source, or status"
              className="w-full md:w-96 rounded-xl border border-[#30363d] bg-[#0d1117] px-4 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
            />
          </div>

          {error ? <div className="mb-4 rounded-lg bg-red-500/10 border border-red-500/30 p-3 text-red-200">{error}</div> : null}
          {isLoading ? <div className="text-sm text-gray-400">Loading reports...</div> : null}

          <div className="space-y-3">
            {filtered.length === 0 && !isLoading ? (
              <div className="rounded-xl border border-[#30363d] bg-[#0d1117] p-4 text-gray-400">No reports found.</div>
            ) : null}

            {filtered.map((item) => (
              <div
                key={item.scan_id}
                className="rounded-2xl border border-[#30363d] bg-[#0f141d]/95 p-4 grid gap-3 md:grid-cols-[1fr_auto] md:items-center hover:border-cyan-500/35 transition-colors"
              >
                <div className="space-y-1">
                  <div className="text-xs text-gray-500 uppercase tracking-wide">{item.status}</div>
                  <div className="text-sm text-white">{item.timestamp}</div>
                  <div className="text-xs text-gray-400">{item.source || "local_upload"}</div>
                  <div className="text-xs text-gray-500 font-mono">ID: {item.scan_id}</div>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => router.push("/history")}
                    className="px-3 py-2 rounded-lg border border-[#30363d] text-sm hover:bg-[#1c2128]"
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
                    className="px-3 py-2 rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 text-white text-sm hover:from-emerald-500 hover:to-teal-500 whitespace-nowrap"
                  >
                    Export Patch
                  </button>
                  <button
                    onClick={() => downloadReport(item.scan_id)}
                    className="px-3 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-purple-600 text-white text-sm hover:from-cyan-500 hover:to-purple-500 whitespace-nowrap"
                  >
                    Export PDF
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </AppShell>
  );
}
