"use client";
import React, { useEffect, useState } from "react";
import Head from "next/head";
import axios from "axios";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

const formatDate = (timestamp: string) => new Date(timestamp).toLocaleString("he-IL", {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit"
});

export default function HistoryPage() {
  const [history, setHistory] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selectedA, setSelectedA] = useState<string>("");
  const [selectedB, setSelectedB] = useState<string>("");
  const [comparison, setComparison] = useState<any>(null);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const response = await axios.get("http://localhost:8000/history");
        setHistory(response.data.history || []);
      } catch (err: any) {
        setError("לא ניתן למשוך היסטוריית סריקות. בדוק את השרת.");
      }
    };
    fetchHistory();
  }, []);

  useEffect(() => {
    if (history.length === 0) return;
  }, [history]);

  const chartData = history.map((entry) => ({
    timestamp: formatDate(entry.timestamp),
    High: entry.stats?.High || 0,
    Medium: entry.stats?.Medium || 0,
    Low: entry.stats?.Low || 0,
  }));

  const compareScans = async () => {
    if (!selectedA || !selectedB) {
      setError("בחר שתי סריקות להשוואה.");
      return;
    }

    try {
      const response = await axios.get("http://localhost:8000/compare", {
        params: { scan_a: selectedA, scan_b: selectedB }
      });
      setComparison(response.data);
      setError(null);
    } catch (err: any) {
      setError("לא ניתן לבצע השוואה כרגע. בדוק את מזהי הסריקות.");
    }
  };

  return (
    <div className="min-h-screen bg-[#0d1117] text-[#c9d1d9] font-sans pb-20">
      <Head>
        <title>CodeGuard AI - Security Trends</title>
      </Head>

      <nav className="border-b border-[#30363d] bg-[#161b22]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-white">דאשבורד היסטורי</h1>
            <p className="text-gray-500 text-sm mt-1">ניהול: מעקב אחר רמת האבטחה לאורך זמן ושיפור הצוות.</p>
          </div>
          <div className="flex gap-3">
            <a href="/" className="px-4 py-2 rounded-lg border border-[#30363d] hover:bg-[#1c2128] transition">חזרה לדשבורד</a>
            <a href="/history" className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 transition text-white">📜 History</a>
          </div>
        </div>
      </nav>

      <main className="max-w-6xl mx-auto px-6 py-10 space-y-10">
        {error && (
          <div className="rounded-xl bg-red-500/10 border border-red-500/30 p-4 text-red-200">
            {error}
          </div>
        )}

        <section className="grid gap-6 md:grid-cols-3">
          <div className="rounded-3xl border border-[#30363d] bg-[#161b22] p-6">
            <h2 className="text-xl font-semibold text-white mb-3">ניהול</h2>
            <p className="text-gray-400 text-sm leading-relaxed">
              מנהל צוות יכול לראות אם כמות הפגיעויות יורדת ככל שהפרויקט מתקדם, ולוודא שהצוות סוגר חורי אבטחה לאורך זמן.
            </p>
          </div>
          <div className="rounded-3xl border border-[#30363d] bg-[#161b22] p-6">
            <h2 className="text-xl font-semibold text-white mb-3">סריקות שמורות</h2>
            <p className="text-gray-400 text-sm">סה"כ סריקות: {history.length}</p>
            <p className="text-gray-400 text-sm">סריקה אחרונה: {history[0]?.timestamp ? formatDate(history[0].timestamp) : "לא נמצאה"}</p>
          </div>
          <div className="rounded-3xl border border-[#30363d] bg-[#161b22] p-6">
            <h2 className="text-xl font-semibold text-white mb-3">וידוי</h2>
            <p className="text-gray-400 text-sm leading-relaxed">
              השוואת גרסאות עוזרת לוודא שחורי אבטחה מדווחים בסריקה קודמת אכן נסגרו בסריקה הנוכחית.
            </p>
          </div>
        </section>

        <section className="rounded-3xl border border-[#30363d] bg-[#161b22] p-6">
          <div className="mb-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div>
              <h2 className="text-2xl font-bold">Security Trends</h2>
              <p className="text-gray-500">גרף רמת האבטחה של כל הסריקות לאורך זמן.</p>
            </div>
          </div>
          <div className="w-full h-[420px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData} margin={{ top: 20, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid stroke="#30363d" strokeDasharray="3 3" />
                <XAxis dataKey="timestamp" stroke="#8b949e" tick={{ fill: '#c9d1d9', fontSize: 12 }} />
                <YAxis stroke="#8b949e" tick={{ fill: '#c9d1d9', fontSize: 12 }} />
                <Tooltip cursor={{ stroke: '#2563eb', strokeWidth: 1 }} contentStyle={{ backgroundColor: '#0d1117', border: '1px solid #30363d', borderRadius: 8, color: '#c9d1d9' }} />
                <Legend wrapperStyle={{ color: '#c9d1d9' }} />
                <Line type="monotone" dataKey="High" stroke="#ef4444" strokeWidth={2} dot={{ r: 4 }} />
                <Line type="monotone" dataKey="Medium" stroke="#eab308" strokeWidth={2} dot={{ r: 4 }} />
                <Line type="monotone" dataKey="Low" stroke="#3b82f6" strokeWidth={2} dot={{ r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="rounded-3xl border border-[#30363d] bg-[#161b22] p-6">
          <h2 className="text-2xl font-bold mb-4">השוואת גרסאות</h2>
          <div className="grid gap-4 md:grid-cols-3 mb-6">
            <select value={selectedA} onChange={(e) => setSelectedA(e.target.value)} className="w-full rounded-xl border border-[#30363d] bg-[#0d1117] p-3 text-white">
              <option value="">בחר סריקה ראשונה</option>
              {history.map((entry) => (
                <option key={entry.scan_id} value={entry.scan_id}>
                  {entry.timestamp} • {entry.status}
                </option>
              ))}
            </select>
            <select value={selectedB} onChange={(e) => setSelectedB(e.target.value)} className="w-full rounded-xl border border-[#30363d] bg-[#0d1117] p-3 text-white">
              <option value="">בחר סריקה שנייה</option>
              {history.map((entry) => (
                <option key={entry.scan_id} value={entry.scan_id}>
                  {entry.timestamp} • {entry.status}
                </option>
              ))}
            </select>
            <button onClick={compareScans} className="w-full rounded-xl bg-purple-600 px-4 py-3 text-white font-semibold hover:bg-purple-500 transition">
              השווה בין סריקות
            </button>
          </div>

          {comparison && (
            <div className="space-y-6">
              <div className="grid gap-4 md:grid-cols-3">
                <div className="rounded-2xl border border-[#30363d] bg-[#0d1117] p-4">
                  <div className="text-sm text-gray-400">סריקה ישנה</div>
                  <div className="mt-2 text-white font-bold">{comparison.scan_a.timestamp}</div>
                  <div className="text-sm text-gray-400">סטטוס: {comparison.scan_a.status}</div>
                </div>
                <div className="rounded-2xl border border-[#30363d] bg-[#0d1117] p-4">
                  <div className="text-sm text-gray-400">סריקה חדשה</div>
                  <div className="mt-2 text-white font-bold">{comparison.scan_b.timestamp}</div>
                  <div className="text-sm text-gray-400">סטטוס: {comparison.scan_b.status}</div>
                </div>
                <div className="rounded-2xl border border-[#30363d] bg-[#0d1117] p-4">
                  <div className="text-sm text-gray-400">סיכום שינוי</div>
                  <div className="mt-2 text-white font-bold">{comparison.comparison.resolved_count} נסגרו</div>
                  <div className="text-sm text-gray-400">{comparison.comparison.new_count} חדשים</div>
                </div>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <div className="rounded-2xl border border-[#30363d] bg-[#0d1117] p-4">
                  <h3 className="text-lg font-semibold mb-3">חורים שנסגרו</h3>
                  {comparison.comparison.resolved_issues.length === 0 ? (
                    <p className="text-gray-400">לא נמצאו חורים שנסגרו.</p>
                  ) : (
                    <ul className="space-y-2 text-sm text-gray-300">
                      {comparison.comparison.resolved_issues.slice(0, 5).map((item: any, idx: number) => (
                        <li key={idx}>{item.file_name}: {item.issue_description}</li>
                      ))}
                    </ul>
                  )}
                </div>
                <div className="rounded-2xl border border-[#30363d] bg-[#0d1117] p-4">
                  <h3 className="text-lg font-semibold mb-3">חורים חדשים</h3>
                  {comparison.comparison.new_issues.length === 0 ? (
                    <p className="text-gray-400">לא נמצאו חורים חדשים.</p>
                  ) : (
                    <ul className="space-y-2 text-sm text-gray-300">
                      {comparison.comparison.new_issues.slice(0, 5).map((item: any, idx: number) => (
                        <li key={idx}>{item.file_name}: {item.issue_description}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </div>
          )}
        </section>

        <section className="rounded-3xl border border-[#30363d] bg-[#161b22] p-6">
          <h2 className="text-2xl font-bold mb-4">סריקות אחרונות</h2>
          <div className="space-y-4">
            {history.length === 0 ? (
              <div className="rounded-2xl bg-[#0d1117] p-6 text-gray-400">לא נמצאו סריקות עדיין.</div>
            ) : (
              history.map((entry) => (
                <div key={entry.scan_id} className="rounded-2xl border border-[#30363d] bg-[#0d1117] p-4 grid gap-2 md:grid-cols-4">
                  <div>
                    <div className="text-sm text-gray-400">תאריך</div>
                    <div className="text-white">{formatDate(entry.timestamp)}</div>
                  </div>
                  <div>
                    <div className="text-sm text-gray-400">סטטוס</div>
                    <div className="text-white">{entry.status}</div>
                  </div>
                  <div>
                    <div className="text-sm text-gray-400">High / Medium / Low</div>
                    <div className="text-white">{entry.stats.High} / {entry.stats.Medium} / {entry.stats.Low}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm text-gray-400">מזהה סריקה</div>
                    <div className="text-gray-300 text-xs font-mono truncate">{entry.scan_id}</div>
                  </div>
                </div>
              ))
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
