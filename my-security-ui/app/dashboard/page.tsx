"use client";

import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import AppShell from "../components/AppShell";
import { useScan } from "../hooks/useScan";
import { getAuthHeaders, getStoredUser } from "../lib/auth";
import axios from "axios";

export default function Dashboard() {


  const searchParams = useSearchParams();
  const [repoUrl, setRepoUrl] = useState("");
  const [persona] = useState("Student");
  const [selectedFiles, setSelectedFiles] = useState<FileList | null>(null);
  const [localError, setLocalError] = useState("");
  const username = getStoredUser()?.username;
  const { results, isScanning, error, scanGithubUrl, uploadFile } = useScan();
  const [healthScore, setHealthScore] = useState<number | null>(null);
  const [scoreLabel, setScoreLabel] = useState("");

  // Fetch scan history to compute security health score
  useEffect(() => {
    const fetchScore = async () => {
      try {
        const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
        const response = await axios.get(`${apiBase}/history`, {
          headers: { ...getAuthHeaders() },
        });
        const history: any[] = response.data.history || [];
        if (history.length === 0) return;
        const safe = history.filter((h) => h.status !== "VULNERABLE").length;
        const score = Math.round((safe / history.length) * 100);
        setHealthScore(score);
        if (score >= 80) setScoreLabel("Excellent");
        else if (score >= 60) setScoreLabel("Good");
        else if (score >= 40) setScoreLabel("Fair");
        else setScoreLabel("Critical");
      } catch {
        // score stays null, widget stays hidden
      }
    };
    fetchScore();
  }, []);

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError("");
    if (selectedFiles && selectedFiles.length > 0) {
      uploadFile(selectedFiles, persona, undefined, "local", username);
      return;
    }
    if (repoUrl.trim()) {
      scanGithubUrl(repoUrl, persona, undefined, "local", username);
      return;
    }
    setLocalError("Provide a GitHub URL or upload files before launching a scan.");
  };

  const actionHint = (() => {
    const action = (searchParams.get("action") || "").toLowerCase();
    if (action === "initialize") {
      return "Terminal initialized. Enter a GitHub URL or upload files, then execute Scan Protocol.";
    }
    if (action === "explore") {
      return "Engine matrix loaded. Choose a computation node and start your scan.";
    }
    return "";
  })();

  return (
    <AppShell title="Dashboard" subtitle="Matrix Control Center">
      <div className="relative z-10 w-full max-w-5xl mx-auto">
        <header className="mb-10 pb-6 text-center lg:text-left relative">
          <h1 className="text-4xl lg:text-5xl font-black tracking-tight text-white flex flex-col lg:flex-row items-center gap-4">
            Security <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#E8FF5A] to-[#00F0FF]">Terminal</span>
          </h1>
          <p className="text-gray-400 mt-4 font-mono text-xs uppercase tracking-[0.3em]">
            Execute deep-inspection protocol
          </p>
          <div className="absolute top-1/2 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-white/10 to-transparent -z-10 mt-6 lg:hidden"></div>
        </header>

        {/* Security Health Score Widget */}
        {healthScore !== null && (
          <div className="mb-8 glass-panel rounded-[2rem] p-6 md:p-8 flex flex-col md:flex-row items-center gap-8 animate-slide-up">
            {/* Ring */}
            <div className="relative flex-shrink-0">
              <svg width="120" height="120" viewBox="0 0 120 120">
                {/* Track */}
                <circle cx="60" cy="60" r="50" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="10" />
                {/* Score arc */}
                <circle
                  cx="60" cy="60" r="50"
                  fill="none"
                  stroke={healthScore >= 80 ? "#E8FF5A" : healthScore >= 60 ? "#00F0FF" : healthScore >= 40 ? "#eab308" : "#ef4444"}
                  strokeWidth="10"
                  strokeLinecap="round"
                  strokeDasharray={`${(healthScore / 100) * 314} 314`}
                  transform="rotate(-90 60 60)"
                  style={{ filter: `drop-shadow(0 0 8px ${healthScore >= 80 ? "rgba(232,255,90,0.6)" : healthScore >= 60 ? "rgba(0,240,255,0.6)" : healthScore >= 40 ? "rgba(234,179,8,0.6)" : "rgba(239,68,68,0.6)"})` }}
                />
                <text x="60" y="60" textAnchor="middle" dominantBaseline="middle" fill="white" fontSize="22" fontWeight="900">{healthScore}</text>
                <text x="60" y="76" textAnchor="middle" dominantBaseline="middle" fill="rgba(255,255,255,0.4)" fontSize="9" fontWeight="600">/ 100</text>
              </svg>
            </div>
            {/* Info */}
            <div className="flex-1 text-center md:text-left">
              <p className="text-xs font-mono uppercase tracking-[0.2em] text-gray-500 mb-2">Security Health Score</p>
              <p className={`text-4xl font-black mb-1 ${healthScore >= 80 ? "text-[#E8FF5A]" : healthScore >= 60 ? "text-[#00F0FF]" : healthScore >= 40 ? "text-yellow-400" : "text-red-400"}`}>
                {scoreLabel}
              </p>
              <p className="text-gray-400 text-sm font-medium leading-relaxed">
                Based on your scan history. A score of <strong className="text-white">{healthScore}%</strong> of scans returned secure results.
                {healthScore < 60 && " Consider re-scanning high-risk repositories."}
              </p>
            </div>
          </div>
        )}

        <section className="glass-panel rounded-[2rem] p-8 md:p-10 mb-12 hover-glow group transition-all">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-[#E8FF5A]/50 to-transparent opacity-50 group-hover:opacity-100 transition-opacity"></div>
          
          <div className="flex items-center gap-4 mb-8">
            <div className="w-10 h-10 rounded-xl bg-[#00F0FF]/10 flex justify-center items-center text-[#00F0FF] font-black border border-[#00F0FF]/20 shadow-[0_0_15px_rgba(0,240,255,0.2)]">1</div>
            <h2 className="text-2xl font-bold text-white tracking-tight">Initialize Target</h2>
          </div>

          <form onSubmit={handleScan} className="flex flex-col gap-6">
            <div className="relative group/input">
              <input
                type="text"
                placeholder="Launch target URL (e.g. https://github.com/user/repo)"
                className="w-full p-5 bg-[#050505] rounded-2xl border border-white/10 focus:border-[#E8FF5A]/50 focus:ring-1 focus:ring-[#E8FF5A]/30 text-white font-mono text-sm transition-all outline-none placeholder:text-gray-600 shadow-inner group-hover/input:border-white/20"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
              />
            </div>

            <div className="flex items-center justify-center w-full relative">
               <div className="h-[1px] bg-white/5 w-full"></div>
               <span className="absolute bg-[#0b0b0b] px-4 text-xs font-mono text-gray-500 uppercase tracking-widest">OR</span>
            </div>

            <div className="rounded-2xl border border-white/10 bg-[#050505] p-6 hover:border-white/20 transition-colors shadow-inner flex flex-col sm:flex-row gap-4 items-center justify-between">
              <label className="text-xs uppercase tracking-widest text-[#E8FF5A] font-bold font-mono">
                Upload Source Files
              </label>
              <input
                type="file"
                multiple
                className="w-full sm:w-auto text-sm text-gray-400 file:mr-4 file:rounded-xl file:border file:border-white/10 file:bg-[#111] file:px-6 file:py-2.5 file:font-bold file:text-white hover:file:bg-white/10 file:transition-colors file:cursor-pointer"
                onChange={(e) => setSelectedFiles(e.target.files)}
              />
            </div>
            
            <div className="flex flex-col md:flex-row gap-4 mt-2 justify-end">
               <button
                 type="submit"
                 disabled={isScanning}
                 className="md:w-[250px] px-8 py-5 bg-gradient-to-r from-[#E8FF5A] to-[#d4e84d] hover:brightness-110 text-black font-black uppercase tracking-wide rounded-2xl transition-all shadow-[0_0_30px_rgba(232,255,90,0.3)] disabled:opacity-50 disabled:cursor-not-allowed hover:scale-[1.02] active:scale-95 flex items-center justify-center gap-3"
               >
                 {isScanning ? (
                   <>
                     <span className="w-5 h-5 rounded-full border-2 border-black/20 border-t-black animate-spin"></span> 
                     <span>Scanning</span>
                   </>
                 ) : (
                   <>
                     <span>Execute</span> <span className="text-xl leading-none">→</span>
                   </>
                 )}
               </button>
            </div>
          </form>
          
          {(error || localError) && (
             <div className="mt-6 p-4 rounded-xl border border-red-500/30 bg-red-500/10 text-red-100 font-mono text-sm shadow-[0_0_15px_rgba(239,68,68,0.2)] animate-slide-up">
               <span className="text-red-400 font-bold mr-2">WARN:</span> {error || localError}
             </div>
          )}
          {actionHint && (
             <div className="mt-6 p-4 rounded-xl border border-[#00F0FF]/30 bg-[#00F0FF]/10 text-white font-mono text-sm shadow-[0_0_15px_rgba(0,240,255,0.1)] animate-slide-up">
               <span className="text-[#00F0FF] font-bold mr-2">SYS:</span> {actionHint}
             </div>
          )}
        </section>

        {results && (
          <section className="glass-panel rounded-[2rem] p-8 md:p-10 border border-[#E8FF5A]/20 shadow-[0_10px_60px_rgba(232,255,90,0.1)] animate-slide-up">
            <h2 className="text-3xl font-black text-white mb-8 flex items-center gap-3">
              <span className="w-4 h-4 bg-[#E8FF5A] rounded-sm rotate-45 shadow-[0_0_15px_rgba(232,255,90,0.8)] animate-pulse-glow"></span>
              Threat Intelligence
            </h2>
            
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center bg-[#050505] rounded-2xl p-6 md:p-8 border border-white/5 mb-8 shadow-inner gap-4">
              <div>
                <span className="text-gray-400 font-mono text-xs uppercase tracking-widest block mb-2">Protocol Status</span>
                <p className="text-gray-300 font-medium">Anomalies Detected: <span className="text-white font-black text-xl">{results.findings.length}</span></p>
              </div>
              <div className="flex flex-col items-end">
                <span className="text-gray-500 font-mono text-xs uppercase tracking-widest mb-1">Threat Level</span>
                <span className={`text-4xl md:text-5xl font-black tracking-tighter ${
                   results.status === "VULNERABLE" ? "text-red-500 [text-shadow:0_0_20px_rgba(239,68,68,0.5)]" :
                   results.findings.length > 0 ? "text-[#E8FF5A] [text-shadow:0_0_20px_rgba(232,255,90,0.5)]" : "text-[#00F0FF] [text-shadow:0_0_20px_rgba(0,240,255,0.5)]"
                }`}>
                   {results.status === "VULNERABLE" ? "CRITICAL" :
                    results.findings.length > 0 ? "WARNING" : "SECURE"}
                </span>
              </div>
            </div>
            
            <div className="space-y-4 max-h-[600px] overflow-y-auto pr-3 custom-scrollbar">
              {results.findings.map((r, i) => (
                <div key={i} className="bg-[#0A0A0A] border border-white/5 p-6 rounded-2xl hover:border-white/20 transition-all hover:shadow-[0_4px_20px_rgba(0,0,0,0.4)] group overflow-hidden relative">
                  <div className="absolute top-0 left-0 w-1 h-full bg-gradient-to-b from-[#E8FF5A] to-[#00F0FF] opacity-30 group-hover:opacity-100 transition-opacity"></div>
                  <p className="text-[#00F0FF] font-mono text-xs mb-3 truncate font-semibold bg-[#00F0FF]/10 inline-block px-3 py-1 rounded-full">
                    {r.file_name}
                  </p>
                  <p className="text-white font-medium text-sm md:text-base leading-relaxed bg-[#111] p-4 rounded-xl border border-white/5">
                    {r.issue_description || "Anomaly Detected"}
                  </p>
                </div>
              ))}
              {results.findings.length === 0 && (
                <div className="flex flex-col items-center justify-center py-16 text-center border border-dashed border-[#00F0FF]/20 rounded-2xl bg-[#00F0FF]/5">
                  <div className="w-16 h-16 rounded-full border-2 border-[#00F0FF]/30 flex items-center justify-center mb-4">
                    <div className="w-8 h-8 bg-[#00F0FF]/20 rounded-full animate-ping"></div>
                  </div>
                  <p className="text-[#00F0FF] font-mono font-bold tracking-widest text-sm uppercase">Sector Clear</p>
                  <p className="text-gray-500 text-sm mt-2">No structural vulnerabilities detected.</p>
                </div>
              )}
            </div>
          </section>
        )}
      </div>
    </AppShell>
  );
}
