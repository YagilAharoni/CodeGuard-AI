"use client";

import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import AppShell from "../components/AppShell";
import { useScan } from "../hooks/useScan";
import { getAuthHeaders, getStoredUser } from "../lib/auth";

export default function Dashboard() {
  interface EngineOption {
    id: string;
    name: string;
    available: boolean;
  }

  interface ExploreEngineResponse {
    engines?: Array<{
      id?: string;
      name?: string;
      available?: boolean;
    }>;
  }

  const searchParams = useSearchParams();
  const providerRef = useRef<HTMLSelectElement | null>(null);
  const [repoUrl, setRepoUrl] = useState("");
  const [provider, setProvider] = useState("groq");
  const [persona] = useState("Student");
  const [selectedFiles, setSelectedFiles] = useState<FileList | null>(null);
  const [localError, setLocalError] = useState("");
  const [engineOptions, setEngineOptions] = useState<EngineOption[]>([
    { id: "groq", name: "Groq Engine", available: true },
    { id: "openai", name: "OpenAI Matrix", available: true },
    { id: "gemini", name: "Gemini Core", available: true },
  ]);
  const username = getStoredUser()?.username;
  const { results, isScanning, error, scanGithubUrl, uploadFile } = useScan();

  useEffect(() => {
    const loadEngines = async () => {
      try {
        const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
        const response = await fetch(`${apiBase}/explore-engine`, {
          method: "GET",
          credentials: "include",
          headers: {
            ...getAuthHeaders(),
          },
        });

        if (!response.ok) {
          return;
        }

        const data = (await response.json()) as ExploreEngineResponse;
        if (Array.isArray(data?.engines) && data.engines.length > 0) {
          const parsed = data.engines
            .map((engine) => ({
              id: String(engine.id || "").toLowerCase(),
              name: String(engine.name || engine.id || "Engine"),
              available: Boolean(engine.available),
            }))
            .filter((engine) => ["groq", "openai", "gemini"].includes(engine.id));

          if (parsed.length > 0) {
            setEngineOptions(parsed);
            setProvider((currentProvider) => {
              const stillValid = parsed.some((engine) => engine.id === currentProvider && engine.available);
              if (stillValid) return currentProvider;
              return parsed.find((engine) => engine.available)?.id || parsed[0].id;
            });
          }
        }
      } catch {
        // Keep local fallback options when backend discovery fails.
      }
    };

    loadEngines();
  }, []);

  useEffect(() => {
    const action = (searchParams.get("action") || "").toLowerCase();
    if (action === "explore") {
      providerRef.current?.focus();
    }
  }, [searchParams]);

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError("");
    if (selectedFiles && selectedFiles.length > 0) {
      uploadFile(selectedFiles, persona, undefined, provider, username);
      return;
    }
    if (repoUrl.trim()) {
      scanGithubUrl(repoUrl, persona, undefined, provider, username);
      return;
    }
    setLocalError("Provide a GitHub URL or upload files before launching a scan.");
  };

  const actionHint = (() => {
    const action = (searchParams.get("action") || "").toLowerCase();
    if (action === "initialize") {
      return "Initialize Scan is ready. Enter a GitHub URL or upload files, then click Start Scan.";
    }
    if (action === "explore") {
      return "Engine list loaded. Choose an engine and start your scan.";
    }
    return "";
  })();

  return (
    <AppShell title="Dashboard" subtitle="Launch scans and inspect findings">
      <div className="relative z-10">
        <header className="mb-12 border-b border-white/5 pb-6 text-center lg:text-left pt-6">
          <h1 className="text-4xl lg:text-5xl font-black tracking-tight text-white flex items-center gap-4">
            Command <span className="text-[#E8FF5A]">Center</span>
          </h1>
          <p className="text-gray-400 mt-2 font-mono text-sm uppercase tracking-widest">
            Execute security analysis protocol
          </p>
        </header>

        <section className="bg-white/5 border border-white/10 rounded-3xl p-8 mb-12 backdrop-blur-xl relative overflow-hidden group">
          <div className="absolute top-0 left-0 w-2 h-full bg-[#00F0FF] group-hover:w-full transition-all duration-[800ms] opacity-5 -z-10"></div>
          
          <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-3">
             <div className="w-8 h-8 rounded-full bg-[#00F0FF]/20 flex justify-center items-center text-[#00F0FF] font-black">1</div>
             Initialize Scan Target
          </h2>

          <form onSubmit={handleScan} className="flex flex-col gap-4">
            <input
              type="text"
              placeholder="Launch target URL (e.g. https://github.com/user/repo)"
              className="flex-grow p-4 bg-[#111] rounded-2xl border border-white/20 focus:border-[#E8FF5A]/50 focus:ring-1 focus:ring-[#E8FF5A]/30 text-white font-mono transition-all outline-none"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
            />

            <div className="rounded-2xl border border-white/10 bg-[#0f0f0f] p-4">
              <label className="block text-xs uppercase tracking-wider text-gray-400 font-mono mb-2">
                Or upload source files
              </label>
              <input
                type="file"
                multiple
                className="w-full text-sm text-gray-300 file:mr-4 file:rounded-xl file:border-0 file:bg-[#E8FF5A] file:px-4 file:py-2 file:font-bold file:text-black hover:file:bg-[#d4e84d]"
                onChange={(e) => setSelectedFiles(e.target.files)}
              />
            </div>
            
            <div className="flex gap-4 flex-col lg:flex-row">
               <select
                 ref={providerRef}
                 className="p-4 bg-[#111] border border-white/20 rounded-2xl text-white outline-none cursor-pointer focus:border-[#00F0FF]/50"
                 value={provider}
                 onChange={(e) => setProvider(e.target.value)}
               >
                 {engineOptions.map((engine) => (
                   <option key={engine.id} value={engine.id} disabled={!engine.available}>
                     {engine.name}{engine.available ? "" : " (Unavailable)"}
                   </option>
                 ))}
               </select>

               <button
                 type="submit"
                 disabled={isScanning}
                 className="px-8 py-4 bg-[#E8FF5A] hover:bg-[#d4e84d] text-black font-black uppercase tracking-wide rounded-2xl transition-all shadow-[0_0_20px_rgba(232,255,90,0.2)] disabled:opacity-50 disabled:cursor-not-allowed"
               >
                 {isScanning ? (
                   <span className="flex items-center gap-2">
                     <span className="w-4 h-4 rounded-full border-2 border-t-black animate-spin"></span> Scanning
                   </span>
                 ) : "Start Scan"}
               </button>
            </div>

              <p className="text-xs text-gray-500 font-mono">
                Provide a GitHub URL or upload one or more files to initialize a scan.
              </p>
          </form>
          {(error || localError) && <p className="text-red-400 mt-4 font-mono text-sm border-l-2 border-red-500 pl-4">{error || localError}</p>}
          {actionHint && <p className="text-cyan-300 mt-3 font-mono text-sm border-l-2 border-cyan-500/60 pl-4">{actionHint}</p>}
        </section>

        {results && (
          <section className="glass-panel rounded-3xl p-8 border border-[#E8FF5A]/20 shadow-[0_4px_40px_rgba(232,255,90,0.05)]">
            <h2 className="text-2xl font-black text-white mb-6 border-b border-white/10 pb-4">Threat Intelligence Report</h2>
            <div className="flex justify-between items-center bg-[#111] rounded-2xl p-6 border border-white/5 mb-6">
              <span className="text-gray-400 font-mono text-sm uppercase">Threat Score</span>
              <span className={`text-4xl font-black ${
                 results.status === "VULNERABLE" ? "text-red-500" :
                 results.findings.length > 0 ? "text-[#E8FF5A]" : "text-[#00F0FF]"
              }`}>
                 {results.status === "VULNERABLE" ? "CRITICAL" :
                  results.findings.length > 0 ? "WARNING" : "CLEAR"}
              </span>
            </div>
            
            <p className="mb-4 text-gray-300 font-medium">Total Vulnerabilities Found: <span className="text-white font-black text-lg">{results.findings.length}</span></p>
            
            <div className="space-y-4 max-h-[500px] overflow-y-auto pr-2 custom-scrollbar">
              {results.findings.map((r, i) => (
                <div key={i} className="bg-[#0a0a0a] border border-white/10 p-5 rounded-2xl hover:border-white/30 transition-colors">
                  <p className="text-[#00F0FF] font-mono text-xs mb-2 truncate">File: {r.file_name}</p>
                  <p className="text-white font-medium">{r.issue_description || "Anomaly Detected"}</p>
                </div>
              ))}
              {results.findings.length === 0 && (
                <p className="text-gray-500 italic font-mono text-center py-10">No anomalies detected in the target sector.</p>
              )}
            </div>
          </section>
        )}
      </div>
    </AppShell>
  );
}
