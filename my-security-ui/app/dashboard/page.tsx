"use client";
import React, { useState, useRef, useEffect } from "react";
import axios from "axios";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useScan, DependencyScanResult, VulnerablePackage } from "../hooks/useScan";
import { clearAuthSession, getAuthHeaders, getStoredUser, isAuthenticated } from "../lib/auth";
import {
  MAX_API_KEY_LEN,
  MAX_FILES_PER_SCAN,
  MAX_GITHUB_URL_LEN,
  validateApiKey,
  validateGithubUrl,
} from "../lib/validation";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
const getSeverityColor = (severity: string): string => {
  const upper = severity.toUpperCase();
  if (upper.includes("HIGH")) return "text-red-500";
  if (upper.includes("MEDIUM")) return "text-yellow-500";
  if (upper.includes("ERROR")) return "text-orange-500";
  return "text-blue-400";
};

const getSeverityBgColor = (severity: string): string => {
  const upper = severity.toUpperCase();
  if (upper.includes("HIGH")) return "bg-red-500/20 border-red-500/30";
  if (upper.includes("MEDIUM")) return "bg-yellow-500/20 border-yellow-500/30";
  if (upper.includes("ERROR")) return "bg-orange-500/20 border-orange-500/30";
  return "bg-blue-500/20 border-blue-500/30";
};

const getSeverityBadgeColor = (severity: string): string => {
  const upper = severity.toUpperCase();
  if (upper.includes("HIGH")) return "bg-red-500/30 text-red-400";
  if (upper.includes("MEDIUM")) return "bg-yellow-500/30 text-yellow-400";
  if (upper.includes("ERROR")) return "bg-orange-500/30 text-orange-400";
  return "bg-blue-500/30 text-blue-400";
};

// --- Severity badge for CVE severity levels ---
const getCveSeverityBadge = (severity: string) => {
  const s = severity.toUpperCase();
  if (s === "CRITICAL") return "bg-red-900/60 text-red-300 border border-red-500/40";
  if (s === "HIGH") return "bg-red-500/20 text-red-400 border border-red-500/30";
  if (s === "MEDIUM") return "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30";
  if (s === "LOW") return "bg-blue-500/20 text-blue-400 border border-blue-500/30";
  return "bg-gray-500/20 text-gray-400 border border-gray-500/30";
};

// --- Dependency Audit Panel ---
const DependencyAuditPanel = ({
  files,
  scanDependencies,
  isDepScanning,
  depResults,
}: {
  files: FileList | null;
  scanDependencies: (files: FileList) => void;
  isDepScanning: boolean;
  depResults: DependencyScanResult | null;
}) => {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const togglePkg = (pkg: string) => {
    const next = new Set(expanded);
    if (next.has(pkg)) next.delete(pkg); else next.add(pkg);
    setExpanded(next);
  };

  return (
    <div className="mb-10 rounded-2xl border border-[#30363d] overflow-hidden bg-[#0d1117]">
      {/* Header */}
      <div className="flex items-center justify-between p-5 bg-[#161b22] border-b border-[#30363d]">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-orange-500/30 to-red-600/30 border border-orange-500/30 flex items-center justify-center">
            <svg className="w-5 h-5 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01" />
            </svg>
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Dependency CVE Audit</h3>
            <p className="text-xs text-gray-500">Real-time vulnerability check via OSV.dev database</p>
          </div>
        </div>
        {files && (
          <button
            id="dep-scan-btn"
            onClick={() => scanDependencies(files)}
            disabled={isDepScanning}
            className={`px-5 py-2 rounded-lg font-bold text-sm transition-all border ${
              isDepScanning
                ? "bg-white/5 border-white/10 text-gray-500 cursor-not-allowed animate-pulse"
                : "bg-gradient-to-r from-orange-600/80 to-red-600/80 border-orange-500/40 text-white hover:scale-105 shadow-lg shadow-orange-500/10"
            }`}
          >
            {isDepScanning ? "⏳ Scanning..." : "🔍 Scan Dependencies"}
          </button>
        )}
      </div>

      {/* Not yet scanned */}
      {!depResults && !isDepScanning && (
        <div className="p-8 text-center">
          <div className="text-3xl mb-3 opacity-40">📦</div>
          <p className="text-gray-500 text-sm">Click <span className="text-orange-400 font-semibold">Scan Dependencies</span> to check all detected packages against the OSV.dev CVE database.</p>
          <p className="text-xs text-gray-600 mt-1">Supports Python (PyPI), JavaScript/TypeScript (npm), and C/C++ imports.</p>
        </div>
      )}

      {/* Scanning loader */}
      {isDepScanning && (
        <div className="p-8 text-center">
          <div className="flex items-center justify-center gap-3 text-orange-400">
            <svg className="animate-spin w-5 h-5" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"/>
            </svg>
            <span className="text-sm font-semibold">Querying OSV.dev database...</span>
          </div>
        </div>
      )}

      {/* Results */}
      {depResults && !isDepScanning && (
        <div className="p-5 space-y-4">
          {/* Summary bar */}
          <div className="grid grid-cols-3 gap-3 mb-4">
            <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/20 text-center">
              <div className="text-2xl font-black text-red-400">{depResults.vulnerable.length}</div>
              <div className="text-xs text-gray-500 uppercase tracking-wide">Vulnerable</div>
            </div>
            <div className="p-3 rounded-xl bg-green-500/10 border border-green-500/20 text-center">
              <div className="text-2xl font-black text-green-400">{depResults.safe.length}</div>
              <div className="text-xs text-gray-500 uppercase tracking-wide">Clean</div>
            </div>
            <div className="p-3 rounded-xl bg-white/5 border border-white/10 text-center">
              <div className="text-2xl font-black text-gray-300">{depResults.total_checked}</div>
              <div className="text-xs text-gray-500 uppercase tracking-wide">Checked</div>
            </div>
          </div>

          {/* Vulnerable packages */}
          {depResults.vulnerable.length > 0 ? (
            <div className="space-y-3">
              <h4 className="text-sm font-bold text-red-400 uppercase tracking-wider flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse shadow-[0_0_6px_rgba(239,68,68,0.8)]"></span>
                Vulnerable Packages ({depResults.vulnerable.length})
              </h4>
              {depResults.vulnerable.map((pkg: VulnerablePackage) => (
                <div key={pkg.package} className="rounded-xl border border-red-500/20 overflow-hidden">
                  <button
                    onClick={() => togglePkg(pkg.package)}
                    className="w-full flex items-center justify-between p-3 bg-red-500/5 hover:bg-red-500/10 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <svg className={`w-4 h-4 text-gray-400 transition-transform ${expanded.has(pkg.package) ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                      </svg>
                      <span className="font-mono text-sm font-bold text-white">{pkg.package}</span>
                      <span className="text-xs text-gray-500 px-2 py-0.5 bg-white/5 rounded">{pkg.ecosystem}</span>
                    </div>
                    <span className="text-xs font-bold px-2 py-1 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                      {pkg.advisory_count} CVE{pkg.advisory_count !== 1 ? 's' : ''}
                    </span>
                  </button>
                  {expanded.has(pkg.package) && (
                    <div className="p-3 space-y-2 border-t border-red-500/10">
                      {pkg.advisories.map((adv) => (
                        <div key={adv.id} className="p-3 rounded-lg bg-[#0d1117] border border-[#30363d] flex flex-col gap-1.5">
                          <div className="flex items-start justify-between gap-2">
                            <a
                              href={adv.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="font-mono text-xs text-cyan-400 hover:text-cyan-300 underline underline-offset-2 shrink-0"
                            >
                              {adv.id}
                            </a>
                            <span className={`text-xs font-bold px-2 py-0.5 rounded ${getCveSeverityBadge(adv.severity)}`}>
                              {adv.severity}
                            </span>
                          </div>
                          <p className="text-xs text-gray-400 leading-relaxed">{adv.summary}</p>
                          {adv.fixed_in && (
                            <p className="text-xs text-green-400 font-semibold">✓ Fixed in: v{adv.fixed_in}</p>
                          )}
                        </div>
                      ))}
                      {pkg.advisory_count > 5 && (
                        <p className="text-xs text-gray-500 text-center pt-1">...and {pkg.advisory_count - 5} more advisory(s).<a href={`https://osv.dev/list?q=${pkg.package}&ecosystem=${pkg.ecosystem}`} target="_blank" rel="noopener noreferrer" className="text-cyan-400 ml-1 hover:underline">View all on OSV.dev</a></p>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="p-5 rounded-xl bg-green-500/5 border border-green-500/20 text-center">
              <div className="text-2xl mb-1">✅</div>
              <p className="text-green-400 text-sm font-semibold">No known vulnerabilities found in detected packages!</p>
            </div>
          )}

          {/* Safe packages inline list */}
          {depResults.safe.length > 0 && (
            <div>
              <h4 className="text-xs font-bold text-green-400 uppercase tracking-wider mb-2 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-green-500"></span>
                Clean Packages ({depResults.safe.length})
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {depResults.safe.map((p) => (
                  <span key={p.package} className="text-xs font-mono px-2 py-1 bg-green-500/5 border border-green-500/10 rounded text-green-400/70">
                    {p.package}
                  </span>
                ))}
              </div>
            </div>
          )}

          {depResults.skipped_stdlib_count > 0 && (
            <p className="text-xs text-gray-600 text-right">{depResults.skipped_stdlib_count} stdlib/built-in package(s) skipped.</p>
          )}
        </div>
      )}
    </div>
  );
};


const VulnerabilityChart = ({ stats }: { stats: any }) => {
  const allChartData = [
    { name: "High", value: stats.High || 0, fill: "#ef4444" },
    { name: "Medium", value: stats.Medium || 0, fill: "#eab308" },
    { name: "Low", value: stats.Low || 0, fill: "#3b82f6" },
  ];

  // Filter out zero-value slices for pie chart to prevent overlap
  const pieChartData = allChartData.filter((d) => d.value > 0);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-10">
      <div className="bg-[#161b22] p-6 rounded-xl border border-[#30363d]">
        <h3 className="text-lg font-bold mb-6 text-gray-200">Distribution by Severity</h3>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={allChartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
            <XAxis dataKey="name" stroke="#8b949e" />
            <YAxis stroke="#8b949e" allowDecimals={false} />
            <Tooltip
              contentStyle={{
                backgroundColor: "#161b22",
                border: "1px solid #30363d",
                borderRadius: "8px",
                color: "#c9d1d9",
              }}
            />
            <Bar dataKey="value" radius={[8, 8, 0, 0]}>
              {allChartData.map((entry, index) => (
                <Cell key={`bar-cell-${index}`} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="bg-[#161b22] p-6 rounded-xl border border-[#30363d]">
        <h3 className="text-lg font-bold mb-6 text-gray-200">Overview</h3>
        {pieChartData.length === 0 ? (
          <div className="flex items-center justify-center h-[300px]">
            <div className="text-center">
              <div className="text-4xl mb-2">✅</div>
              <p className="text-gray-400 text-sm">No vulnerabilities found</p>
            </div>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={pieChartData}
                cx="50%"
                cy="50%"
                labelLine={true}
                label={({ name, value }) => `${name}: ${value}`}
                outerRadius={90}
                dataKey="value"
              >
                {pieChartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: "#161b22",
                  border: "1px solid #30363d",
                  borderRadius: "8px",
                  color: "#c9d1d9",
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
};

export default function Home() {
  const clientApiKeysEnabled = process.env.NEXT_PUBLIC_ALLOW_CLIENT_API_KEYS !== "false";
  const SESSION_API_KEY_STORAGE_KEY = "codeguard_session_api_key";
  // --- States ---
  const router = useRouter();
  const [isLoggedIn, setIsLoggedIn] = useState(true);
  const [persona, setPersona] = useState<"Student" | "Professional">("Student");
  const [apiKey, setApiKey] = useState("");
  const [mounted, setMounted] = useState(false);
  const [loggedInUsername, setLoggedInUsername] = useState<string>("anonymous");

  const [isHovered, setIsHovered] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedFiles, setSelectedFiles] = useState<FileList | null>(null);
  const [githubUrl, setGithubUrl] = useState("");
  const [expandedFiles, setExpandedFiles] = useState<Set<string>>(new Set());
  const [expandedDiffs, setExpandedDiffs] = useState<Record<string, boolean>>({});
  const [copiedMessage, setCopiedMessage] = useState<string | null>(null);
  const [isFolderMode, setIsFolderMode] = useState(false);
  const [history, setHistory] = useState<any[]>([]);
  const [inputError, setInputError] = useState<string | null>(null);

  // Hook for backend connection
  const { uploadFile, scanGithubUrl, downloadReport, scanDependencies, isScanning, isDepScanning, results, depResults, error, clearError, clearResults } = useScan();

  const fetchHistory = async () => {
    if (!isAuthenticated()) return;
    try {
      const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      const response = await axios.get(`${apiBase}/history`, {
        headers: {
          ...getAuthHeaders(),
        },
      });
      setHistory(response.data.history || []);
    } catch (err) {
      console.error("Failed to fetch history:", err);
    }
  };

  // Prevent hydration mismatch
  useEffect(() => {
    if (!isAuthenticated()) {
      router.replace("/");
      return;
    }

    setMounted(true);
    const user = getStoredUser();
    if (user?.username) {
      setLoggedInUsername(user.username);
    }

    try {
      const rawPrefs = localStorage.getItem("codeguard_preferences");
      if (rawPrefs) {
        const prefs = JSON.parse(rawPrefs) as { defaultPersona?: "Student" | "Professional" };
        if (prefs.defaultPersona) {
          setPersona(prefs.defaultPersona);
        }
      }
    } catch {
      // ignore malformed local settings
    }
  }, [router]);

  useEffect(() => {
    if (mounted) fetchHistory();
  }, [mounted]);

  useEffect(() => {
    if (!mounted || !clientApiKeysEnabled) {
      return;
    }
    try {
      const storedSessionApiKey = sessionStorage.getItem(SESSION_API_KEY_STORAGE_KEY);
      if (storedSessionApiKey) {
        setApiKey(storedSessionApiKey.slice(0, MAX_API_KEY_LEN));
      }
    } catch {
      // Ignore storage access issues.
    }
  }, [mounted, clientApiKeysEnabled]);

  useEffect(() => {
    if (!mounted || !clientApiKeysEnabled) {
      return;
    }
    try {
      if (apiKey) {
        sessionStorage.setItem(SESSION_API_KEY_STORAGE_KEY, apiKey);
      } else {
        sessionStorage.removeItem(SESSION_API_KEY_STORAGE_KEY);
      }
    } catch {
      // Ignore storage access issues.
    }
  }, [apiKey, mounted, clientApiKeysEnabled]);

  useEffect(() => {
    if (results) fetchHistory();
  }, [results]);

  // --- Handlers ---
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsHovered(true);
  };
  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsHovered(false);
  };
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsHovered(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setSelectedFiles(e.dataTransfer.files);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFiles(e.target.files);
    }
  };

  const getModelInfo = () => {
    if (!apiKey) return { provider: "Server Default", icon: "🛡️", color: "text-blue-300" };
    const key = apiKey.trim();
    if (key.startsWith("gsk_")) return { provider: "Groq", icon: "⚡", color: "text-cyan-400" };
    if (key.startsWith("sk-")) return { provider: "OpenAI", icon: "🤖", color: "text-green-400" };
    if (key.startsWith("AIzaSy")) return { provider: "Google Gemini", icon: "✨", color: "text-yellow-400" };
    return { provider: "Auto", icon: "🔍", color: "text-gray-400" };
  };

  const getFindingKey = (fileName: string, idx: number) => `${fileName}-${idx}`;

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedMessage('Fixed code copied to clipboard.');
    } catch (err) {
      setCopiedMessage('Unable to copy fixed code. Please copy manually.');
    }
  };

  useEffect(() => {
    if (!copiedMessage) return;
    const timeout = window.setTimeout(() => setCopiedMessage(null), 2500);
    return () => window.clearTimeout(timeout);
  }, [copiedMessage]);

  const toggleDiffPanel = (key: string) => {
    setExpandedDiffs(prev => ({
      ...prev,
      [key]: !prev[key],
    }));
  };

  const renderFixComparison = (finding: any) => {
    const source = finding.source_code?.trim();
    const fixed = finding.fixed_code?.trim();

    if (!source && !fixed) {
      return (
        <div className="bg-[#0d1117] p-3 rounded border border-[#30363d]">
          <p className="text-green-400 text-xs font-semibold mb-1">Suggested Fix:</p>
          <pre className="text-gray-400 text-sm font-mono whitespace-pre-wrap break-words">{finding.suggested_fix}</pre>
        </div>
      );
    }

    return (
      <div className="grid gap-4 md:grid-cols-2 mt-3">
        {source && (
          <div className="bg-[#0d1117] p-3 rounded border border-[#30363d]">
            <div className="flex items-center justify-between mb-2">
              <span className="text-yellow-300 text-xs font-semibold uppercase tracking-wide">Original Code</span>
            </div>
            <pre className="text-gray-400 text-sm font-mono whitespace-pre-wrap break-words">{source}</pre>
          </div>
        )}
        {fixed && (
          <div className="bg-[#0d1117] p-3 rounded border border-[#30363d]">
            <div className="flex items-center justify-between mb-2">
              <span className="text-green-400 text-xs font-semibold uppercase tracking-wide">Auto-Fixed Code</span>
            </div>
            <pre className="text-gray-400 text-sm font-mono whitespace-pre-wrap break-words">{fixed}</pre>
          </div>
        )}
      </div>
    );
  };

  const runAnalysis = () => {
    setInputError(null);

    if (clientApiKeysEnabled) {
      const apiKeyError = validateApiKey(apiKey);
      if (apiKeyError) {
        setInputError(apiKeyError);
        return;
      }
    }

    if (selectedFiles && selectedFiles.length > MAX_FILES_PER_SCAN) {
      setInputError(`Too many files selected. Maximum allowed is ${MAX_FILES_PER_SCAN}.`);
      return;
    }

    if (githubUrl && !selectedFiles) {
      const githubError = validateGithubUrl(githubUrl);
      if (githubError) {
        setInputError(githubError);
        return;
      }
    }

    const apiKeyToPass = clientApiKeysEnabled ? apiKey || undefined : undefined;
    if (githubUrl && !selectedFiles) {
      scanGithubUrl(githubUrl, persona, apiKeyToPass, "auto", loggedInUsername);
    } else if (selectedFiles) {
      uploadFile(selectedFiles, persona, apiKeyToPass, "auto", loggedInUsername);
    }
  };

  const toggleFileExpansion = (fileName: string) => {
    const newExpanded = new Set(expandedFiles);
    if (newExpanded.has(fileName)) {
      newExpanded.delete(fileName);
    } else {
      newExpanded.add(fileName);
    }
    setExpandedFiles(newExpanded);
  };

  const toggleAllFiles = () => {
    if (expandedFiles.size === Object.keys(groupedFindings).length) {
      // All expanded, collapse all
      setExpandedFiles(new Set());
    } else {
      // Expand all
      setExpandedFiles(new Set(Object.keys(groupedFindings)));
    }
  };

  // Group findings by file and sort
  const groupedFindings = React.useMemo(() => {
    if (!results?.findings) return {};
    
    const grouped: { [key: string]: any[] } = {};
    results.findings.forEach((finding: any) => {
      const fileName = finding.file_name || "unknown";
      if (!grouped[fileName]) {
        grouped[fileName] = [];
      }
      grouped[fileName].push(finding);
    });
    
    return grouped;
  }, [results]);

  // Auto-expand all findings and fixes when results arrive
  useEffect(() => {
    if (results?.findings && results.findings.length > 0) {
      const fileNames = Object.keys(groupedFindings);
      setExpandedFiles(new Set(fileNames));
      
      const diffKeys: Record<string, boolean> = {};
      results.findings.forEach((finding: any, idx: number) => {
        const fileName = finding.file_name || "unknown";
        // We need to find the index within that specific file's findings 
        // because getFindingKey is used with mapped findings per file
      });
      
      // Actually, looking at the render logic (line 906):
      // findings.map((finding: any, idx: number) => ... getFindingKey(fileName, idx))
      // It uses the index of the finding WITHIN the file group.
      
      Object.entries(groupedFindings).forEach(([fileName, fileFindings]) => {
        fileFindings.forEach((_, idx) => {
          diffKeys[getFindingKey(fileName, idx)] = true;
        });
      });
      setExpandedDiffs(diffKeys);
    }
  }, [results, groupedFindings]);

  return (
    <div className="relative min-h-screen bg-[#0A0C10] text-white font-sans selection:bg-cyan-500/30 pb-20 overflow-hidden">

      {/* Cyber background glows */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] rounded-full bg-[#8A2BE2]/10 blur-[130px] pointer-events-none" />
      <div className="absolute top-[20%] right-[-10%] w-[40%] h-[60%] rounded-full bg-[#00F0FF]/8 blur-[150px] pointer-events-none" />
      <div className="absolute bottom-[-20%] left-[20%] w-[60%] h-[40%] rounded-full bg-[#8A2BE2]/8 blur-[120px] pointer-events-none" />
      <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI0MCIgaGVpZ2h0PSI0MCI+PGRlZnM+PHBhdHRlcm4gaWQ9ImciIHdpZHRoPSI0MCIgaGVpZ2h0PSI0MCIgcGF0dGVyblVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+PHBhdGggZD0iTTAgNDBoNDBWMEgweiIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJyZ2JhKDI1NSwyNTUsMjU1LDAuMDMpIiBzdHJva2Utd2lkdGg9IjEiLz48L3BhdHRlcm4+PC9kZWZzPjxyZWN0IHdpZHRoPSIxMDAlIiBoZWlnaHQ9IjEwMCUiIGZpbGw9InVybCgjZykiLz48L3N2Zz4=')] pointer-events-none opacity-40" />
      <div className="absolute inset-0 pointer-events-none opacity-20 bg-[radial-gradient(circle_at_1px_1px,rgba(255,255,255,0.14)_1px,transparent_0)] [background-size:14px_14px]" />

      {/* Navbar */}
      <nav className="border-b border-white/5 bg-[#0A0C10]/80 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-purple-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <span className="text-white font-bold text-xl">🛡️</span>
            </div>
            <h1 className="text-xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-400">
              CodeGuard AI
            </h1>
          </div>
          <div className="flex gap-4 items-center">
            <Link href="/history" className="px-4 py-2 rounded-lg border border-white/10 hover:bg-white/5 transition text-sm font-medium text-gray-300">📜 History</Link>
            <Link href="/reports" className="px-4 py-2 rounded-lg border border-white/10 hover:bg-white/5 transition text-sm font-medium text-gray-300">📦 Reports</Link>
            <Link href="/settings" className="px-4 py-2 rounded-lg border border-white/10 hover:bg-white/5 transition text-sm font-medium text-gray-300">⚙ Settings</Link>
            <div className="px-3 py-1.5 bg-white/5 border border-white/10 rounded-lg flex items-center gap-2">
              <span className="text-xs text-gray-500">👤</span>
              <span className="text-sm font-semibold text-cyan-300">{loggedInUsername}</span>
              <button
                onClick={() => {
                  clearAuthSession();
                  try {
                    sessionStorage.removeItem(SESSION_API_KEY_STORAGE_KEY);
                  } catch {
                    // Ignore storage access issues.
                  }
                  router.replace('/');
                }}
                className="ml-2 text-xs text-gray-500 hover:text-red-400 transition"
                title="Logout"
              >
                ⏻
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Application Main Body */}
      <main className="relative z-10 max-w-5xl mx-auto px-6 py-12 flex flex-col items-center">
        
        {/* --- VIEW 1: LOGIN / PERSONA SELECTION --- */}
        {!isLoggedIn && (
          <div className="w-full max-w-2xl mt-10 animate-fade-in">
            <div className="text-center mb-10">
              <h2 className="text-4xl font-extrabold tracking-tight mb-4 text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-400">Identify Yourself</h2>
              <p className="text-gray-400">Choose your analysis strictness and role.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
              {/* Persona 1: Student */}
              <div 
                onClick={() => setPersona("Student")}
                className={`cursor-pointer p-6 rounded-2xl border-2 transition-all duration-300 ${
                  persona === "Student" 
                    ? "border-cyan-500 bg-cyan-500/10 shadow-lg shadow-cyan-500/20" 
                    : "border-white/10 bg-white/5 hover:border-cyan-500/40"
                }`}
              >
                <div className="text-4xl mb-4">🎓</div>
                <h3 className="text-xl font-bold text-white mb-2">Student & Learner</h3>
                <p className="text-sm text-gray-400">Helpful, encouraging AI tutor. Identifies minor issues but focuses on best practices.</p>
              </div>

              {/* Persona 2: Professional */}
              <div 
                onClick={() => setPersona("Professional")}
                className={`cursor-pointer p-6 rounded-2xl border-2 transition-all duration-300 ${
                  persona === "Professional" 
                    ? "border-purple-500 bg-purple-500/10 shadow-lg shadow-purple-500/20" 
                    : "border-white/10 bg-white/5 hover:border-purple-500/40"
                }`}
              >
                <div className="text-4xl mb-4">🕵️‍♂️</div>
                <h3 className="text-xl font-bold text-white mb-2">Lead Auditor</h3>
                <p className="text-sm text-gray-400">Ruthless, enterprise-grade AI auditor. Flags every minor risk as vulnerable.</p>
              </div>
            </div>

            {clientApiKeysEnabled ? (
              <div className="bg-white/5 p-6 rounded-2xl border border-white/10 mb-8 backdrop-blur-sm">
                <label className="block text-sm font-semibold mb-2 text-gray-300">AI API Key <span className="text-gray-500 font-normal">(optional — uses server default if empty)</span></label>
                <input 
                  type="password" 
                  value={apiKey}
                  onChange={(e) => {
                    setInputError(null);
                    setApiKey(e.target.value.slice(0, MAX_API_KEY_LEN));
                  }}
                  placeholder="gsk_... or sk-... or AIzaSy..."
                  className="w-full bg-[#0A0C10]/80 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 transition-all font-mono text-sm"
                  maxLength={MAX_API_KEY_LEN}
                  autoComplete="off"
                />
                <p className="text-xs text-gray-500 mt-2">Auto-detects: Groq (gsk_), OpenAI (sk-), Google Gemini (AIzaSy), or uses server default provider.</p>
              </div>
            ) : (
              <div className="bg-white/5 p-6 rounded-2xl border border-white/10 mb-8 backdrop-blur-sm">
                <label className="block text-sm font-semibold mb-2 text-gray-300">Server-managed API Security</label>
                <p className="text-xs text-gray-400">Client API keys are disabled for security. Scans use server-side credentials only.</p>
              </div>
            )}

            <button 
              onClick={() => setIsLoggedIn(true)}
              className="relative w-full overflow-hidden group rounded-xl border border-white/10"
            >
              <div className="absolute inset-0 bg-gradient-to-r from-cyan-600/80 to-purple-600/80 transition-transform duration-500 group-hover:scale-105"></div>
              <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 to-purple-500 opacity-0 group-hover:opacity-100 transition-opacity duration-500 blur-md"></div>
              <div className="relative px-6 py-4 flex items-center justify-center font-bold text-white tracking-wider uppercase text-sm">
                Enter System
              </div>
            </button>
          </div>
        )}

        {/* --- VIEW 2: DASHBOARD (UPLOAD) --- */}
        {isLoggedIn && !results && (
          <div className="w-full mt-10 animate-fade-in flex flex-col items-center">
             <div className="text-center mb-10">
               <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 text-xs font-semibold tracking-wider uppercase mb-5">
                 Mission Control
               </div>
               <h2 className="text-5xl font-black tracking-tight mb-4 leading-tight">
                  Secure Your Codebase
                  <span className="block text-transparent bg-clip-text bg-gradient-to-r from-cyan-300 via-blue-400 to-purple-500 mt-1">
                    Sharp. Fast. Explainable.
                  </span>
                </h2>
                <p className="text-base text-gray-400 max-w-3xl mx-auto">
                  Drop files or paste a repository URL, set your scan profile, then launch an AI-assisted security audit from one clean workspace.
                </p>
             </div>

             {error && (
               <div className="w-full max-w-2xl bg-red-500/10 border border-red-500/50 text-red-500 p-4 rounded-xl mb-6 flex justify-between items-center">
                 <span>{error}</span>
                 <button onClick={clearError} className="text-red-400 hover:text-white">✕</button>
               </div>
             )}

             {inputError && (
               <div className="w-full max-w-2xl bg-red-500/10 border border-red-500/50 text-red-500 p-4 rounded-xl mb-6 flex justify-between items-center">
                 <span>{inputError}</span>
                 <button onClick={() => setInputError(null)} className="text-red-400 hover:text-white">✕</button>
               </div>
             )}

            <div className="w-full max-w-6xl grid gap-6 lg:grid-cols-[1.4fr_1fr] animate-fade-in">
              <section
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`relative rounded-3xl border p-8 md:p-10 cursor-pointer transition-all duration-300 overflow-hidden ${
                  isHovered
                    ? "border-cyan-400/60 bg-cyan-500/10 shadow-[0_20px_80px_rgba(34,211,238,0.12)] scale-[1.01]"
                    : "border-white/10 bg-[#0f141d]/85 hover:border-cyan-500/40"
                }`}
              >
                <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(135deg,rgba(255,255,255,0.03),transparent_35%,rgba(0,240,255,0.04)_70%,transparent)]" />
                <input
                  type="file"
                  multiple
                  className="hidden"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                  accept=".py,.js,.ts,.cpp,.h,.zip"
                  {...(isFolderMode ? { webkitdirectory: "", directory: "" } as any : {})}
                />

                <div className="relative z-10 flex flex-col items-start gap-6">
                  <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
                    <svg className="w-8 h-8 text-cyan-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                    </svg>
                  </div>

                  <div>
                    <h3 className="text-2xl font-extrabold text-white mb-2">
                      {selectedFiles ? `${selectedFiles.length} file(s) ready for scan` : "Drop source files to begin"}
                    </h3>
                    <p className="text-sm text-gray-400">
                      Supports .py, .js, .ts, .cpp, .h and .zip. Click anywhere in this panel to browse.
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-3">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setIsFolderMode(false);
                        setSelectedFiles(null);
                      }}
                      className={`px-4 py-2 rounded-xl text-xs font-bold tracking-wide border transition-all ${
                        !isFolderMode
                          ? "bg-cyan-500/20 border-cyan-400/40 text-cyan-200"
                          : "bg-white/5 border-white/10 text-gray-300 hover:text-white"
                      }`}
                    >
                      FILE MODE
                    </button>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setIsFolderMode(true);
                        setSelectedFiles(null);
                      }}
                      className={`px-4 py-2 rounded-xl text-xs font-bold tracking-wide border transition-all ${
                        isFolderMode
                          ? "bg-purple-500/20 border-purple-400/40 text-purple-200"
                          : "bg-white/5 border-white/10 text-gray-300 hover:text-white"
                      }`}
                    >
                      FOLDER MODE
                    </button>
                    <span className="text-xs text-gray-500 ml-1">
                      {isFolderMode ? "Folder structure preserved" : "Single and multiple files supported"}
                    </span>
                  </div>

                  <div className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600/80 to-purple-600/80 border border-cyan-500/30 text-sm font-bold tracking-wide">
                    {isFolderMode ? "Select Folder" : "Browse Files"}
                  </div>
                </div>
              </section>

              <section className="rounded-3xl border border-white/10 bg-[#111722]/85 p-6 md:p-7 backdrop-blur-md relative overflow-hidden">
                <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(160deg,rgba(255,255,255,0.04),transparent_30%,rgba(138,43,226,0.08)_65%,transparent)]" />
                <div className="relative z-10 space-y-5">
                  <div>
                    <h3 className="text-xl font-black text-white">Scan Configuration</h3>
                    <p className="text-xs text-gray-400 mt-1">Configure source and access in one place before starting the scan.</p>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wide text-gray-400 mb-2">Source (Optional)</label>
                    <input
                      type="text"
                      value={githubUrl}
                      onChange={(e) => {
                        setInputError(null);
                        setGithubUrl(e.target.value.slice(0, MAX_GITHUB_URL_LEN));
                        setSelectedFiles(null);
                      }}
                      placeholder="https://github.com/owner/repo"
                      className="w-full bg-[#0A0C10]/85 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 transition-all text-sm"
                      maxLength={MAX_GITHUB_URL_LEN}
                    />
                    <p className="text-[11px] text-gray-500 mt-1.5">Use this or file upload, not both.</p>
                  </div>

                  {clientApiKeysEnabled ? (
                    <div>
                      <label className="block text-xs font-semibold uppercase tracking-wide text-gray-400 mb-2">API Key (Optional)</label>
                      <input
                        type="password"
                        value={apiKey}
                        onChange={(e) => {
                          setInputError(null);
                          setApiKey(e.target.value.slice(0, MAX_API_KEY_LEN));
                        }}
                        placeholder="gsk_... | sk-... | AIzaSy..."
                        className="w-full bg-[#0A0C10]/85 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 transition-all font-mono text-sm"
                        maxLength={MAX_API_KEY_LEN}
                        autoComplete="off"
                      />
                      <p className="text-[11px] text-gray-500 mt-1.5">Leave empty to use the server default provider.</p>
                    </div>
                  ) : (
                    <div className="rounded-xl border border-white/10 bg-white/5 p-3.5">
                      <div className="text-[11px] uppercase tracking-widest text-gray-500 mb-1">API Key Mode</div>
                      <div className="text-sm text-gray-300 font-semibold">Server-managed only (client keys disabled)</div>
                    </div>
                  )}

                  <div className="rounded-xl border border-white/10 bg-white/5 p-3.5">
                    <div className="text-[11px] uppercase tracking-widest text-gray-500 mb-1">Active Model Route</div>
                    <div className={`text-sm font-bold ${getModelInfo().color}`}>{getModelInfo().icon} {getModelInfo().provider}</div>
                  </div>

                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      runAnalysis();
                    }}
                    disabled={isScanning || (!selectedFiles && !githubUrl)}
                    className={`w-full py-3.5 rounded-xl font-extrabold tracking-wide text-white transition-all shadow-xl ${
                      isScanning || (!selectedFiles && !githubUrl)
                        ? "bg-white/10 cursor-not-allowed text-gray-400"
                        : "bg-gradient-to-r from-cyan-600 to-purple-600 hover:scale-[1.02] shadow-purple-500/20"
                    }`}
                  >
                    {isScanning ? "Agents Analyzing..." : "Run Security Scan"}
                  </button>
                </div>
              </section>
            </div>

            <div className="w-full max-w-4xl mt-12 grid gap-4 md:grid-cols-3">
              <Link href="/history" className="rounded-2xl border border-white/10 bg-white/5 p-5 hover:border-cyan-500/40 transition-colors">
                <div className="text-sm text-cyan-300 font-semibold">Timeline</div>
                <div className="text-xl font-bold text-white mt-1">History Explorer</div>
                <p className="text-xs text-gray-400 mt-2">Compare snapshots and track risk trend over time.</p>
              </Link>
              <Link href="/reports" className="rounded-2xl border border-white/10 bg-white/5 p-5 hover:border-cyan-500/40 transition-colors">
                <div className="text-sm text-cyan-300 font-semibold">Exports</div>
                <div className="text-xl font-bold text-white mt-1">Reports Center</div>
                <p className="text-xs text-gray-400 mt-2">Filter previous scans and export ownership-protected PDFs.</p>
              </Link>
              <Link href="/settings" className="rounded-2xl border border-white/10 bg-white/5 p-5 hover:border-cyan-500/40 transition-colors">
                <div className="text-sm text-cyan-300 font-semibold">Profile</div>
                <div className="text-xl font-bold text-white mt-1">Security Settings</div>
                <p className="text-xs text-gray-400 mt-2">Configure default persona and secure session behavior.</p>
              </Link>
            </div>

            {/* --- RECENT HISTORY PREVIEW --- */}
            {history.length > 0 && (
              <div className="w-full max-w-4xl mt-16 p-8 rounded-2xl bg-white/5 border border-white/10 backdrop-blur-md animate-fade-in">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-2xl font-bold flex items-center gap-3">
                    <span className="text-2xl">🕒</span>
                    Recent Security Scans
                  </h3>
                  <Link href="/history" className="text-sm text-cyan-400 hover:text-cyan-300 transition-colors font-semibold flex items-center gap-1 group">
                    View All <span className="group-hover:translate-x-1 transition-transform">→</span>
                  </Link>
                </div>
                <div className="grid gap-4">
                  {history.slice(0, 3).map((scan: any) => (
                    <div key={scan.scan_id} className="flex flex-col md:flex-row items-center justify-between p-4 rounded-xl bg-white/5 border border-white/10 hover:border-cyan-500/30 transition-all group">
                      <div className="flex items-center gap-4 mb-4 md:mb-0">
                         <div className={`w-3 h-3 rounded-full ${scan.status === 'SAFE' ? 'bg-green-500 shadow-[0_0_10px_rgba(34,197,94,0.5)]' : 'bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]'}`}></div>
                         <div>
                            <div className="text-sm font-bold text-white group-hover:text-cyan-400 transition">{scan.timestamp}</div>
                            <div className="text-xs text-gray-500 truncate max-w-[200px]">{scan.source || 'Local Upload'}</div>
                         </div>
                      </div>
                      <div className="flex items-center gap-6">
                        <div className="flex gap-2">
                           {scan.stats && (
                             <>
                               <span className="text-xs font-semibold px-2 py-1 bg-red-500/10 text-red-400 rounded border border-red-500/20">H: {scan.stats.High}</span>
                               <span className="text-xs font-semibold px-2 py-1 bg-yellow-500/10 text-yellow-400 rounded border border-yellow-500/20">M: {scan.stats.Medium}</span>
                             </>
                           )}
                        </div>
                        <button 
                          onClick={() => downloadReport(scan.scan_id, loggedInUsername)}
                          className="px-4 py-2 bg-white/5 hover:bg-cyan-500/20 rounded-lg text-xs font-bold transition-all border border-white/10 hover:border-cyan-500/50"
                        >
                          DOWNLOAD PDF
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* --- VIEW 3: RESULTS & PDF EXPORT --- */}
        {results && (
          <div className="w-full max-w-6xl mt-10 animate-fade-in">
             <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-4 mb-8 rounded-2xl border border-white/10 bg-[#111722]/80 p-6 backdrop-blur-md relative overflow-hidden">
               <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(130deg,rgba(255,255,255,0.04),transparent_35%,rgba(0,240,255,0.05)_70%,transparent)]" />
               <div>
                  <div className="text-[11px] uppercase tracking-widest text-cyan-300 mb-2">Scan Report</div>
                  <h2 className="text-4xl font-black tracking-tight mb-2">Audit Report</h2>
                  <p className="text-gray-400">Analysis completed with <span className="text-cyan-300 font-semibold">{persona}</span> persona profile.</p>
               </div>
               <div className="relative z-10 flex gap-3">
                 <button onClick={clearResults} className="px-5 py-2.5 rounded-xl border border-white/15 bg-white/5 hover:bg-white/10 transition-colors text-sm font-semibold">
                   New Scan
                 </button>
                 <button 
                    onClick={() => downloadReport(results.report_id, loggedInUsername)}
                    className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-purple-600 hover:from-cyan-500 hover:to-purple-500 rounded-xl text-white font-bold shadow-lg shadow-purple-500/20 transition-transform hover:scale-[1.02]"
                  >
                   <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
                   Export PDF
                 </button>
               </div>
             </div>

             {/* Current scan info instead of provider selector */}
             <div className="bg-[#111722]/80 p-4 rounded-2xl border border-white/10 mb-8 flex items-center gap-4 backdrop-blur-md relative overflow-hidden">
               <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(120deg,rgba(255,255,255,0.03),transparent_40%,rgba(138,43,226,0.06)_80%,transparent)]" />
               <span className="text-2xl">{getModelInfo().icon}</span>
               <div className="relative z-10">
                 <div className="text-sm font-semibold text-gray-300">Analyzed with <span className={getModelInfo().color}>{getModelInfo().provider}</span> · Persona: <span className="text-cyan-300">{persona}</span></div>
                 <div className="text-xs text-gray-500">Click &quot;New Scan&quot; to start a fresh analysis.</div>
               </div>
             </div>

             {/* Metric Cards */}
             <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-10">
               <div className={`p-5 rounded-2xl border backdrop-blur-sm ${results.status === 'SAFE' ? 'bg-green-500/10 border-green-500/30' : results.status === 'ERROR' ? 'bg-yellow-500/10 border-yellow-500/30' : 'bg-red-500/10 border-red-500/30'}`}>
                 <div className={`text-3xl font-black mb-1 ${results.status === 'SAFE' ? 'text-green-400' : results.status === 'ERROR' ? 'text-yellow-400' : 'text-red-500'}`}>{results.status}</div>
                 <div className="text-xs text-gray-500 uppercase tracking-widest">Status</div>
               </div>
               <div className="p-5 rounded-2xl bg-[#131c28]/80 border border-[#2d3a4c] backdrop-blur-sm">
                 <div className="text-3xl font-black text-red-500 mb-1">{results.stats.High}</div>
                 <div className="text-xs text-gray-500 uppercase tracking-widest">High Risk</div>
               </div>
               <div className="p-5 rounded-2xl bg-[#1f1b13]/80 border border-[#4f4123] backdrop-blur-sm">
                 <div className="text-3xl font-black text-yellow-500 mb-1">{results.stats.Medium}</div>
                 <div className="text-xs text-gray-500 uppercase tracking-widest">Medium Risk</div>
               </div>
               <div className="p-5 rounded-2xl bg-[#141b2a]/80 border border-[#2f4367] backdrop-blur-sm">
                 <div className="text-3xl font-black text-blue-400 mb-1">{results.stats.Low}</div>
                 <div className="text-xs text-gray-500 uppercase tracking-widest">Low Risk</div>
               </div>
             </div>

             {/* Vulnerability Charts */}
             <VulnerabilityChart stats={results.stats} />

             {/* Dependency Audit Panel */}
             <DependencyAuditPanel
               files={selectedFiles}
               scanDependencies={scanDependencies}
               isDepScanning={isDepScanning}
               depResults={depResults}
             />

             <div className="mt-6 mb-4 rounded-xl bg-[#161b22] border border-blue-500/20 p-4 text-sm text-blue-200">
               <strong className="text-blue-300">Auto-Fix Mode:</strong> Review suggested fixes with one-click copy and preview the original vs fixed code when available.
             </div>

             {/* Findings Grouped by File */}
             <div className="space-y-8">
                <div className="flex items-center justify-between border-b border-[#30363d] pb-3">
                  <h3 className="text-2xl font-bold">Identified Vulnerabilities by File</h3>
                  {results.findings && results.findings.length > 0 && (
                    <button
                      onClick={toggleAllFiles}
                      className="px-4 py-2 bg-[#161b22] border border-[#30363d] rounded-xl hover:bg-[#1c2128] transition-colors text-sm font-medium flex items-center gap-2"
                    >
                      <svg className={`w-4 h-4 transition-transform ${expandedFiles.size === Object.keys(groupedFindings).length ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                      </svg>
                      {expandedFiles.size === Object.keys(groupedFindings).length ? 'Collapse All' : 'Expand All'}
                    </button>
                  )}
                </div>
                
                {results.findings && results.findings.length > 0 ? (
                  Object.entries(groupedFindings).map(([fileName, findings]) => {
                    const isExpanded = expandedFiles.has(fileName);
                    const severityCounts = findings.reduce((acc: any, finding: any) => {
                      const severity = finding.issue_description?.match(/\[(HIGH|MEDIUM|LOW)\]/i)?.[1] || "LOW";
                      acc[severity] = (acc[severity] || 0) + 1;
                      return acc;
                    }, {});
                    
                    return (
                      <div key={fileName} className="rounded-2xl border border-[#30363d] overflow-hidden bg-[#121922]/70 backdrop-blur-sm">
                        <button 
                          onClick={() => toggleFileExpansion(fileName)}
                          className="w-full bg-[#161b22]/90 p-4 border-b border-[#30363d] flex items-center justify-between hover:bg-[#1c2128] transition-colors"
                        >
                          <div className="flex items-center gap-3">
                            <svg 
                              className={`w-5 h-5 text-blue-400 transition-transform ${isExpanded ? 'rotate-90' : ''}`} 
                              fill="none" 
                              stroke="currentColor" 
                              viewBox="0 0 24 24"
                            >
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                            </svg>
                            <svg className="w-5 h-5 text-blue-400" fill="currentColor" viewBox="0 0 20 20">
                              <path d="M5.5 13a3.5 3.5 0 01-.369-6.98 4 4 0 117.753-1.3A4.5 4.5 0 1113.5 13H11V9.413l1.293 1.293a1 1 0 001.414-1.414l-3-3a1 1 0 00-1.414 0l-3 3a1 1 0 001.414 1.414L9 9.414V13H5.5z" />
                            </svg>
                            <span className="font-mono text-sm text-gray-300">{fileName}</span>
                          </div>
                          <div className="flex items-center gap-3">
                            <div className="flex gap-2">
                              {severityCounts.HIGH && (
                                <span className="px-2 py-1 bg-red-500/20 text-red-400 rounded text-xs font-bold">
                                  {severityCounts.HIGH} High
                                </span>
                              )}
                              {severityCounts.MEDIUM && (
                                <span className="px-2 py-1 bg-yellow-500/20 text-yellow-400 rounded text-xs font-bold">
                                  {severityCounts.MEDIUM} Medium
                                </span>
                              )}
                              {severityCounts.LOW && (
                                <span className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-xs font-bold">
                                  {severityCounts.LOW} Low
                                </span>
                              )}
                            </div>
                            <span className="px-3 py-1 bg-blue-500/20 text-blue-400 rounded-full text-xs font-bold">
                              {findings.length} issue{findings.length !== 1 ? "s" : ""}
                            </span>
                          </div>
                        </button>

                        {isExpanded && (
                          <div className="space-y-4 p-4">
                            {findings.map((finding: any, idx: number) => {
                              const severity = finding.issue_description?.match(/\[(HIGH|MEDIUM|LOW)\]/i)?.[1] || "LOW";
                              return (
                                <div key={idx} className={`p-4 rounded-lg border ${getSeverityBgColor(severity)}`}>
                                  <div className="flex items-start justify-between mb-2">
                                    <h4 className="font-bold text-gray-200">Issue {idx + 1}</h4>
                                    <span className={`px-2 py-1 rounded text-xs font-bold ${getSeverityBadgeColor(severity)}`}>
                                      {severity.toUpperCase()}
                                    </span>
                                  </div>
                                  <p className="text-gray-300 text-sm mb-3">{finding.issue_description}</p>
                                  <div className="flex flex-col gap-3">
                                    <div className="flex flex-wrap items-center gap-3 mb-2">
                                      <button
                                        onClick={() => copyToClipboard(finding.fixed_code?.trim() || finding.suggested_fix)}
                                        className="px-3 py-2 rounded-lg border border-[#30363d] bg-[#161b22] text-sm font-medium hover:bg-[#1c2128] transition-colors"
                                      >
                                        Copy Fixed Code
                                      </button>
                                      <button
                                        onClick={() => toggleDiffPanel(getFindingKey(fileName, idx))}
                                        className="px-3 py-2 rounded-lg border border-[#30363d] bg-[#161b22] text-sm font-medium hover:bg-[#1c2128] transition-colors"
                                      >
                                        {expandedDiffs[getFindingKey(fileName, idx)] ? 'Hide Fix Preview' : 'Show Fix Preview'}
                                      </button>
                                      {copiedMessage && (
                                        <span className="text-xs text-green-300">{copiedMessage}</span>
                                      )}
                                    </div>
                                    {expandedDiffs[getFindingKey(fileName, idx)] ? (
                                      <div className="bg-[#0d1117] p-4 rounded border border-[#30363d]">
                                        {finding.source_code || finding.fixed_code ? (
                                          renderFixComparison(finding)
                                        ) : (
                                          <>
                                            <p className="text-green-400 text-xs font-semibold mb-2">Suggested Fix:</p>
                                            <pre className="text-gray-400 text-sm font-mono whitespace-pre-wrap break-words">{finding.suggested_fix}</pre>
                                          </>
                                        )}
                                      </div>
                                    ) : (
                                      <div className="bg-[#0d1117] p-3 rounded border border-[#30363d]">
                                        <p className="text-green-400 text-xs font-semibold mb-1">Suggested Fix:</p>
                                        <p className="text-gray-400 text-sm font-mono whitespace-pre-wrap break-words">{finding.suggested_fix}</p>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })
                ) : (
                  <div className="p-10 rounded-xl bg-green-500/5 border border-green-500/20 text-center">
                    <div className="text-4xl mb-4">✨</div>
                    <h3 className="text-xl font-bold text-green-400">Your code is crystal clear!</h3>
                    <p className="text-green-500/70">No vulnerabilities detected based on the current strictness settings.</p>
                  </div>
                )}
             </div>

             {/* Improvement Suggestions for Students */}
             {persona === "Student" && (results as any).improvement_suggestions && (results as any).improvement_suggestions.length > 0 && (
               <div className="mt-10 space-y-4">
                 <h3 className="text-2xl font-bold border-b border-[#30363d] pb-2 flex items-center gap-3">
                   <span className="text-2xl">💡</span>
                   Project Improvement Suggestions
                 </h3>
                 <div className="grid gap-3">
                   {(results as any).improvement_suggestions.map((suggestion: string, idx: number) => (
                     <div key={idx} className="p-4 rounded-lg bg-blue-500/10 border border-blue-500/30">
                       <div className="flex gap-3">
                         <div className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500/30 flex items-center justify-center flex-col">
                           <span className="text-xs font-bold text-blue-400">{idx + 1}</span>
                         </div>
                         <div>
                           <p className="text-gray-300 text-sm leading-relaxed">{suggestion}</p>
                         </div>
                       </div>
                     </div>
                   ))}
                 </div>
               </div>
             )}
          </div>
        )}

      </main>
    </div>
  );
}
