"use client";
import React, { useState, useRef, useEffect } from "react";
import Head from "next/head";
import { useScan } from "./hooks/useScan";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";

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

const VulnerabilityChart = ({ stats }: { stats: any }) => {
  const chartData = [
    { name: "High", value: stats.High || 0, fill: "#ef4444" },
    { name: "Medium", value: stats.Medium || 0, fill: "#eab308" },
    { name: "Low", value: stats.Low || 0, fill: "#3b82f6" },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-10">
      <div className="bg-[#161b22] p-6 rounded-xl border border-[#30363d]">
        <h3 className="text-lg font-bold mb-6 text-gray-200">Distribution by Severity</h3>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
            <XAxis dataKey="name" stroke="#8b949e" />
            <YAxis stroke="#8b949e" />
            <Tooltip
              contentStyle={{
                backgroundColor: "#161b22",
                border: "1px solid #30363d",
                borderRadius: "8px",
                color: "#c9d1d9",
              }}
            />
            <Bar dataKey="value" fill="#3b82f6" radius={[8, 8, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="bg-[#161b22] p-6 rounded-xl border border-[#30363d]">
        <h3 className="text-lg font-bold mb-6 text-gray-200">Overview</h3>
        <ResponsiveContainer width="100%" height={300}>
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              labelLine={false}
              label={({ name, value }) => `${name}: ${value}`}
              outerRadius={80}
              fill="#8884d8"
              dataKey="value"
            >
              {chartData.map((entry, index) => (
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
      </div>
    </div>
  );
};

export default function Home() {
  // --- States ---
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [persona, setPersona] = useState<"Student" | "Professional">("Student");
  const [apiKey, setApiKey] = useState("");
  const [selectedProvider, setSelectedProvider] = useState<"auto" | "groq" | "openai" | "gemini" | "ollama">("auto");
  const [mounted, setMounted] = useState(false);

  const [isHovered, setIsHovered] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedFiles, setSelectedFiles] = useState<FileList | null>(null);
  const [expandedFiles, setExpandedFiles] = useState<Set<string>>(new Set());

  // Hook for backend connection
  const { uploadFile, downloadReport, isScanning, results, error, clearError, clearResults } = useScan("http://localhost:8000");

  // Prevent hydration mismatch
  useEffect(() => {
    setMounted(true);
  }, []);

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
    if (selectedProvider === "auto") {
      if (!apiKey) return { provider: "Ollama", icon: "🦙", color: "text-purple-400" };
      
      const key = apiKey.trim();
      if (key.startsWith("gsk_")) return { provider: "Groq", icon: "⚡", color: "text-blue-400" };
      if (key.startsWith("sk-")) return { provider: "OpenAI", icon: "🤖", color: "text-green-400" };
      if (key.startsWith("AIzaSy")) return { provider: "Google Gemini", icon: "✨", color: "text-yellow-400" };
      
      return { provider: "Unknown", icon: "❓", color: "text-gray-400" };
    }
    
    // Manual provider selection
    switch (selectedProvider) {
      case "groq": return { provider: "Groq", icon: "⚡", color: "text-blue-400" };
      case "openai": return { provider: "OpenAI", icon: "🤖", color: "text-green-400" };
      case "gemini": return { provider: "Google Gemini", icon: "✨", color: "text-yellow-400" };
      case "ollama": return { provider: "Ollama", icon: "🦙", color: "text-purple-400" };
      default: return { provider: "Unknown", icon: "❓", color: "text-gray-400" };
    }
  };

  const runAnalysis = () => {
    if (selectedFiles) {
      uploadFile(selectedFiles, persona, apiKey, selectedProvider);
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

  return (
    <div className="min-h-screen bg-[#0d1117] text-[#c9d1d9] font-sans selection:bg-blue-500/30 pb-20">
      <Head>
        <title>CodeGuard AI - Identity & Scan</title>
      </Head>

      {/* Navbar Minimalist */}
      <nav className="border-b border-[#30363d] bg-[#161b22]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-lg shadow-blue-500/20">
              <span className="text-white font-bold text-xl">🛡️</span>
            </div>
            <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-gray-100 to-gray-400">
              CodeGuard AI
            </h1>
          </div>
          <div className="flex gap-4 items-center">
            {isLoggedIn && (
              <>
                {/* Profile Card */}
                <div className="px-4 py-2 bg-[#0d1117] border border-[#30363d] rounded-lg flex items-center gap-3">
                  <div className="flex flex-col gap-1">
                    <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Account</div>
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${persona === 'Student' ? 'bg-blue-400' : 'bg-red-500'}`}></span>
                      <span className="text-sm font-semibold text-gray-300">{persona === 'Student' ? '🎓 Student' : '🕵️ Auditor'}</span>
                    </div>
                  </div>
                  <div className="w-px h-8 bg-[#30363d]"></div>
                  <div className="flex flex-col gap-1">
                    <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Model</div>
                    <div className="flex items-center gap-1.5">
                      {mounted ? (
                        <>
                          <span className="text-lg">{getModelInfo().icon}</span>
                          <span className={`text-sm font-semibold ${getModelInfo().color}`}>{getModelInfo().provider}</span>
                        </>
                      ) : (
                        <>
                          <span className="text-lg">🔍</span>
                          <span className="text-sm font-semibold text-gray-400">Loading...</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
                
                {/* Original Status Indicator */}
                <div className="px-3 py-1 bg-[#0d1117] border border-[#30363d] rounded-full text-xs font-semibold text-gray-400 flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${persona === 'Student' ? 'bg-blue-400' : 'bg-red-500 animate-pulse'}`}></span>
                  {persona === 'Student' ? 'Learning Mode' : 'Auditor Mode'} Active
                </div>
              </>
            )}
          </div>
        </div>
      </nav>

      {/* Application Main Body */}
      <main className="max-w-5xl mx-auto px-6 py-12 flex flex-col items-center">
        
        {/* --- VIEW 1: LOGIN / PERSONA SELECTION --- */}
        {!isLoggedIn && (
          <div className="w-full max-w-2xl mt-10 animate-fade-in">
            <div className="text-center mb-10">
              <h2 className="text-4xl font-extrabold tracking-tight mb-4">Identify Yourself</h2>
              <p className="text-gray-400">Choose your analysis strictness and role.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
              {/* Persona 1: Student */}
              <div 
                onClick={() => setPersona("Student")}
                className={`cursor-pointer p-6 rounded-2xl border-2 transition-all duration-300 ${
                  persona === "Student" 
                    ? "border-blue-500 bg-blue-500/10 shadow-lg shadow-blue-500/20" 
                    : "border-[#30363d] bg-[#161b22] hover:border-gray-500"
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
                    ? "border-red-500 bg-red-500/10 shadow-lg shadow-red-500/20" 
                    : "border-[#30363d] bg-[#161b22] hover:border-gray-500"
                }`}
              >
                <div className="text-4xl mb-4">🕵️‍♂️</div>
                <h3 className="text-xl font-bold text-white mb-2">Lead Auditor</h3>
                <p className="text-sm text-gray-400">Ruthless, enterprise-grade AI auditor. Flags every minor risk as vulnerable.</p>
              </div>
            </div>

            <div className="bg-[#161b22] p-6 rounded-2xl border border-[#30363d] mb-8">
              <label className="block text-sm font-semibold mb-2 text-gray-300">AI API Key (Optional)</label>
              <input 
                type="password" 
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="gsk_... or sk-... or AIzaSy..."
                className="w-full bg-[#0d1117] border border-[#30363d] rounded-lg px-4 py-3 text-white focus:outline-none focus:border-blue-500 transition-colors"
              />
              <p className="text-xs text-gray-500 mt-2">Supports: Groq (gsk_), OpenAI (sk-), Google Gemini (AIzaSy), or fallback to local Ollama.</p>
            </div>

            <div className="bg-[#161b22] p-6 rounded-2xl border border-[#30363d] mb-8">
              <label className="block text-sm font-semibold mb-4 text-gray-300">AI Provider Selection</label>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                <div 
                  onClick={() => setSelectedProvider("auto")}
                  className={`cursor-pointer p-4 rounded-lg border-2 transition-all duration-200 text-center ${
                    selectedProvider === "auto" 
                      ? "border-blue-500 bg-blue-500/10" 
                      : "border-[#30363d] bg-[#0d1117] hover:border-gray-500"
                  }`}
                >
                  <div className="text-2xl mb-2">🔍</div>
                  <div className="text-sm font-semibold text-white">Auto Detect</div>
                  <div className="text-xs text-gray-500">From API key</div>
                </div>
                <div 
                  onClick={() => setSelectedProvider("groq")}
                  className={`cursor-pointer p-4 rounded-lg border-2 transition-all duration-200 text-center ${
                    selectedProvider === "groq" 
                      ? "border-blue-500 bg-blue-500/10" 
                      : "border-[#30363d] bg-[#0d1117] hover:border-gray-500"
                  }`}
                >
                  <div className="text-2xl mb-2">⚡</div>
                  <div className="text-sm font-semibold text-white">Groq</div>
                  <div className="text-xs text-gray-500">Fast & Free</div>
                </div>
                <div 
                  onClick={() => setSelectedProvider("openai")}
                  className={`cursor-pointer p-4 rounded-lg border-2 transition-all duration-200 text-center ${
                    selectedProvider === "openai" 
                      ? "border-green-500 bg-green-500/10" 
                      : "border-[#30363d] bg-[#0d1117] hover:border-gray-500"
                  }`}
                >
                  <div className="text-2xl mb-2">🤖</div>
                  <div className="text-sm font-semibold text-white">OpenAI</div>
                  <div className="text-xs text-gray-500">GPT-4o Mini</div>
                </div>
                <div 
                  onClick={() => setSelectedProvider("gemini")}
                  className={`cursor-pointer p-4 rounded-lg border-2 transition-all duration-200 text-center ${
                    selectedProvider === "gemini" 
                      ? "border-yellow-500 bg-yellow-500/10" 
                      : "border-[#30363d] bg-[#0d1117] hover:border-gray-500"
                  }`}
                >
                  <div className="text-2xl mb-2">✨</div>
                  <div className="text-sm font-semibold text-white">Gemini</div>
                  <div className="text-xs text-gray-500">Google AI</div>
                </div>
                <div 
                  onClick={() => setSelectedProvider("ollama")}
                  className={`cursor-pointer p-4 rounded-lg border-2 transition-all duration-200 text-center ${
                    selectedProvider === "ollama" 
                      ? "border-purple-500 bg-purple-500/10" 
                      : "border-[#30363d] bg-[#0d1117] hover:border-gray-500"
                  }`}
                >
                  <div className="text-2xl mb-2">🦙</div>
                  <div className="text-sm font-semibold text-white">Ollama</div>
                  <div className="text-xs text-gray-500">Local AI</div>
                </div>
              </div>
              <p className="text-xs text-gray-500 mt-3">
                Choose "Auto Detect" to automatically select based on your API key, or manually select a provider to override.
              </p>
            </div>

            <button 
              onClick={() => setIsLoggedIn(true)}
              className="w-full py-4 rounded-xl bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white font-bold text-lg transition-transform hover:scale-[1.01] shadow-xl shadow-blue-500/20"
            >
              Enter System
            </button>
          </div>
        )}

        {/* --- VIEW 2: DASHBOARD (UPLOAD) --- */}
        {isLoggedIn && !results && (
          <div className="w-full mt-10 animate-fade-in flex flex-col items-center">
             <div className="text-center mb-12">
               <h2 className="text-5xl font-extrabold tracking-tight mb-4">
                  Secure Your Code. <br className="hidden md:block" />
                  <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-500">
                    Powered by AI.
                  </span>
                </h2>
                <p className="text-lg text-gray-400 max-w-2xl mx-auto">
                  Upload your Python, JS, or C++ files for an instant, deep vulnerability scan.
                </p>
             </div>

             {/* Dynamic Provider Selection */}
             <div className="bg-[#161b22] p-6 rounded-2xl border border-[#30363d] mb-8 w-full max-w-4xl">
               <label className="block text-sm font-semibold mb-4 text-gray-300">AI Provider Selection</label>
               <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                 <div 
                   onClick={() => setSelectedProvider("auto")}
                   className={`cursor-pointer p-4 rounded-lg border-2 transition-all duration-200 text-center ${
                     selectedProvider === "auto" 
                       ? "border-blue-500 bg-blue-500/10" 
                       : "border-[#30363d] bg-[#0d1117] hover:border-gray-500"
                   }`}
                 >
                   <div className="text-2xl mb-2">🔍</div>
                   <div className="text-sm font-semibold text-white">Auto Detect</div>
                   <div className="text-xs text-gray-500">From API key</div>
                 </div>
                 <div 
                   onClick={() => setSelectedProvider("groq")}
                   className={`cursor-pointer p-4 rounded-lg border-2 transition-all duration-200 text-center ${
                     selectedProvider === "groq" 
                       ? "border-blue-500 bg-blue-500/10" 
                       : "border-[#30363d] bg-[#0d1117] hover:border-gray-500"
                   }`}
                 >
                   <div className="text-2xl mb-2">⚡</div>
                   <div className="text-sm font-semibold text-white">Groq</div>
                   <div className="text-xs text-gray-500">Fast & Free</div>
                 </div>
                 <div 
                   onClick={() => setSelectedProvider("openai")}
                   className={`cursor-pointer p-4 rounded-lg border-2 transition-all duration-200 text-center ${
                     selectedProvider === "openai" 
                       ? "border-green-500 bg-green-500/10" 
                       : "border-[#30363d] bg-[#0d1117] hover:border-gray-500"
                   }`}
                 >
                   <div className="text-2xl mb-2">🤖</div>
                   <div className="text-sm font-semibold text-white">OpenAI</div>
                   <div className="text-xs text-gray-500">GPT-4o Mini</div>
                 </div>
                 <div 
                   onClick={() => setSelectedProvider("gemini")}
                   className={`cursor-pointer p-4 rounded-lg border-2 transition-all duration-200 text-center ${
                     selectedProvider === "gemini" 
                       ? "border-yellow-500 bg-yellow-500/10" 
                       : "border-[#30363d] bg-[#0d1117] hover:border-gray-500"
                   }`}
                 >
                   <div className="text-2xl mb-2">✨</div>
                   <div className="text-sm font-semibold text-white">Gemini</div>
                   <div className="text-xs text-gray-500">Google AI</div>
                 </div>
                 <div 
                   onClick={() => setSelectedProvider("ollama")}
                   className={`cursor-pointer p-4 rounded-lg border-2 transition-all duration-200 text-center ${
                     selectedProvider === "ollama" 
                       ? "border-purple-500 bg-purple-500/10" 
                       : "border-[#30363d] bg-[#0d1117] hover:border-gray-500"
                   }`}
                 >
                   <div className="text-2xl mb-2">🦙</div>
                   <div className="text-sm font-semibold text-white">Ollama</div>
                   <div className="text-xs text-gray-500">Local AI</div>
                 </div>
               </div>
               <p className="text-xs text-gray-500 mt-3">
                 Choose your AI provider for this scan. Changes take effect immediately.
               </p>
             </div>

             {error && (
               <div className="w-full max-w-2xl bg-red-500/10 border border-red-500/50 text-red-500 p-4 rounded-xl mb-6 flex justify-between items-center">
                 <span>{error}</span>
                 <button onClick={clearError} className="text-red-400 hover:text-white">✕</button>
               </div>
             )}

             <div 
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`w-full max-w-2xl p-16 rounded-2xl border-2 border-dashed transition-all duration-300 cursor-pointer flex flex-col items-center justify-center gap-4 ${
                  isHovered 
                    ? "bg-[#161b22] border-blue-500 shadow-2xl shadow-blue-500/10 scale-[1.02]" 
                    : "bg-[#161b22]/50 border-[#30363d] hover:border-blue-500/50 hover:bg-[#161b22]"
                }`}
              >
                <input 
                  type="file" 
                  multiple 
                  className="hidden" 
                  ref={fileInputRef} 
                  onChange={handleFileChange}
                  accept=".py,.js,.ts,.cpp,.h,.zip"
                />
                <div className="w-20 h-20 rounded-full bg-blue-500/10 flex items-center justify-center mb-2">
                  <svg className="w-10 h-10 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                  </svg>
                </div>
                {selectedFiles ? (
                  <h3 className="text-xl font-bold text-green-400">{selectedFiles.length} file(s) selected</h3>
                ) : (
                  <h3 className="text-xl font-bold text-gray-200">Drag & Drop source files here</h3>
                )}
                <p className="text-sm text-gray-500 text-center">Supports .py, .cpp, .js, or .zip archives</p>
                <div className="mt-4 px-8 py-3 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold transition-colors shadow-lg shadow-blue-500/25">
                  Browse Files
                </div>
            </div>

            {selectedFiles && (
              <button 
                onClick={(e) => { e.stopPropagation(); runAnalysis(); }}
                disabled={isScanning}
                className={`mt-10 px-12 py-4 rounded-xl font-bold text-xl text-white transition-all shadow-xl ${
                  isScanning 
                    ? "bg-[#30363d] cursor-not-allowed animate-pulse" 
                    : "bg-gradient-to-r from-blue-600 to-purple-600 hover:scale-105 shadow-purple-500/20"
                }`}
              >
                {isScanning ? "🔮 Agents Analyzing Code..." : "🚀 Run AI Scan"}
              </button>
            )}
          </div>
        )}

        {/* --- VIEW 3: RESULTS & PDF EXPORT --- */}
        {results && (
          <div className="w-full mt-10 animate-fade-in">
             <div className="flex justify-between items-end mb-8">
               <div>
                  <h2 className="text-4xl font-extrabold tracking-tight mb-2">Audit Report</h2>
                  <p className="text-gray-400">Analysis completed based on your selected persona ({persona}).</p>
               </div>
               <div className="flex gap-4">
                 <button onClick={clearResults} className="px-6 py-2 rounded-lg border border-[#30363d] hover:bg-[#161b22] transition-colors">
                   New Scan
                 </button>
                 <button 
                    onClick={() => downloadReport(results.report_id)}
                    className="flex items-center gap-2 px-6 py-2 bg-purple-600 hover:bg-purple-500 rounded-lg text-white font-bold shadow-lg shadow-purple-500/20 transition-transform hover:scale-105"
                  >
                   <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
                   Export PDF
                 </button>
               </div>
             </div>

             {/* Dynamic Provider Selection for Next Scan */}
             <div className="bg-[#161b22] p-6 rounded-2xl border border-[#30363d] mb-8">
               <label className="block text-sm font-semibold mb-4 text-gray-300">Change AI Provider for Next Scan</label>
               <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                 <div 
                   onClick={() => setSelectedProvider("auto")}
                   className={`cursor-pointer p-4 rounded-lg border-2 transition-all duration-200 text-center ${
                     selectedProvider === "auto" 
                       ? "border-blue-500 bg-blue-500/10" 
                       : "border-[#30363d] bg-[#0d1117] hover:border-gray-500"
                   }`}
                 >
                   <div className="text-2xl mb-2">🔍</div>
                   <div className="text-sm font-semibold text-white">Auto Detect</div>
                   <div className="text-xs text-gray-500">From API key</div>
                 </div>
                 <div 
                   onClick={() => setSelectedProvider("groq")}
                   className={`cursor-pointer p-4 rounded-lg border-2 transition-all duration-200 text-center ${
                     selectedProvider === "groq" 
                       ? "border-blue-500 bg-blue-500/10" 
                       : "border-[#30363d] bg-[#0d1117] hover:border-gray-500"
                   }`}
                 >
                   <div className="text-2xl mb-2">⚡</div>
                   <div className="text-sm font-semibold text-white">Groq</div>
                   <div className="text-xs text-gray-500">Fast & Free</div>
                 </div>
                 <div 
                   onClick={() => setSelectedProvider("openai")}
                   className={`cursor-pointer p-4 rounded-lg border-2 transition-all duration-200 text-center ${
                     selectedProvider === "openai" 
                       ? "border-green-500 bg-green-500/10" 
                       : "border-[#30363d] bg-[#0d1117] hover:border-gray-500"
                   }`}
                 >
                   <div className="text-2xl mb-2">🤖</div>
                   <div className="text-sm font-semibold text-white">OpenAI</div>
                   <div className="text-xs text-gray-500">GPT-4o Mini</div>
                 </div>
                 <div 
                   onClick={() => setSelectedProvider("gemini")}
                   className={`cursor-pointer p-4 rounded-lg border-2 transition-all duration-200 text-center ${
                     selectedProvider === "gemini" 
                       ? "border-yellow-500 bg-yellow-500/10" 
                       : "border-[#30363d] bg-[#0d1117] hover:border-gray-500"
                   }`}
                 >
                   <div className="text-2xl mb-2">✨</div>
                   <div className="text-sm font-semibold text-white">Gemini</div>
                   <div className="text-xs text-gray-500">Google AI</div>
                 </div>
                 <div 
                   onClick={() => setSelectedProvider("ollama")}
                   className={`cursor-pointer p-4 rounded-lg border-2 transition-all duration-200 text-center ${
                     selectedProvider === "ollama" 
                       ? "border-purple-500 bg-purple-500/10" 
                       : "border-[#30363d] bg-[#0d1117] hover:border-gray-500"
                   }`}
                 >
                   <div className="text-2xl mb-2">🦙</div>
                   <div className="text-sm font-semibold text-white">Ollama</div>
                   <div className="text-xs text-gray-500">Local AI</div>
                 </div>
               </div>
               <p className="text-xs text-gray-500 mt-3">
                 Select a different provider and click "New Scan" to analyze with the new AI model.
               </p>
             </div>

             {/* Metric Cards */}
             <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-10 text-center">
               <div className={`p-6 rounded-xl border ${results.status === 'SAFE' ? 'bg-green-500/10 border-green-500/30' : results.status === 'ERROR' ? 'bg-yellow-500/10 border-yellow-500/30' : 'bg-red-500/10 border-red-500/30'}`}>
                 <div className={`text-3xl font-black mb-1 ${results.status === 'SAFE' ? 'text-green-400' : results.status === 'ERROR' ? 'text-yellow-400' : 'text-red-500'}`}>{results.status}</div>
                 <div className="text-sm text-gray-500 uppercase tracking-wide">Status</div>
               </div>
               <div className="p-6 rounded-xl bg-[#161b22] border border-[#30363d]">
                 <div className="text-3xl font-black text-red-500 mb-1">{results.stats.High}</div>
                 <div className="text-sm text-gray-500 uppercase tracking-wide">High Risk</div>
               </div>
               <div className="p-6 rounded-xl bg-[#161b22] border border-[#30363d]">
                 <div className="text-3xl font-black text-yellow-500 mb-1">{results.stats.Medium}</div>
                 <div className="text-sm text-gray-500 uppercase tracking-wide">Medium Risk</div>
               </div>
               <div className="p-6 rounded-xl bg-[#161b22] border border-[#30363d]">
                 <div className="text-3xl font-black text-blue-400 mb-1">{results.stats.Low}</div>
                 <div className="text-sm text-gray-500 uppercase tracking-wide">Low Risk</div>
               </div>
             </div>

             {/* Vulnerability Charts */}
             <VulnerabilityChart stats={results.stats} />

             {/* Findings Grouped by File */}
             <div className="space-y-8">
                <div className="flex items-center justify-between border-b border-[#30363d] pb-2">
                  <h3 className="text-2xl font-bold">Identified Vulnerabilities by File</h3>
                  {results.findings && results.findings.length > 0 && (
                    <button
                      onClick={toggleAllFiles}
                      className="px-4 py-2 bg-[#161b22] border border-[#30363d] rounded-lg hover:bg-[#1c2128] transition-colors text-sm font-medium flex items-center gap-2"
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
                      <div key={fileName} className="rounded-xl border border-[#30363d] overflow-hidden">
                        <button 
                          onClick={() => toggleFileExpansion(fileName)}
                          className="w-full bg-[#161b22] p-4 border-b border-[#30363d] flex items-center justify-between hover:bg-[#1c2128] transition-colors"
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
                                  <div className="bg-[#0d1117] p-3 rounded border border-[#30363d]">
                                    <p className="text-green-400 text-xs font-semibold mb-1">Suggested Fix:</p>
                                    <p className="text-gray-400 text-sm font-mono">{finding.suggested_fix}</p>
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
