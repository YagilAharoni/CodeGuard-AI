"use client";
import React, { useState, useRef } from "react";
import Head from "next/head";
import { useScan } from "./hooks/useScan";

export default function Home() {
  // --- States ---
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [persona, setPersona] = useState<"Student" | "Professional">("Student");
  const [apiKey, setApiKey] = useState("");

  const [isHovered, setIsHovered] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedFiles, setSelectedFiles] = useState<FileList | null>(null);

  // Hook for backend connection
  const { uploadFile, downloadReport, isScanning, results, error, clearError, clearResults } = useScan("http://localhost:8000");

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

  const runAnalysis = () => {
    if (selectedFiles) {
      uploadFile(selectedFiles, persona, apiKey);
    }
  };

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
          <div className="flex gap-4">
            {isLoggedIn && (
               <div className="px-3 py-1 bg-[#0d1117] border border-[#30363d] rounded-full text-xs font-semibold text-gray-400 flex items-center gap-2">
                 <span className={`w-2 h-2 rounded-full ${persona === 'Student' ? 'bg-blue-400' : 'bg-red-500 animate-pulse'}`}></span>
                 {persona === 'Student' ? 'Learning Mode' : 'Auditor Mode'} Active
               </div>
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
              <label className="block text-sm font-semibold mb-2 text-gray-300">Groq API Key (Optional for Llama-3)</label>
              <input 
                type="password" 
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="gsk_..."
                className="w-full bg-[#0d1117] border border-[#30363d] rounded-lg px-4 py-3 text-white focus:outline-none focus:border-blue-500 transition-colors"
              />
              <p className="text-xs text-gray-500 mt-2">If empty, system will fallback to local Ollama models.</p>
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

             {/* Metric Cards */}
             <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-10 text-center">
               <div className={`p-6 rounded-xl border ${results.status === 'SAFE' ? 'bg-green-500/10 border-green-500/30' : 'bg-[#161b22] border-[#30363d]'}`}>
                 <div className="text-3xl font-black mb-1">{results.status}</div>
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

             {/* Findings */}
             <div className="space-y-6">
                <h3 className="text-2xl font-bold border-b border-[#30363d] pb-2">Identified Vulnerabilities</h3>
                {results.findings && results.findings.length > 0 ? (
                  results.findings.map((finding, idx) => (
                    <div key={idx} className="p-6 rounded-xl bg-[#161b22] border border-red-500/20 shadow-lg shadow-red-500/5">
                      <div className="flex items-center gap-3 mb-4">
                        <span className="px-3 py-1 bg-red-500/20 text-red-400 rounded-md text-xs font-bold font-mono">
                          {finding.file_name}
                        </span>
                      </div>
                      <h4 className="text-lg font-bold text-gray-200 mb-2">Issue Description</h4>
                      <p className="text-gray-400 mb-6 font-mono text-sm bg-[#0d1117] p-4 rounded-lg border border-[#30363d]">
                        {finding.issue_description}
                      </p>
                      <h4 className="text-lg font-bold text-green-400 mb-2 flex items-center gap-2">
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                        Suggested Fix
                      </h4>
                      <p className="text-gray-300 font-mono text-sm bg-[#0d1117] p-4 rounded-lg border border-[#30363d]">
                        {finding.suggested_fix}
                      </p>
                    </div>
                  ))
                ) : (
                  <div className="p-10 rounded-xl bg-green-500/5 border border-green-500/20 text-center">
                    <div className="text-4xl mb-4">✨</div>
                    <h3 className="text-xl font-bold text-green-400">Your code is crystal clear!</h3>
                    <p className="text-green-500/70">No vulnerabilities detected based on the current strictness settings.</p>
                  </div>
                )}
             </div>
          </div>
        )}

      </main>
    </div>
  );
}
