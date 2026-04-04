"use client";
import React, { useState } from "react";
import Head from "next/head";

export default function Home() {
  const [isHovered, setIsHovered] = useState(false);

  return (
    <div className="min-h-screen bg-[#0d1117] text-[#c9d1d9] font-sans selection:bg-blue-500/30">
      <Head>
        <title>CodeGuard AI - Next-Gen Security Auditor</title>
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
            <button className="text-sm font-medium hover:text-white transition-colors">
              Auditor Home
            </button>
            <button className="text-sm font-medium hover:text-white transition-colors">
              My Profile
            </button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <main className="max-w-5xl mx-auto px-6 py-20 flex flex-col items-center text-center">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold uppercase tracking-wider mb-8">
          <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>
          System Live
        </div>
        
        <h2 className="text-5xl md:text-7xl font-extrabold tracking-tight mb-6">
          Secure Your Code. <br className="hidden md:block" />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-500">
            Powered by AI.
          </span>
        </h2>
        
        <p className="text-lg md:text-xl text-gray-400 max-w-2xl mb-12 leading-relaxed">
          The ultimate defense for your software. Upload your Python, JS, or C++ files and our rigorous security AI will audit them instantly.
        </p>

        {/* Upload Card */}
        <div 
          className={`w-full max-w-2xl p-12 rounded-2xl border transition-all duration-500 cursor-pointer flex flex-col items-center justify-center gap-4 ${
            isHovered 
              ? "bg-[#161b22] border-blue-500/50 shadow-2xl shadow-blue-500/10 scale-[1.02]" 
              : "bg-[#161b22]/50 border-[#30363d]"
          }`}
          onMouseEnter={() => setIsHovered(true)}
          onMouseLeave={() => setIsHovered(false)}
        >
          <div className="w-16 h-16 rounded-full bg-blue-500/10 flex items-center justify-center mb-2">
            <svg className="w-8 h-8 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
            </svg>
          </div>
          <h3 className="text-xl font-bold text-gray-200">
            Drag & Drop source files here
          </h3>
          <p className="text-sm text-gray-500 text-center">
            Supports .py, .cpp, .js, .h, or .zip archives
          </p>
          <div className="mt-4 px-6 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium transition-colors shadow-lg shadow-blue-500/25">
            Browse Files
          </div>
        </div>

        {/* Info Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-20 w-full max-w-4xl text-left">
          <div className="p-6 rounded-xl bg-[#161b22] border border-[#30363d]">
            <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center text-purple-400 mb-4 text-xl">🧠</div>
            <h4 className="font-bold mb-2">Dual AI Engines</h4>
            <p className="text-sm text-gray-400">Powered by Groq LLama-3 and fallback local Ollama models.</p>
          </div>
          <div className="p-6 rounded-xl bg-[#161b22] border border-[#30363d]">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center text-green-400 mb-4 text-xl">⚡</div>
            <h4 className="font-bold mb-2">Instant Audits</h4>
            <p className="text-sm text-gray-400">Deep line-by-line vulnerability detection in seconds.</p>
          </div>
          <div className="p-6 rounded-xl bg-[#161b22] border border-[#30363d]">
            <div className="w-10 h-10 rounded-lg bg-pink-500/10 flex items-center justify-center text-pink-400 mb-4 text-xl">📄</div>
            <h4 className="font-bold mb-2">PDF Reports</h4>
            <p className="text-sm text-gray-400">Generate stunning auditor-ready PDF reports instantly.</p>
          </div>
        </div>
      </main>
    </div>
  );
}
