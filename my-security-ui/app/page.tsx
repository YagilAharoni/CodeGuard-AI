"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { isAuthenticated, saveAuthSession } from "./lib/auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function Home() {
  const router = useRouter();
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const handleHeroAction = (action: "initialize" | "explore") => {
    if (isAuthenticated()) {
      router.push(`/dashboard?action=${action}`);
      return;
    }

    const authSection = document.getElementById("auth");
    authSection?.scrollIntoView({ behavior: "smooth", block: "start" });
    setError("Please log in first to start a scan.");
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      const trimmedUsername = username.trim();

      if (isLogin) {
        // Login Flow

        const res = await fetch(`${API_BASE}/api/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ login: trimmedUsername, password }),
        });

        if (res.ok) {
          const data = await res.json();
          saveAuthSession(data.token, data.expires_in, data.user);
          router.push("/dashboard");
        } else {
          const data = await res.json().catch(() => null);
          setError(data?.detail || "Invalid credentials");
        }
      } else {
        // Register Flow
        const normalizedEmail = email.trim();
        const effectiveEmail = normalizedEmail || `${trimmedUsername.toLowerCase()}@codeguard.local`;
        const res = await fetch(`${API_BASE}/api/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ username: trimmedUsername, email: effectiveEmail, password }),
        });

        if (res.ok) {
          const loginRes = await fetch(`${API_BASE}/api/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ login: trimmedUsername, password }),
          });

          if (loginRes.ok) {
            const data = await loginRes.json();
            saveAuthSession(data.token, data.expires_in, data.user);
            router.push("/dashboard");
          } else {
            setIsLogin(true);
            setError("Node initialized. Please authenticate.");
          }
        } else {
          try {
            const data = await res.json();
            setError(data.detail || "Error creating node");
          } catch {
            setError("Network anomaly. Node registration failed.");
          }
        }
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred.");
    }
  };

  return (
    <div className="min-h-screen bg-[#030303] text-white selection:bg-[#E8FF5A] selection:text-black overflow-hidden relative font-sans">
      {/* Dynamic Background Orbs */}
      <div className="absolute top-[-10%] right-[-5%] w-[800px] h-[800px] bg-gradient-to-br from-[#E8FF5A]/10 to-[#00F0FF]/5 rounded-full blur-[150px] -z-10 mix-blend-screen animate-float"></div>
      <div className="absolute top-[40%] left-[-10%] w-[600px] h-[600px] bg-gradient-to-tr from-[#8B5CF6]/10 to-[#00F0FF]/10 rounded-full blur-[120px] -z-10 mix-blend-screen animate-float transition-all delay-700"></div>
      <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI4IiBoZWlnaHQ9IjgiPjxyZWN0IHdpZHRoPSI4IiBoZWlnaHQ9IjgiIGZpbGw9IiNmZmYiIGZpbGwtb3BhY2l0eT0iMC4wMiIvPjxpbGluZSB4MT0iMCIgeTE9IjgiIHgyPSI4IiB5Mj0iMCIgc3Ryb2tlPSIjZmZmIiBzdHJva2Utb3BhY2l0eT0iMC4wMSIvPjwvc3ZnPg==')] opacity-30 mix-blend-overlay pointer-events-none -z-10"></div>
      
      {/* Navigation */}
      <nav className="fixed w-full z-50 top-0 pt-6 px-4 md:px-10 flex justify-between items-center bg-gradient-to-b from-[#030303] to-transparent pb-6 backdrop-blur-sm mask-image-gradient">
        <div className="flex items-center gap-4 group cursor-pointer">
          <div className="w-10 h-10 rounded-2xl bg-gradient-to-tr from-[#E8FF5A] to-[#22D3EE] flex items-center justify-center font-bold text-black shadow-[0_0_20px_rgba(232,255,90,0.3)] group-hover:scale-105 transition-transform">
            <div className="w-4 h-4 bg-black rounded-sm rotate-45 group-hover:rotate-90 transition-transform duration-500" />
          </div>
          <span className="text-2xl font-black tracking-tighter text-white">CodeGuard<span className="text-[#E8FF5A]">AI</span></span>
        </div>
        <div className="hidden md:flex gap-10 text-sm font-semibold text-gray-400">
          <a href="#features" className="hover:text-white transition-colors cursor-pointer">Platform</a>
          <a href="#how-it-works" className="hover:text-white transition-colors cursor-pointer">Protocol</a>
          <a href="#auth" className="hover:text-[#E8FF5A] transition-colors cursor-pointer">Connect</a>
        </div>
        <a href="#auth" className="px-6 py-2.5 rounded-full bg-white/5 border border-white/10 hover:border-[#E8FF5A]/50 hover:bg-[#E8FF5A]/10 transition-all font-bold text-sm shadow-[0_0_15px_rgba(255,255,255,0.02)]">
          Launch Console
        </a>
      </nav>

      <main className="flex flex-col items-center">
        {/* Hero Section */}
        <section className="relative w-full max-w-7xl mx-auto px-6 pt-40 pb-20 flex flex-col items-center text-center justify-center min-h-screen">
           <div className="inline-flex items-center gap-3 px-4 py-1.5 rounded-full border border-white/10 bg-white/5 text-[#E8FF5A] text-xs font-bold uppercase tracking-[0.2em] mb-10 animate-slide-up" style={{ animationDelay: '0.1s' }}>
             <span className="w-2.5 h-2.5 rounded-full bg-[#E8FF5A] shadow-[0_0_10px_rgba(232,255,90,0.8)] animate-pulse-glow"></span>
             v2.0 Next-Gen Core Online
           </div>

           <h1 className="text-6xl md:text-[7rem] font-black tracking-tighter max-w-6xl leading-[1.05] mb-8 animate-slide-up" style={{ animationDelay: '0.2s' }}>
             UNBREAKABLE <br className="hidden md:block"/> 
             <span className="text-transparent bg-clip-text bg-gradient-to-r from-white via-[#E8FF5A] to-[#00F0FF]">SECURITY INTELLIGENCE</span>
           </h1>
           
           <p className="text-gray-400 text-xl md:text-2xl max-w-3xl font-medium leading-relaxed mb-12 animate-slide-up" style={{ animationDelay: '0.3s' }}>
             A decentralized AI matrix for code auditing. Isolate vulnerabilities, generate exact patches, and fortify your applications before they deploy.
           </p>
           
           <div className="flex flex-col sm:flex-row gap-6 items-center animate-slide-up" style={{ animationDelay: '0.4s' }}>
             <button
               type="button"
               onClick={() => handleHeroAction("initialize")}
               className="group relative px-10 py-5 bg-[#E8FF5A] text-black font-black uppercase tracking-wide rounded-2xl transition-all hover:scale-105 shadow-[0_0_40px_rgba(232,255,90,0.4)] overflow-hidden"
             >
               <span className="relative z-10 flex items-center gap-2">Initialize Scan <span className="text-xl leading-none group-hover:translate-x-1 transition-transform">→</span></span>
               <div className="absolute inset-0 bg-white/30 translate-y-[100%] group-hover:translate-y-0 transition-transform duration-300"></div>
             </button>
             <button
               type="button"
               onClick={() => handleHeroAction("explore")}
               className="px-10 py-5 bg-transparent border border-white/20 text-white font-bold uppercase tracking-wide rounded-2xl hover:bg-white/10 hover:border-white/40 transition-all backdrop-blur-md"
             >
               Explore Matrix
             </button>
           </div>
        </section>

        {/* Features Rolling Section */}
        <section id="features" className="w-full bg-[#050505] py-32 border-t border-white/5 relative overflow-hidden">
          <div className="absolute right-0 bottom-0 w-1/2 h-1/2 bg-[#00F0FF]/5 blur-[120px] rounded-full pointer-events-none"></div>
          
          <div className="max-w-7xl mx-auto px-6 grid md:grid-cols-3 gap-8 relative z-10">
             
             <div className="p-10 rounded-3xl glass-panel hover-glow group transition-all">
               <div className="w-14 h-14 rounded-2xl bg-[#E8FF5A]/10 text-[#E8FF5A] flex items-center justify-center mb-8 text-2xl font-black border border-[#E8FF5A]/20 group-hover:bg-[#E8FF5A] group-hover:text-black transition-colors">
                 01
               </div>
               <h3 className="text-2xl font-bold mb-4 text-white">Hybrid Engine</h3>
               <p className="text-gray-400 leading-relaxed font-medium">Multi-dimensional analysis combining lightweight deterministic regex with advanced LLM semantic verification mapping.</p>
             </div>

             <div className="p-10 rounded-3xl glass-panel hover-glow group transition-all md:translate-y-8">
               <div className="w-14 h-14 rounded-2xl bg-[#00F0FF]/10 text-[#00F0FF] flex items-center justify-center mb-8 text-2xl font-black border border-[#00F0FF]/20 group-hover:bg-[#00F0FF] group-hover:text-black transition-colors">
                 02
               </div>
               <h3 className="text-2xl font-bold mb-4 text-white">Instant Patch Matrix</h3>
               <p className="text-gray-400 leading-relaxed font-medium">Zero-click remediation. Auto-generate git patches ready to be piped directly into your codebase for frictionless merges.</p>
             </div>

             <div className="p-10 rounded-3xl glass-panel hover-glow group transition-all md:translate-y-16">
               <div className="w-14 h-14 rounded-2xl bg-purple-500/10 text-purple-400 flex items-center justify-center mb-8 text-2xl font-black border border-purple-500/20 group-hover:bg-purple-500 group-hover:text-black transition-colors">
                 03
               </div>
               <h3 className="text-2xl font-bold mb-4 text-white">Cryptographic Briefs</h3>
               <p className="text-gray-400 leading-relaxed font-medium">Executive-ready PDF audit trails cryptographically stamped, breaking down complex zero-days into actionable readable intel.</p>
             </div>

          </div>
        </section>

        <section id="how-it-works" className="w-full py-32 px-6 bg-[#030303] border-t border-b border-white/5 relative">
          <div className="absolute left-[-10%] top-[40%] w-[40%] h-[40%] bg-[#E8FF5A]/5 blur-[120px] rounded-full pointer-events-none"></div>

          <div className="max-w-6xl mx-auto relative z-10">
            <h2 className="text-4xl md:text-6xl font-black text-white mb-16 text-center">Execute Protocol</h2>
            <div className="grid gap-8 md:grid-cols-3 relative">
              <div className="absolute top-1/2 left-0 w-full h-0.5 bg-gradient-to-r from-transparent via-white/10 to-transparent -translate-y-1/2 hidden md:block z-0"></div>
              
              <div className="glass-panel rounded-3xl p-8 relative z-10 hover:-translate-y-2 transition-transform duration-500 border border-t-[#E8FF5A]/30">
                <span className="absolute -top-4 -left-4 w-12 h-12 bg-[#050505] border border-white/10 rounded-xl flex items-center justify-center text-[#E8FF5A] font-black shadow-[0_0_15px_rgba(232,255,90,0.2)]">I</span>
                <p className="text-xs tracking-[0.2em] font-bold text-[#E8FF5A] mb-4 mt-2">LINK DEVICE</p>
                <h3 className="text-2xl font-bold text-white mb-3">Establish Uplink</h3>
                <p className="text-gray-400 text-sm leading-relaxed">Sign in with secure credentials to establish an encrypted session token with the mainframe.</p>
              </div>

              <div className="glass-panel rounded-3xl p-8 relative z-10 hover:-translate-y-2 transition-transform duration-500 border border-t-[#00F0FF]/30 mt-0 md:mt-12">
                <span className="absolute -top-4 -left-4 w-12 h-12 bg-[#050505] border border-white/10 rounded-xl flex items-center justify-center text-[#00F0FF] font-black shadow-[0_0_15px_rgba(0,240,255,0.2)]">II</span>
                <p className="text-xs tracking-[0.2em] font-bold text-[#00F0FF] mb-4 mt-2">EXECUTE SCAN</p>
                <h3 className="text-2xl font-bold text-white mb-3">Deploy Sensors</h3>
                <p className="text-gray-400 text-sm leading-relaxed">Target a repository or local files. The AI swarm analyzes abstract syntax trees for deep vulnerabilities.</p>
              </div>

              <div className="glass-panel rounded-3xl p-8 relative z-10 hover:-translate-y-2 transition-transform duration-500 border border-t-purple-400/30 mt-0 md:mt-24">
                <span className="absolute -top-4 -left-4 w-12 h-12 bg-[#050505] border border-white/10 rounded-xl flex items-center justify-center text-purple-400 font-black shadow-[0_0_15px_rgba(168,85,247,0.2)]">III</span>
                <p className="text-xs tracking-[0.2em] font-bold text-purple-400 mb-4 mt-2">EXTRACT INTEL</p>
                <h3 className="text-2xl font-bold text-white mb-3">Download Briefs</h3>
                <p className="text-gray-400 text-sm leading-relaxed">Retrieve fully parsed, C-level read-ready PDF reports and raw code patches to merge immediately.</p>
              </div>
            </div>
          </div>
        </section>

        {/* Authentication Section */}
        <section id="auth" className="w-full py-32 relative flex justify-center items-center px-4 overflow-hidden min-h-[90vh]">
          {/* Decorative radar lines */}
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(232,255,90,0.05)_1px,transparent_1px)] bg-[size:40px_40px] opacity-30"></div>
          
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] border border-white/5 rounded-full animate-[spin_60s_linear_infinite]"></div>
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] border border-white/5 rounded-full animate-[spin_40s_linear_infinite_reverse]"></div>

          <div className="w-full max-w-md relative z-10 glass-panel p-10 md:p-14 rounded-[2.5rem] shadow-[0_0_80px_rgba(0,0,0,0.8)] border border-white/10">
            <div className="mb-10 text-center">
              <div className="w-16 h-16 mx-auto bg-[#111] border border-white/10 rounded-2xl flex items-center justify-center mb-6 shadow-inner">
                <div className="w-6 h-6 border-2 border-[#E8FF5A] rounded-md animate-pulse"></div>
              </div>
              <h2 className="text-3xl font-black tracking-tight text-white mb-2">{isLogin ? "System Link" : "Initialize Identity"}</h2>
              <p className="text-sm text-gray-400 font-medium">
                {isLogin ? "Authenticate to access terminal matrix" : "Create new encrypted identity"}
              </p>
            </div>

            <form onSubmit={handleSubmit} className="flex flex-col gap-5">
              <div className="relative group">
                <input
                  suppressHydrationWarning
                  type="text"
                  placeholder="Username"
                  className="w-full bg-[#0A0A0A] border border-white/10 rounded-2xl px-6 py-5 text-white focus:outline-none focus:border-[#E8FF5A]/50 focus:ring-1 focus:ring-[#E8FF5A]/30 transition-all font-mono text-sm placeholder:text-gray-600"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                />
              </div>
              <div className="relative group">
                <input
                  suppressHydrationWarning
                  type="password"
                  placeholder="Passphrase"
                  className="w-full bg-[#0A0A0A] border border-white/10 rounded-2xl px-6 py-5 text-white focus:outline-none focus:border-[#E8FF5A]/50 focus:ring-1 focus:ring-[#E8FF5A]/30 transition-all font-mono text-sm placeholder:text-gray-600"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>

              {!isLogin && (
                <div className="relative group">
                  <input
                    type="email"
                    placeholder="Email Address (Optional)"
                    className="w-full bg-[#0A0A0A] border border-white/10 rounded-2xl px-6 py-5 text-white focus:outline-none focus:border-[#E8FF5A]/50 focus:ring-1 focus:ring-[#E8FF5A]/30 transition-all font-mono text-sm placeholder:text-gray-600"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>
              )}
              
              {error && (
                <div className="p-4 rounded-xl border border-red-500/30 bg-red-500/10 text-red-400 text-sm font-medium text-center animate-slide-up">
                  {error}
                </div>
              )}

              <button
                suppressHydrationWarning
                type="submit"
                className="w-full bg-white text-black font-black uppercase tracking-wider rounded-2xl py-5 mt-4 hover:bg-[#E8FF5A] hover:shadow-[0_0_30px_rgba(232,255,90,0.5)] transition-all duration-300"
              >
                {isLogin ? "Establish Link" : "Generate Node"}
              </button>
            </form>

            <div className="mt-8 text-center text-sm font-medium text-gray-500">
              {isLogin ? "No identity sequence? " : "Already initialized? "}
              <button
                suppressHydrationWarning
                onClick={() => setIsLogin(!isLogin)}
                className="text-white hover:text-[#E8FF5A] transition-colors font-bold border-b border-transparent hover:border-[#E8FF5A] ml-1"
              >
                {isLogin ? "Install Credentials" : "Auth Link"}
              </button>
            </div>
          </div>
        </section>

        {/* Footer */}
        <footer className="w-full py-10 border-t border-white/5 bg-[#030303] flex justify-center items-center">
          <div className="text-center">
            <div className="w-8 h-8 rounded-xl bg-[#E8FF5A]/10 text-[#E8FF5A] flex items-center justify-center font-bold mx-auto mb-4 border border-[#E8FF5A]/20">
              CG
            </div>
            <p className="text-gray-500 text-xs font-mono font-medium">
              © {new Date().getFullYear()} CodeGuard AI Core. Secure the decentralized future.
            </p>
          </div>
        </footer>
      </main>
    </div>
  );
}
