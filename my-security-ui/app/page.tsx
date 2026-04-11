"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { saveAuthSession } from "./lib/auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function Home() {
  const router = useRouter();
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

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
    <div className="min-h-screen bg-[#050505] text-white selection:bg-[#E8FF5A] selection:text-black overflow-hidden relative">
      {/* Background Neon Elements */}
      <div className="absolute top-0 right-1/4 w-[600px] h-[600px] bg-[#E8FF5A]/10 rounded-full blur-[150px] -z-10 mix-blend-screen pointer-events-none animate-float"></div>
      <div className="absolute top-1/2 left-1/4 w-[500px] h-[500px] bg-[#00F0FF]/10 rounded-full blur-[120px] -z-10 mix-blend-screen pointer-events-none animate-float transition-all delay-700"></div>
      
      {/* Navigation */}
      <nav className="fixed w-full z-50 top-0 pt-6 px-10 flex justify-between items-center bg-gradient-to-b from-[#050505] to-transparent pb-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-[#E8FF5A] flex items-center justify-center font-bold text-black border-2 border-[#E8FF5A]/50">
            CG
          </div>
          <span className="text-xl font-bold tracking-tight text-white hover:text-[#E8FF5A] transition-colors">CodeGuard<span className="text-[#E8FF5A]">AI</span></span>
        </div>
        <div className="hidden md:flex gap-8 text-sm font-medium text-gray-400">
          <a href="#features" className="hover:text-white transition-colors cursor-pointer">Features</a>
          <a href="#how-it-works" className="hover:text-white transition-colors cursor-pointer">Protocol</a>
          <a href="#auth" className="hover:text-white transition-colors cursor-pointer">Launch App</a>
        </div>
        <a href="#auth" className="px-5 py-2 rounded-full border border-white/10 hover:border-[#E8FF5A]/50 hover:bg-[#E8FF5A]/10 transition-all font-semibold text-sm">
          Connect System
        </a>
      </nav>

      <main className="pt-32 flex flex-col items-center">
        {/* Hero Section */}
        <section className="relative w-full max-w-7xl mx-auto px-6 py-20 flex flex-col items-center text-center grid-bg min-h-[80vh] justify-center">
           <div className="absolute inset-0 bg-[url('https://transparenttextures.com/patterns/cubes.png')] opacity-5 mask-image-gradient"></div>
           
           <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[#E8FF5A]/30 bg-[#E8FF5A]/5 text-[#E8FF5A] text-xs font-semibold uppercase tracking-widest mb-8">
             <span className="w-2 h-2 rounded-full bg-[#E8FF5A] animate-pulse"></span>
             v2.0 Next-Gen Threat Intel Live
           </div>

           <h1 className="text-6xl md:text-8xl font-black tracking-tighter max-w-5xl leading-[1.1] mb-8">
             UNBREAKABLE <br /> 
             <span className="text-transparent bg-clip-text bg-gradient-to-r from-white via-[#E8FF5A] to-[#00F0FF]">SECURITY INTELLIGENCE</span>
           </h1>
           
           <p className="text-gray-400 text-lg md:text-2xl max-w-2xl font-light leading-relaxed mb-12">
             An AI-driven code analysis network powered by decentralized knowledge. Discover, isolate, and terminate vulnerabilities before they enter production.
           </p>
           
           <div className="flex gap-4 items-center">
             <a href="#auth" className="px-8 py-4 bg-[#E8FF5A] hover:bg-[#d4e84d] text-black font-bold rounded-full transition-transform hover:scale-105 shadow-[0_0_30px_rgba(232,255,90,0.3)]">
               Initialize Scan
             </a>
             <a href="#features" className="px-8 py-4 bg-white/5 hover:bg-white/10 border border-white/10 text-white font-bold rounded-full transition-all">
               Explore Engine
             </a>
           </div>
        </section>

        {/* Features Rolling Section */}
        <section id="features" className="w-full bg-[#030303] py-32 border-t border-b border-white/5 relative">
          <div className="max-w-7xl mx-auto px-6 grid md:grid-cols-3 gap-8 relative z-10">
             
             <div className="p-8 rounded-3xl glass-panel group hover:-translate-y-2 transition-transform duration-500">
               <div className="w-12 h-12 rounded-xl bg-[#E8FF5A]/10 text-[#E8FF5A] flex items-center justify-center mb-6 text-2xl font-black">
                 01
               </div>
               <h3 className="text-2xl font-bold mb-4 group-hover:text-[#E8FF5A] transition-colors">Hybrid Scan Protocol</h3>
               <p className="text-gray-400 leading-relaxed">Multi-dimensional analysis combining lightweight deterministic regex with advanced LLM semantic verification mapping.</p>
             </div>

             <div className="p-8 rounded-3xl glass-panel group hover:-translate-y-2 transition-transform duration-500 delay-100">
               <div className="w-12 h-12 rounded-xl bg-[#00F0FF]/10 text-[#00F0FF] flex items-center justify-center mb-6 text-2xl font-black">
                 02
               </div>
               <h3 className="text-2xl font-bold mb-4 group-hover:text-[#00F0FF] transition-colors">Instant Patch Export</h3>
               <p className="text-gray-400 leading-relaxed">Zero-click remediation. Auto-generate git patches ready to be piped directly into your codebase for frictionless merges.</p>
             </div>

             <div className="p-8 rounded-3xl glass-panel group hover:-translate-y-2 transition-transform duration-500 delay-200">
               <div className="w-12 h-12 rounded-xl bg-purple-500/10 text-purple-400 flex items-center justify-center mb-6 text-2xl font-black">
                 03
               </div>
               <h3 className="text-2xl font-bold mb-4 group-hover:text-purple-400 transition-colors">PDF Threat Briefs</h3>
               <p className="text-gray-400 leading-relaxed">Cryptographically stamped, executive-ready PDF audit trails that break down complex zero-days into readable intel.</p>
             </div>

          </div>
        </section>

        <section id="how-it-works" className="w-full py-24 px-6 bg-[#070707] border-b border-white/5">
          <div className="max-w-6xl mx-auto">
            <h2 className="text-3xl md:text-5xl font-black text-white mb-10 text-center">Protocol Flow</h2>
            <div className="grid gap-6 md:grid-cols-3">
              <div className="glass-panel rounded-2xl p-6">
                <p className="text-xs tracking-[0.2em] text-[#E8FF5A] mb-3">STEP 01</p>
                <h3 className="text-xl font-bold text-white mb-2">Authenticate</h3>
                <p className="text-gray-400 text-sm">Sign in and establish a secure session token before starting any analysis job.</p>
              </div>
              <div className="glass-panel rounded-2xl p-6">
                <p className="text-xs tracking-[0.2em] text-[#00F0FF] mb-3">STEP 02</p>
                <h3 className="text-xl font-bold text-white mb-2">Scan</h3>
                <p className="text-gray-400 text-sm">Launch repository analysis from the dashboard and inspect findings generated by the backend AI pipeline.</p>
              </div>
              <div className="glass-panel rounded-2xl p-6">
                <p className="text-xs tracking-[0.2em] text-purple-300 mb-3">STEP 03</p>
                <h3 className="text-xl font-bold text-white mb-2">Export</h3>
                <p className="text-gray-400 text-sm">Navigate to reports to download PDF evidence and patch files tied to each scan ID.</p>
              </div>
            </div>
          </div>
        </section>

        {/* Authentication Section */}
        <section id="auth" className="w-full py-32 relative flex justify-center items-center overflow-hidden min-h-[90vh]">
          {/* Decorative radar lines */}
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(232,255,90,0.05)_1px,transparent_1px)] bg-[size:40px_40px] opacity-20"></div>

          <div className="w-full max-w-sm relative z-10 glass-panel p-10 rounded-3xl shadow-[0_0_50px_rgba(0,0,0,0.5)]">
            <div className="mb-10 text-center">
              <h2 className="text-3xl font-black tracking-tight">{isLogin ? "System Login" : "Initialize Auth"}</h2>
              <p className="text-sm text-gray-400 mt-2">
                {isLogin ? "Authenticate to access terminal" : "Create new secure identity"}
              </p>
            </div>

            <form onSubmit={handleSubmit} className="flex flex-col gap-5">
              <div className="relative">
                <input
                  suppressHydrationWarning
                  type="text"
                  placeholder="Username"
                  className="w-full bg-[#111] border border-white/10 rounded-xl px-5 py-4 text-white focus:outline-none focus:border-[#E8FF5A]/50 focus:ring-1 focus:ring-[#E8FF5A]/20 transition-all font-mono text-sm"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                />
              </div>
              <div className="relative">
                <input
                  suppressHydrationWarning
                  type="password"
                  placeholder="Passphrase"
                  className="w-full bg-[#111] border border-white/10 rounded-xl px-5 py-4 text-white focus:outline-none focus:border-[#E8FF5A]/50 focus:ring-1 focus:ring-[#E8FF5A]/20 transition-all font-mono text-sm"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>

              {!isLogin && (
                <div className="relative">
                  <input
                    type="email"
                    placeholder="Email (optional)"
                    className="w-full bg-[#111] border border-white/10 rounded-xl px-5 py-4 text-white focus:outline-none focus:border-[#E8FF5A]/50 focus:ring-1 focus:ring-[#E8FF5A]/20 transition-all font-mono text-sm"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>
              )}
              
              {error && (
                <div className="mx-auto block p-3 rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 text-xs font-mono text-center max-w-[90%] break-words">
                  {error}
                </div>
              )}

              <button
                suppressHydrationWarning
                type="submit"
                className="w-full bg-white text-black font-bold rounded-xl py-4 mt-2 hover:bg-[#E8FF5A] hover:shadow-[0_0_20px_rgba(232,255,90,0.4)] transition-all duration-300"
              >
                {isLogin ? "A C C E S S" : "E N R O L L"}
              </button>
            </form>

            <div className="mt-8 text-center text-sm font-medium text-gray-500">
              {isLogin ? "No identity sequence? " : "Already initialized? "}
              <button
                suppressHydrationWarning
                onClick={() => setIsLogin(!isLogin)}
                className="text-white hover:text-[#E8FF5A] transition-colors font-bold border-b border-transparent hover:border-[#E8FF5A]"
              >
                {isLogin ? "Register Node" : "Access Node"}
              </button>
            </div>
          </div>
        </section>

        {/* Footer */}
        <footer className="w-full py-8 border-t border-white/5 text-center text-gray-600 text-xs font-mono">
          © {new Date().getFullYear()} CodeGuard AI. Secure the decentralized future.
        </footer>
      </main>
    </div>
  );
}
