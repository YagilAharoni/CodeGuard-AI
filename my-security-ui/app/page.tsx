"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";

export default function LandingPage() {
  const router = useRouter();
  const [isLogin, setIsLogin] = useState(true);
  
  // Form State
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    try {
      const endpoint = isLogin ? "/api/login" : "/api/register";
      const payload = isLogin 
        ? { login: email || username, password } 
        : { username, email, password };

      const res = await fetch(`http://localhost:8000${endpoint}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || "Authentication failed");
      }

      if (!isLogin) {
        // Switch to login mode after successful registration
        setIsLogin(true);
        setError("Registration successful! Please login.");
        setEmail(email || username);
      } else {
        // Store user info in localStorage for use across pages
        if (data.user) {
          localStorage.setItem('codeguard_user', JSON.stringify(data.user));
        }
        // Redirect to dashboard on successful login
        router.push("/dashboard");
      }
    } catch (err: any) {
      setError(err.message || "An error occurred");
    } finally {
      setIsLoading(false);
    }
  };

  if (!mounted) {
    return (
      <div className="relative min-h-screen bg-[#0A0C10] overflow-hidden flex items-center justify-center">
        {/* Simple background shell for initial SSR render */}
        <div className="absolute inset-0 bg-[#0A0C10]" />
        <div className="relative z-10 w-full max-w-6xl mx-auto px-6 py-12 flex flex-col items-center gap-8 animate-pulse">
           <div className="w-48 h-12 bg-white/5 rounded-full" />
           <div className="w-96 h-24 bg-white/5 rounded-2xl" />
        </div>
      </div>
    );
  }

  return (
    <div className="relative min-h-screen bg-[#0A0C10] overflow-hidden font-sans text-white flex items-center justify-center selection:bg-cyan-500/30">
      
      {/* Background Cybery Elements */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] rounded-full bg-[#8A2BE2]/15 blur-[130px] pointer-events-none transition-transform duration-1000 animate-pulse-slow" />
      <div className="absolute top-[20%] right-[-10%] w-[40%] h-[60%] rounded-full bg-[#00F0FF]/15 blur-[150px] pointer-events-none transition-transform duration-1000" />
      <div className="absolute bottom-[-20%] left-[20%] w-[60%] h-[40%] rounded-full bg-[#8A2BE2]/10 blur-[120px] pointer-events-none" />
      
      {/* Grid Overlay */}
      <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI0MCIgaGVpZ2h0PSI0MCI+PGRlZnM+PHBhdHRlcm4gaWQ9ImciIHdpZHRoPSI0MCIgaGVpZ2h0PSI0MCIgcGF0dGVyblVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+PHBhdGggZD0iTTAgNDBoNDBWMEgweiIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJyZ2JhKDI1NSwyNTUsMjU1LDAuMDMpIiBzdHJva2Utd2lkdGg9IjEiLz48L3BhdHRlcm4+PC9kZWZzPjxyZWN0IHdpZHRoPSIxMDAlIiBoZWlnaHQ9IjEwMCUiIGZpbGw9InVybCgjZykiLz48L3N2Zz4=')] pointer-events-none opacity-50" />

      {/* Floating Network Lines */}
      <div className="absolute inset-0 pointer-events-none opacity-25">
         <svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
             <path d="M -100 200 Q 200 400 500 150 T 1200 300" stroke="url(#cyan-grad)" strokeWidth="1" fill="none" />
             <path d="M -100 700 Q 400 500 700 800 T 1300 500" stroke="url(#purple-grad)" strokeWidth="1" fill="none" />
             <defs>
               <linearGradient id="cyan-grad" x1="0%" y1="0%" x2="100%" y2="0%">
                 <stop offset="0%" stopColor="#0A0C10" stopOpacity="0" />
                 <stop offset="50%" stopColor="#00F0FF" stopOpacity="1" />
                 <stop offset="100%" stopColor="#0A0C10" stopOpacity="0" />
               </linearGradient>
               <linearGradient id="purple-grad" x1="0%" y1="0%" x2="100%" y2="0%">
                 <stop offset="0%" stopColor="#0A0C10" stopOpacity="0" />
                 <stop offset="50%" stopColor="#8A2BE2" stopOpacity="1" />
                 <stop offset="100%" stopColor="#0A0C10" stopOpacity="0" />
               </linearGradient>
             </defs>
         </svg>
      </div>

      <div className="relative z-10 w-full max-w-6xl mx-auto px-6 py-12 flex flex-col lg:flex-row items-center gap-16">
        
        {/* Left Side: Copy & Branding */}
        <div className="flex-1 text-left space-y-8 animate-fade-in-up">
          <div className="inline-flex items-center gap-3 px-4 py-2 rounded-full bg-white/5 border border-white/10 backdrop-blur-md shadow-[0_0_15px_rgba(0,240,255,0.1)]">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#00F0FF]"></span>
            <span className="text-sm font-semibold tracking-wider text-cyan-100 uppercase">Enterprise Grade Security</span>
          </div>
          
          <h1 className="text-6xl md:text-7xl font-black tracking-tight leading-[1.1]">
            One-click for <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-400 to-purple-500 drop-shadow-[0_0_30px_rgba(138,43,226,0.3)]">
              Asset Defense
            </span>
          </h1>
          
          <p className="text-lg text-gray-400 max-w-xl leading-relaxed">
            Dive into zero-day prevention where innovative blockchain technology meets robust AI security expertise. Secure your application instantly and autonomously.
          </p>

          <div className="flex items-center gap-8 pt-4">
             <div className="flex items-center gap-3 text-cyan-200/90 text-sm font-semibold tracking-wide">
                <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
                  <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                </div>
                Real-time Audit
             </div>
             <div className="flex items-center gap-3 text-purple-200/90 text-sm font-semibold tracking-wide">
                <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20">
                  <svg className="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                </div>
                Military Grade
             </div>
          </div>
        </div>

        {/* Right Side: Auth Form */}
        <div className="w-full max-w-md animate-fade-in-up" style={{ animationDelay: '0.2s' }}>
          <div className="relative p-8 rounded-[2rem] bg-[#11131A]/70 backdrop-blur-2xl border border-white/5 shadow-2xl overflow-hidden before:absolute before:inset-0 before:bg-gradient-to-br before:from-cyan-500/10 before:to-purple-600/10 before:pointer-events-none hover:border-cyan-500/30 transition-colors duration-500">
            
            <div className="flex justify-between items-center mb-8 border-b border-white/10 pb-4 relative z-10">
              <button 
                onClick={() => {setIsLogin(true); setError("");}}
                className={`text-lg font-bold transition-all duration-300 ${isLogin ? 'text-cyan-400 drop-shadow-[0_0_10px_rgba(0,240,255,0.5)]' : 'text-gray-500 hover:text-white'}`}
              >
                Sign In
              </button>
              <div className="w-px h-6 bg-white/10"></div>
              <button 
                onClick={() => {setIsLogin(false); setError("");}}
                className={`text-lg font-bold transition-all duration-300 ${!isLogin ? 'text-purple-400 drop-shadow-[0_0_10px_rgba(138,43,226,0.5)]' : 'text-gray-500 hover:text-white'}`}
              >
                Create Account
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-6 relative z-10">
              
              {!isLogin && (
                <div className="space-y-1.5 group">
                  <label className="text-xs font-bold uppercase tracking-wider text-gray-400 ml-1 group-focus-within:text-cyan-400 transition-colors">Username</label>
                  <input 
                    type="text" 
                    required={!isLogin}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full bg-[#0A0C10]/80 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 transition-all font-mono text-sm"
                    placeholder="neo_1337"
                  />
                </div>
              )}

              <div className="space-y-1.5 group">
                <label className="text-xs font-bold uppercase tracking-wider text-gray-400 ml-1 group-focus-within:text-cyan-400 transition-colors">
                  {isLogin ? "Email or Username" : "Email Address"}
                </label>
                <input 
                  type="text" 
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-[#0A0C10]/80 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 transition-all font-mono text-sm"
                  placeholder={isLogin ? "neo / neo@matrix.com" : "neo@matrix.com"}
                />
              </div>

              <div className="space-y-1.5 group">
                <label className="text-xs font-bold uppercase tracking-wider text-gray-400 ml-1 group-focus-within:text-purple-400 transition-colors">Password</label>
                <input 
                  type="password" 
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-[#0A0C10]/80 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/50 transition-all font-mono text-sm"
                  placeholder="••••••••"
                />
              </div>

              {error && (
                <div className={`p-4 rounded-xl text-sm font-semibold flex items-center gap-2 ${error.includes('successful') ? 'bg-green-500/10 text-green-400 border border-green-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                  {error.includes('successful') ? (
                    <svg className="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path></svg>
                  ) : (
                    <svg className="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                  )}
                  {error}
                </div>
              )}

              <button 
                type="submit"
                disabled={isLoading}
                className="relative w-full overflow-hidden group rounded-xl mt-6 border border-white/10"
              >
                <div className="absolute inset-0 w-full h-full bg-gradient-to-r from-cyan-600/80 to-purple-600/80 transition-transform duration-500 group-hover:scale-105"></div>
                <div className="absolute inset-0 w-full h-full bg-gradient-to-r from-cyan-500 to-purple-500 opacity-0 group-hover:opacity-100 transition-opacity duration-500 blur-md"></div>
                <div className="relative w-full px-6 py-4 flex items-center justify-center font-bold text-white tracking-wider uppercase text-sm">
                  {isLoading ? (
                    <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                  ) : (
                    isLogin ? "Authenticate" : "Initialize Identity"
                  )}
                </div>
              </button>

              <div className="mt-6 flex justify-between items-center text-[10px] sm:text-xs text-gray-500">
                <button 
                  type="button" 
                  onClick={() => setError("Password reset protocol initiated. Please check your secure comms or contact administrator.")}
                  className="hover:text-cyan-400 transition-colors uppercase tracking-widest font-mono"
                >
                  [ Forgot Password? ]
                </button>
                <button 
                  type="button"
                  onClick={() => {
                    setIsLogin(!isLogin);
                    setError("");
                  }}
                  className="text-cyan-400 hover:text-cyan-300 font-bold uppercase tracking-widest font-mono"
                >
                  {isLogin ? ">> Register Operator" : ">> Back to Login"}
                </button>
              </div>
            </form>
          </div>
        </div>

      </div>
      
      <style dangerouslySetInnerHTML={{__html: `
        @keyframes fadeInUp {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .animate-fade-in-up {
          animation: fadeInUp 0.8s ease-out forwards;
        }
        @keyframes pulse-slow {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.8; transform: scale(1.05); }
        }
        .animate-pulse-slow {
          animation: pulse-slow 8s infinite ease-in-out;
        }
      `}} />
    </div>
  );
}
