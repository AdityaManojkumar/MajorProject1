import React, { useState } from "react";
import { KeyRound } from "lucide-react";

export function LoginMonitor({ onLoginAttempt }: { onLoginAttempt: () => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [lastMsg, setLastMsg] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = (await res.json()) as { success: boolean; message: string };
    setLastMsg(`${data.success ? "OK" : "FAIL"}: ${data.message}`);
    onLoginAttempt();
  };

  return (
    <div className="bg-zinc-900/40 border border-white/5 rounded-2xl p-6">
      <h3 className="text-lg font-bold text-white mb-2 flex items-center gap-2">
        <KeyRound className="w-5 h-5 text-amber-400" />
        Login monitor (demo)
      </h3>
      <p className="text-xs text-zinc-500 mb-4">
        Each attempt is logged with IP, timestamp, success/failure, and streamed live. Demo credentials:{" "}
        <code className="text-emerald-400">admin / admin123</code>
      </p>
      <form onSubmit={submit} className="space-y-3">
        <input
          className="w-full px-3 py-2 rounded-lg bg-black/40 border border-white/10 text-sm text-white"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <input
          type="password"
          className="w-full px-3 py-2 rounded-lg bg-black/40 border border-white/10 text-sm text-white"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <button
          type="submit"
          className="w-full py-2 bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 text-sm font-bold rounded-lg border border-amber-500/30"
        >
          Attempt login
        </button>
      </form>
      {lastMsg && <p className="mt-3 text-xs text-zinc-400">{lastMsg}</p>}
    </div>
  );
}
