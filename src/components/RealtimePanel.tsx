import React, { useEffect, useRef, useState } from "react";
import type { SecurityEvent } from "../types/event";
import { Radio } from "lucide-react";
import { apiUrl } from "../lib/api.ts";

export function RealtimePanel({
  events,
  onEventMessage,
  onEventAnalyzed,
  onBlockedIpUpdated,
}: {
  events: SecurityEvent[];
  onEventMessage: (ev: SecurityEvent) => void;
  onEventAnalyzed: (ev: SecurityEvent) => void;
  onBlockedIpUpdated?: () => void;
}) {
  const [connected, setConnected] = useState(false);
  const [feed, setFeed] = useState<string[]>([]);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const es = new EventSource(apiUrl("/api/stream"));
    esRef.current = es;
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data) as { type: string; data?: SecurityEvent & Record<string, unknown> };
        if (msg.type === "event_created" && msg.data) {
          onEventMessage(msg.data as SecurityEvent);
          setFeed((f) => [
            `[+] Event #${(msg.data as SecurityEvent).id} ${(msg.data as SecurityEvent).description.slice(0, 60)}...`,
            ...f.slice(0, 49),
          ]);
        }
        if (msg.type === "event_analyzed" && msg.data) {
          onEventAnalyzed(msg.data as SecurityEvent);
          setFeed((f) => [
            `[AI] #${(msg.data as SecurityEvent).id} → ${(msg.data as SecurityEvent).classification} (${Math.round(((msg.data as SecurityEvent).confidence ?? 0) * 100)}%)`,
            ...f.slice(0, 49),
          ]);
        }
        if (msg.type === "blocked_ip_updated" && msg.data) {
          onBlockedIpUpdated?.();
          const block = msg.data as { ip?: string; reason?: string };
          setFeed((f) => [
            `[block] ${block.ip ?? "IP"} — ${(block.reason ?? "blocked").slice(0, 72)}`,
            ...f.slice(0, 49),
          ]);
        }
        if (msg.type === "replay_started" || msg.type === "replay_complete" || msg.type === "suspicious_login") {
          setFeed((f) => [`[stream] ${msg.type}`, ...f.slice(0, 49)]);
        }
      } catch {
        /* ignore */
      }
    };
    return () => {
      es.close();
      esRef.current = null;
    };
  }, [onEventMessage, onEventAnalyzed, onBlockedIpUpdated]);

  return (
    <div className="bg-white border border-slate-200 rounded-2xl p-4 h-full flex flex-col min-h-[200px]">
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
          <Radio className={`w-4 h-4 ${connected ? "text-emerald-700 animate-pulse" : "text-slate-500"}`} />
          Live stream
        </h4>
        <span className="text-[10px] text-slate-500">{connected ? "SSE connected" : "connecting…"}</span>
      </div>
      <p className="text-[10px] text-slate-500 mb-2">Latest: {events[0]?.description?.slice(0, 80) ?? "—"}</p>
      <div className="flex-1 overflow-y-auto font-mono text-[10px] text-slate-600 space-y-1 max-h-[180px]">
        {feed.length === 0 ? <span className="text-slate-400">Waiting for events…</span> : feed.map((l, i) => <div key={i}>{l}</div>)}
      </div>
    </div>
  );
}
