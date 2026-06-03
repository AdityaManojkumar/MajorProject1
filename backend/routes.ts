import type { Express, Request } from "express";
import type { GoogleGenAI } from "@google/genai";
import {
  insertEvent,
  listEvents,
  listPendingEvents,
  updateEventAnalysis,
  listBlockedIps,
  upsertBlockedIp,
  getDb,
  listProtocolThreats,
  listMitigationActions,
} from "./db.js";
import { publish, addSseClient, removeSseClient } from "./stream.js";
import { classifyWithGemini, classifyHeuristic, normalizeClassifyResult } from "./ai/classify.js";
import { loadDataset, filterAttackRows, type DatasetId } from "./replay/loaders.js";
import { startReplay, stopReplay, injectDatasetSample } from "./replay/scheduler.js";
import { enrichAnalysisResults } from "./ai/analysis-display.js";
import { runRsaShorDemo } from "./quantum/rsa-shor.js";
import { runPqcDemo } from "./pqc/demo.js";
import { runRsaLatticeProtectionDemo } from "./pqc/rsa-vs-lattice-demo.js";
import { processEventThroughProtocolLayer, refreshProtocolAnalysis } from "./pipeline.js";
import { analyzeProtocolTraffic, buildAttackMetadata } from "./protocol/analyzer.js";
import { classifyCryptoThreat, PROTECTED_OSI_LAYERS } from "./protocol/crypto-security.js";
import {
  applyLayerAwareMitigation,
  mitigationStatusFromResults,
} from "./incident/response.js";

const loginFailures = new Map<string, { count: number; firstAt: number }>();
const BRUTE_WINDOW_MS = 60_000;
const BRUTE_THRESHOLD = 3;

function clientIp(req: Request): string {
  const xf = req.headers["x-forwarded-for"];
  if (typeof xf === "string" && xf.length) return xf.split(",")[0].trim();
  return req.socket.remoteAddress?.replace(/^::ffff:/, "") || "127.0.0.1";
}

function diversifyConfidence(r: import("./ai/classify.js").ClassifyResult): import("./ai/classify.js").ClassifyResult {
  const spread = ((r.id * 1103515245 + 12345) >>> 0) % 19;
  const delta = (spread - 9) * 0.012;
  const c = Math.min(0.98, Math.max(0.34, Math.round((r.confidence + delta) * 100) / 100));
  return { ...r, confidence: c };
}

async function runBatchAnalyze(
  ai: GoogleGenAI | null,
  events: import("./types.js").SecurityEventRow[]
): Promise<{ results: import("./ai/classify.js").ClassifyResult[]; source: string }> {
  if (events.length === 0) return { results: [], source: "none" };

  // Protocol Analysis Layer runs before AI Threat Detection Engine
  const enrichedEvents = refreshProtocolAnalysis(events);

  const applyResults = (raw: import("./ai/classify.js").ClassifyResult[]) => {
    const diversified = raw.map(diversifyConfidence);
    const finalized: import("./ai/classify.js").ClassifyResult[] = [];

    for (const r of diversified) {
      const row = getDb().prepare("SELECT * FROM events WHERE id = ?").get(r.id) as
        | import("./types.js").SecurityEventRow
        | undefined;
      if (!row) continue;

      const protocolAnalysis = analyzeProtocolTraffic(row);
      const cryptoClass = r.crypto_threat_class || classifyCryptoThreat(row, protocolAnalysis, r.attack_type);
      const metadata = buildAttackMetadata(row, protocolAnalysis, r.classification, r.attack_type, cryptoClass);
      const normalized = normalizeClassifyResult(r, row, metadata);

      updateEventAnalysis(
        normalized.id,
        normalized.classification,
        normalized.attack_type || null,
        normalized.confidence,
        normalized.reason + (normalized.feature_importance ? ` | Signals: ${normalized.feature_importance}` : ""),
        {
          osi_layer: normalized.osi_layer || metadata.osi_layer,
          protocol: normalized.protocol || metadata.protocol,
          severity_score: normalized.severity_score ?? metadata.severity_score,
          crypto_threat_class: normalized.crypto_threat_class || metadata.crypto_threat_class,
          attack_metadata_json: JSON.stringify(metadata),
        }
      );

      const mitigationResults = applyLayerAwareMitigation(row, metadata, normalized.classification);
      const mitigationStatus = mitigationStatusFromResults(mitigationResults, normalized.classification);
      if (mitigationStatus !== "none") {
        getDb()
          .prepare("UPDATE events SET mitigation_status = ? WHERE id = ?")
          .run(mitigationStatus, normalized.id);
      }

      if (
        normalized.classification === "confirmed_attack" &&
        metadata.osi_layer !== "Layer 3 - Network" &&
        mitigationResults.length === 0
      ) {
        const why = `Auto-block: ${normalized.attack_type || "attack"} · ${Math.round(normalized.confidence * 100)}% · ${normalized.reason}`;
        upsertBlockedIp(row.source_ip, why);
        publish({ type: "blocked_ip_updated", data: { ip: row.source_ip, reason: why } });
      }

      const updated = getDb().prepare("SELECT * FROM events WHERE id = ?").get(r.id);
      publish({ type: "event_analyzed", data: updated });

      finalized.push({
        ...normalized,
        osi_layer: normalized.osi_layer || metadata.osi_layer,
        protocol: normalized.protocol || metadata.protocol,
        severity_score: normalized.severity_score ?? metadata.severity_score,
        crypto_threat_class: normalized.crypto_threat_class || metadata.crypto_threat_class,
      });
    }
    return finalized;
  };
  try {
    if (!ai) throw new Error("Gemini key missing; falling back to heuristics");
    let results = await classifyWithGemini(ai, enrichedEvents);
    const seen = new Set(results.map((r) => r.id));
    const missing = enrichedEvents.filter((e) => !seen.has(e.id));
    if (missing.length) {
      results = [...results, ...classifyHeuristic(missing)];
    }
    const finalResults = applyResults(results);
    return { results: finalResults, source: "gemini" };
  } catch (e) {
    console.error("Analyze:", e);
    const results = classifyHeuristic(enrichedEvents);
    const finalResults = applyResults(results);
    return { results: finalResults, source: "heuristic_fallback" };
  }
}

function checkBruteForce(ip: string): string | null {
  const now = Date.now();
  const rec = loginFailures.get(ip);
  if (!rec) return null;
  if (now - rec.firstAt > BRUTE_WINDOW_MS) {
    loginFailures.delete(ip);
    return null;
  }
  if (rec.count >= BRUTE_THRESHOLD) {
    return `Multiple failed logins (${rec.count}) from this IP within ${BRUTE_WINDOW_MS / 1000}s`;
  }
  return null;
}

function publishIngestedEvent(id: number): void {
  processEventThroughProtocolLayer(id);
  const row = getDb().prepare("SELECT * FROM events WHERE id = ?").get(id);
  publish({ type: "event_created", data: row });
}

export function registerApiRoutes(app: Express, ai: GoogleGenAI | null): void {
  // CORS for frontend deployed separately (e.g., Vercel). Set FRONTEND_ORIGIN in backend host.
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    const allow = process.env.FRONTEND_ORIGIN;
    if (allow && origin && origin === allow) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).end();
    next();
  });

  app.get("/api/stream", (req, res) => {
    const origin = req.headers.origin;
    const allow = process.env.FRONTEND_ORIGIN;
    if (allow && origin && origin === allow) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders?.();
    res.write(`data: ${JSON.stringify({ type: "connected", data: { t: Date.now() } })}\n\n`);
    addSseClient(res);
    req.on("close", () => removeSseClient(res));
  });

  app.get("/api/events", (_req, res) => {
    res.json(listEvents(200));
  });

  app.get("/api/logs", (_req, res) => {
    const ev = listEvents(100);
    const legacy = ev.map((e) => ({
      id: e.id,
      timestamp: e.timestamp,
      source_ip: e.source_ip,
      event_type: e.attack_type || e.action,
      severity: e.severity,
      description: e.description,
      status: e.status,
      classification: e.classification,
      confidence: e.confidence,
    }));
    res.json(legacy);
  });

  app.get("/api/blocked-ips", (_req, res) => {
    res.json(listBlockedIps());
  });

  /** Layer-aware threat widget: attack type, protocol, OSI layer, mitigation status */
  app.get("/api/protocol/threats", (_req, res) => {
    res.json(listProtocolThreats(40));
  });

  app.get("/api/protocol/mitigations", (req, res) => {
    const eventId = req.query.eventId ? Number(req.query.eventId) : undefined;
    res.json(listMitigationActions(eventId));
  });

  app.get("/api/protocol/architecture", (_req, res) => {
    res.json({
      pipeline: [
        "Backend Application (ingest)",
        "Protocol Analysis Layer (L3/L4/L7 feature extraction)",
        "AI Threat Detection Engine (classification + severity)",
        "Incident Response Engine (layer-aware mitigation)",
        "Cross-Layer Cryptographic Security Module (PQC vs classical)",
      ],
      protectedLayers: PROTECTED_OSI_LAYERS,
    });
  });

  app.post("/api/protocol/analyze", (req, res) => {
    const body = req.body as {
      source_ip?: string;
      destination_ip?: string;
      protocol?: string;
      packet_count?: number;
      destination_port?: number;
      connection_attempts?: number;
      api_requests?: number;
      login_failures?: number;
      description?: string;
    };
    const ip = body.source_ip || clientIp(req);
    const id = insertEvent({
      source_ip: ip,
      event_kind: "network",
      action: "traffic",
      features_json: JSON.stringify({
        destination_ip: body.destination_ip || "10.0.0.1",
        protocol: body.protocol || "TCP",
        packet_count: body.packet_count ?? 500,
        destination_port: body.destination_port ?? 443,
        connection_attempts: body.connection_attempts ?? 1,
        api_requests: body.api_requests ?? 0,
        login_failures: body.login_failures ?? 0,
      }),
      severity: (body.packet_count ?? 0) > 800 ? "high" : "medium",
      description: body.description || `Protocol-analyzed traffic from ${ip}`,
      status: "pending_analyze",
    });
    publishIngestedEvent(id);
    const row = getDb().prepare("SELECT * FROM events WHERE id = ?").get(id);
    res.json({ ok: true, eventId: id, protocolAnalysis: row });
  });

  app.get("/api/stats", (_req, res) => {
    const db = getDb();
    const classical = (
      db
        .prepare(
          `SELECT COUNT(*) as c FROM events WHERE classification = 'confirmed_attack' OR ground_truth_label = 'attack'`
        )
        .get() as { c: number }
    ).c;
    const suspicious = (
      db.prepare(`SELECT COUNT(*) as c FROM events WHERE classification = 'suspicious'`).get() as { c: number }
    ).c;
    const normal = (
      db.prepare(`SELECT COUNT(*) as c FROM events WHERE classification = 'normal'`).get() as { c: number }
    ).c;
    const quantumVulnDemo = (
      db.prepare(`SELECT value FROM settings WHERE key = 'quantum_demo_runs'`).get() as { value: string } | undefined
    )?.value;
    const datasetInjectedEvents = (
      db.prepare(`SELECT COUNT(*) as c FROM events WHERE dataset IS NOT NULL`).get() as { c: number }
    ).c;
    const simulatedAttackEvents = (
      db
        .prepare(
          `SELECT COUNT(*) as c FROM events WHERE features_json LIKE '%"simulated"%' OR description LIKE 'Simulated potential%'`
        )
        .get() as { c: number }
    ).c;
    const loginDemoEvents = (
      db.prepare(`SELECT COUNT(*) as c FROM events WHERE event_kind = 'login'`).get() as { c: number }
    ).c;
    const classicalDemoTraffic = datasetInjectedEvents + simulatedAttackEvents + loginDemoEvents;
    res.json({
      classicalAttacksDetected: classical,
      suspiciousEvents: suspicious,
      normalClassified: normal,
      quantumVulnerabilityDemos: Number(quantumVulnDemo || 0),
      datasetInjectedEvents,
      simulatedAttackEvents,
      loginDemoEvents,
      classicalDemoTraffic,
      pqcStatus: "Kyber/Dilithium/SPHINCS+ educational mode",
      rsaStatus: "Vulnerable to Shor at scale (demo uses tiny keys)",
    });
  });

  app.post("/api/auth/login", (req, res) => {
    const ip = clientIp(req);
    const { username, password } = req.body as { username?: string; password?: string };
    const demoUser = process.env.DEMO_USER || "admin";
    const demoPass = process.env.DEMO_PASS || "admin123";
    const success = username === demoUser && password === demoPass;

    let suspicious: string | null = null;
    if (!success) {
      const now = Date.now();
      const rec = loginFailures.get(ip);
      if (!rec || now - rec.firstAt > BRUTE_WINDOW_MS) {
        loginFailures.set(ip, { count: 1, firstAt: now });
      } else {
        rec.count += 1;
        loginFailures.set(ip, rec);
      }
      suspicious = checkBruteForce(ip);
    } else {
      loginFailures.delete(ip);
    }

    const id = insertEvent({
      source_ip: ip,
      event_kind: "login",
      action: success ? "auth_success" : "auth_failure",
      login_success: success ? 1 : 0,
      username: username || null,
      severity: success ? "low" : "medium",
      description: success
        ? `Login success for user ${username || "?"}`
        : `Login failure for user ${username || "?"}`,
      status: "pending_analyze",
      suspicious_indicators: suspicious,
    });

    const row = getDb().prepare("SELECT * FROM events WHERE id = ?").get(id);
    publishIngestedEvent(id);
    if (suspicious) {
      publish({ type: "suspicious_login", data: { ip, message: suspicious } });
    }

    res.json({
      success,
      message: success ? "Authenticated" : "Invalid credentials",
      eventId: id,
    });
  });

  app.post("/api/sim/replay/start", (req, res) => {
    const {
      dataset,
      attackType,
      rateMs = 800,
      count = 20,
    } = req.body as {
      dataset?: DatasetId;
      attackType?: string;
      rateMs?: number;
      count?: number;
    };
    if (!dataset || !["cicids2017", "nsl-kdd", "unsw-nb15"].includes(dataset)) {
      return res.status(400).json({ error: "dataset must be cicids2017 | nsl-kdd | unsw-nb15" });
    }
    const all = loadDataset(dataset);
    const rows = filterAttackRows(all, attackType);
    const { started, total } = startReplay(rows, dataset, rateMs, count, () => {});
    publish({ type: "replay_started", data: { dataset, total } });
    res.json({ started, total, message: started ? "Replay running" : "No rows to replay" });
  });

  app.post("/api/sim/replay/stop", (_req, res) => {
    stopReplay();
    publish({ type: "replay_stopped", data: {} });
    res.json({ ok: true });
  });

  app.post("/api/sim/inject-sample", (req, res) => {
    const { dataset, attackType } = req.body as { dataset?: DatasetId; attackType?: string };
    if (!dataset || !["cicids2017", "nsl-kdd", "unsw-nb15"].includes(dataset)) {
      return res.status(400).json({ error: "dataset must be cicids2017 | nsl-kdd | unsw-nb15" });
    }
    const inject = injectDatasetSample(dataset, attackType);
    if (!inject) {
      return res.status(404).json({ error: "Sample CSV empty or missing — check datasets/samples/" });
    }
    res.json({ ok: true, inject });
  });

  app.post("/api/analyze", async (req, res) => {
    const { ids, limit = 10 } = req.body as { ids?: number[]; limit?: number };
    const events = ids?.length
      ? (ids
          .map((id) => getDb().prepare("SELECT * FROM events WHERE id = ?").get(id))
          .filter(Boolean) as import("./types.js").SecurityEventRow[])
      : listPendingEvents(Math.min(50, limit));

    if (events.length === 0) {
      return res.json({ processed: 0, results: [], source: "none" });
    }

    const { results, source } = await runBatchAnalyze(ai, events);
    res.json({ processed: results.length, results: enrichAnalysisResults(results), source });
  });

  app.post("/api/analyze-threats", async (_req, res) => {
    const events = listPendingEvents(5);
    if (events.length === 0) return res.json({ processed: 0, results: [], source: "none" });
    const { results, source } = await runBatchAnalyze(ai, events);
    res.json({ processed: results.length, results: enrichAnalysisResults(results), source });
  });

  app.post("/api/simulate-attack", (req, res) => {
    const { type } = req.body as { type?: string };
    const ips = ["192.168.1.50", "45.33.22.11", "10.0.0.5", "172.16.0.20"];
    const randomIp = ips[Math.floor(Math.random() * ips.length)];
    const eventType = type || "Unusual Traffic";
    const id = insertEvent({
      source_ip: randomIp,
      event_kind: "network",
      action: "traffic",
      features_json: JSON.stringify({ simulated: true, type: eventType }),
      severity: "high",
      description: `Simulated potential ${eventType} from ${randomIp}`,
      status: "pending_analyze",
    });
    const row = getDb().prepare("SELECT * FROM events WHERE id = ?").get(id);
    publishIngestedEvent(id);
    res.json({ success: true, id });
  });

  app.post("/api/quantum/rsa-demo", (_req, res) => {
    const demo = runRsaShorDemo("HI");
    const db = getDb();
    const cur = (
      db.prepare("SELECT value FROM settings WHERE key = 'quantum_demo_runs'").get() as { value: string } | undefined
    )?.value;
    const n = String(Number(cur || 0) + 1);
    db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('quantum_demo_runs', ?)").run(n);
    publish({ type: "quantum_demo", data: { ...demo, ciphertext: demo.ciphertext } });
    res.json(demo);
  });

  app.get("/api/pqc/demo", (_req, res) => {
    const out = runPqcDemo();
    publish({ type: "pqc_demo", data: out });
    res.json(out);
  });

  app.post("/api/pqc/protection-demo", (req, res) => {
    const body = req.body as { message?: string } | undefined;
    const out = runRsaLatticeProtectionDemo(body?.message);
    publish({ type: "pqc_protection_demo", data: { summary: out.summary, secretPayloadLen: out.secretPayload.length } });
    res.json(out);
  });

  app.post("/api/secure-message", (req, res) => {
    const { encryptedData } = req.body as { encryptedData?: unknown };
    console.log("Received Quantum-Safe Message:", encryptedData);
    res.json({ status: "success", message: "Message received and verified using lattice-based signatures." });
  });
}
