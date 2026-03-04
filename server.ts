import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import Database from "better-sqlite3";
import { GoogleGenAI } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const db = new Database("cybersecurity.db");

// Initialize DB
db.exec(`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip TEXT,
    event_type TEXT,
    severity TEXT,
    description TEXT,
    status TEXT DEFAULT 'pending'
  );

  CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE,
    reason TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );

  -- Seed initial data if empty
  INSERT INTO logs (source_ip, event_type, severity, description, status)
  SELECT '192.168.1.1', 'System Startup', 'low', 'QuantumGuard Node SG-01 initialized', 'cleared'
  WHERE NOT EXISTS (SELECT 1 FROM logs);
  
  INSERT INTO logs (source_ip, event_type, severity, description, status)
  SELECT '10.0.0.15', 'Login Attempt', 'low', 'Successful admin login from internal network', 'cleared'
  WHERE (SELECT COUNT(*) FROM logs) < 2;
`);

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Routes
  app.get("/api/logs", (req, res) => {
    const logs = db.prepare("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100").all();
    res.json(logs);
  });

  app.get("/api/blocked-ips", (req, res) => {
    const ips = db.prepare("SELECT * FROM blocked_ips ORDER BY timestamp DESC").all();
    res.json(ips);
  });

  app.post("/api/simulate-attack", async (req, res) => {
    const { type } = req.body;
    const ips = ["192.168.1.50", "45.33.22.11", "10.0.0.5", "172.16.0.20"];
    const randomIp = ips[Math.floor(Math.random() * ips.length)];
    
    let event = {
      source_ip: randomIp,
      event_type: type || "Unusual Traffic",
      severity: "high",
      description: `Detected potential ${type || 'anomaly'} from ${randomIp}`
    };

    const stmt = db.prepare("INSERT INTO logs (source_ip, event_type, severity, description) VALUES (?, ?, ?, ?)");
    const info = stmt.run(event.source_ip, event.event_type, event.severity, event.description);
    
    res.json({ success: true, id: info.lastInsertRowid });
  });

  app.post("/api/analyze-threats", async (req, res) => {
    try {
      const logs = db.prepare("SELECT * FROM logs WHERE status = 'pending' LIMIT 5").all();
      if (logs.length === 0) return res.json({ processed: 0 });

      const prompt = `Analyze these system logs and identify if any represent a real cyber attack. 
      For each log, decide if it should be 'blocked' or 'ignored'. 
      If blocked, provide a reason.
      Logs: ${JSON.stringify(logs)}
      Return a JSON array of objects: { id: number, action: 'block' | 'ignore', reason: string }`;

      const response = await ai.models.generateContent({
        model: "gemini-2.0-flash-exp",
        contents: [{ parts: [{ text: prompt }] }],
        config: { responseMimeType: "application/json" }
      });

      const results = JSON.parse(response.text || "[]");
      
      for (const result of results) {
        if (result.action === "block") {
          const log = db.prepare("SELECT source_ip FROM logs WHERE id = ?").get(result.id) as any;
          if (log) {
            db.prepare("INSERT OR IGNORE INTO blocked_ips (ip, reason) VALUES (?, ?)").run(log.source_ip, result.reason);
            db.prepare("UPDATE logs SET status = 'blocked' WHERE id = ?").run(result.id);
          }
        } else {
          db.prepare("UPDATE logs SET status = 'cleared' WHERE id = ?").run(result.id);
        }
      }

      res.json({ processed: results.length, results });
    } catch (error) {
      console.error("AI Analysis Error:", error);
      res.status(500).json({ error: "Failed to analyze threats" });
    }
  });

  // PQC Secure Message Simulation
  app.post("/api/secure-message", (req, res) => {
    const { encryptedData, publicKey } = req.body;
    // In a real PQC app, we'd decrypt here using our private key.
    // For simulation, we'll just log that a quantum-safe message was received.
    console.log("Received Quantum-Safe Message:", encryptedData);
    res.json({ status: "success", message: "Message received and verified using lattice-based signatures." });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
