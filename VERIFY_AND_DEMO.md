# Verify Everything & Show the Demo

## 1. Quick verification (is everything running 100%?)

### A. Server is up
- Terminal shows: `Server running on http://localhost:3000`
- Open in browser: **http://localhost:3000**
- You should see the QuantumGuard cybersecurity dashboard (no blank page, no connection errors)

### B. Backend APIs
With the app running, open a **second** terminal and run:

```bash
# Logs (should return JSON array)
curl -s http://localhost:3000/api/logs | head -c 200

# Blocked IPs (should return JSON array)
curl -s http://localhost:3000/api/blocked-ips
```

Both should return JSON, not "Connection refused" or HTML.

### C. Database
- On the dashboard, you should see **Security Logs** and **Blocked IPs** (may be empty at first).
- If the Overview tab shows stats and charts, the DB and frontend are talking to the server.

### D. Simulate attack
- In the UI, find the **Simulate Attack** or similar control.
- Click it (e.g. "Unusual Traffic" or "DDoS").
- Refresh or wait a few seconds: a **new log entry** should appear in the logs list.
- If it does, the server and DB are working.

### E. AI threat analysis (Gemini)
- Ensure there are some logs with status **pending** (simulate an attack first if needed).
- Click **Analyze Threats** (or "Run AI Analysis").
- Wait a few seconds. You should see either:
  - Some logs marked **blocked** or **cleared**, and/or
  - New entries under **Blocked IPs** if the AI decided to block.
- If you get an error or "Failed to analyze threats", check that `GEMINI_API_KEY` in `.env` is set and valid.

### F. PQC (Post-Quantum Cryptography) demo
- Open the **PQC** or **Quantum-Safe** tab/section.
- Click the button to generate keys / run the demo.
- You should see something like "Quantum-Safe Protocol Initialized" or encrypted/decrypted message output.
- No console errors = PQC demo is working.

---

## 2. How to show the demo (presentation flow)

1. **Start the app**
   ```bash
   cd /home/aditya_manoj/MajorProject1
   npm run dev
   ```

2. **Open the dashboard**
   - Browser: **http://localhost:3000**
   - Show the **Overview** tab: stats, charts, system health.

3. **Show live logs**
   - Go to the **Logs** (or Security Logs) section.
   - Point out the existing seed logs (e.g. "System Startup", "Login Attempt").

4. **Simulate an attack**
   - Use **Simulate Attack** (e.g. "DDoS", "Brute Force", "Unusual Traffic").
   - Show the new **pending** log appearing in the list.

5. **Run AI analysis**
   - Click **Analyze Threats**.
   - Show that the AI (Gemini) classifies events and that some get **blocked** (and appear under Blocked IPs) and some **cleared**.

6. **Show Blocked IPs**
   - Open the **Blocked IPs** section and show any IPs the AI decided to block with reasons.

7. **PQC / Quantum-safe demo**
   - Switch to the **PQC** (or Quantum-Safe) tab.
   - Run the key-generation / encryption demo and show the "Quantum-Safe Protocol Initialized" (or similar) message.

8. **Optional: API check**
   - If you want to show it’s a real backend, open DevTools → Network, trigger **Simulate Attack** or **Analyze Threats**, and show the `/api/simulate-attack` or `/api/analyze-threats` requests and JSON responses.

---

## 3. One-line sanity check

With the server running:

```bash
curl -s http://localhost:3000/api/logs | head -c 300
```

You should see JSON. If you see "Connection refused" or HTML, the server isn’t running or the port is wrong.
