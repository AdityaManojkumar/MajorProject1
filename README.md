<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/cfe5c60c-d5a1-4da0-b037-3c294617722c

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`

## Features (QuantumGuard upgrade)

- **Protocol Analysis Layer** — L3/L4/L7 feature extraction before AI classification (`backend/protocol/analyzer.ts`).
- **Layer-aware incident response** — IP block (L3), port/session (L4), account/API throttle (L7).
- **Cross-layer crypto module** — classical vs quantum cryptographic threat classification + PQC demos.
- **SSE** `GET /api/stream` — real-time event, analysis, and mitigation updates.
- **Events** `GET /api/events` — normalized security events with OSI layer and protocol fields.
- **Protocol threats** `GET /api/protocol/threats` — dashboard widget data.
- **Login demo** `POST /api/auth/login` — default `admin` / `admin123` (override with `DEMO_USER` / `DEMO_PASS`).
- **Dataset replay** `POST /api/sim/replay/start` — sample CSVs under `datasets/samples/`.
- **AI classify** `POST /api/analyze` — attack type, OSI layer, protocol, severity score (Gemini + heuristic).
- **Quantum RSA demo** `POST /api/quantum/rsa-demo` — small-key RSA + simulated Shor factors.
- **PQC walkthrough** `GET /api/pqc/demo` — Kyber / Dilithium / SPHINCS+ educational steps.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full pipeline and OSI protection matrix.

UI tabs: **Overview** (charts + protocol threat matrix), **Logs**, **Live**, **Quantum**, **PQC**, **Defense**.
