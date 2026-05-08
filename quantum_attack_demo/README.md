# Quantum attack demo (Python + Qiskit + FastAPI)

Educational module: **tiny RSA** → **encrypt** → **factor modulus using real Shor on a simulator** → **recover private key** → **decrypt**.

## 1. Install (Ubuntu / Linux)

```bash
cd quantum_attack_demo
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If `pip` is missing:

```bash
sudo apt update
sudo apt install -y python3-pip python3-venv
```

## 2. Run API

```bash
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000
```

Open docs: `http://localhost:8000/docs`

### Main endpoint

`GET /quantum-attack?message=Hi&n=15`

Example:

```bash
wget -qO- 'http://localhost:8000/quantum-attack?message=Hi&n=15'
```

## 3. CLI (no HTTP)

```bash
source .venv/bin/activate
python main.py "RSA"
```

## 4. Sample JSON shape

```json
{
  "rsa_modulus": 15,
  "public_key": [3, 15],
  "encrypted_message": "[12, 9]",
  "factored_primes": [3, 5],
  "time_taken": "0.0234s",
  "decrypted_message": "Hi",
  "status": "ENCRYPTION BROKEN"
}
```

## 5. Dashboard integration

- From browser JS: `fetch('http://localhost:8000/quantum-attack?message=Hi')` (CORS allows `localhost:3000` by default).
- Or proxy through your Node server if you prefer a single origin.

## Notes

- Modulus is one of **15, 21, 35** by design (`n` query param).
- This is **not** cryptographically secure.
- This module does **not** silently fall back to classical factoring. If Shor cannot run in your environment, the API returns an error telling you what to install/fix.
