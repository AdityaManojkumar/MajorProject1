"""
FastAPI entrypoint for the quantum attack demo.

Run:
  uvicorn main:app --reload --port 8000

Or:
  python main.py
"""

from __future__ import annotations

import os
import sys

from attack_pipeline import run_quantum_attack_demo
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Quantum Attack Demo API",
    description="Educational RSA + Qiskit-assisted factorization simulation",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/quantum-attack")
def quantum_attack(
    message: str = Query(default="Hi", min_length=1, max_length=32),
    n: int = Query(default=15, description="RSA modulus to break (15, 21, or 35)"),
):
    """
    Run full pipeline and return JSON suitable for dashboard binding.
    """
    try:
        result = run_quantum_attack_demo(message, n_override=n)
        print(result["console_log"])
        return {
            "rsa_modulus": result["rsa_modulus"],
            "public_key": result["public_key"],
            "encrypted_message": result["encrypted_message_repr"],
            "factored_primes": result["factored_primes"],
            "time_taken": result["time_taken"],
            "decrypted_message": result["decrypted_message"],
            "status": result["status"],
            "used_library_shor": result["used_library_shor"],
            "message_matches": result["message_matches"],
            "console_log": result["console_log"],
        }
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={
                "status": "FAILED",
                "error": str(exc),
                "hint": "Install compatible qiskit + qiskit-aer + qiskit-algorithms, then retry. Use n=15 for the most reliable Shor demo.",
            },
        )


@app.get("/health")
def health():
    return {"ok": True}


def main() -> None:
    """CLI quick run without HTTP server."""
    msg = sys.argv[1] if len(sys.argv) > 1 else "Hi"
    out = run_quantum_attack_demo(msg)
    print(out["console_log"])
    print("\nJSON summary:")
    print(
        {
            "rsa_modulus": out["rsa_modulus"],
            "public_key": out["public_key"],
            "factored_primes": out["factored_primes"],
            "time_taken": out["time_taken"],
            "status": out["status"],
        }
    )


if __name__ == "__main__":
    # If user runs `python main.py serve`, start uvicorn; else demo pipeline.
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        import uvicorn

        uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=False)
    else:
        main()
