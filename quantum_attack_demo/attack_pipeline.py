"""
End-to-end quantum attack demonstration pipeline (educational).
"""

from __future__ import annotations

from typing import Any, Dict, List

from quantum_attack import simulate_shor
from rsa_module import PrivateKey, PublicKey, decrypt, encrypt, generate_rsa_keys


def _reconstruct_private_key_from_factors(p: int, q: int, public_key: PublicKey) -> PrivateKey:
    e, n = public_key
    if p * q != n:
        raise ValueError("Factored primes do not match RSA modulus")
    phi = (p - 1) * (q - 1)
    # Recover d from known factorisation (what attacker gains after breaking RSA)
    from rsa_module import mod_inverse

    d = mod_inverse(e, phi)
    return (d, n)


def run_quantum_attack_demo(message: str, n_override: int | None = None) -> Dict[str, Any]:
    """
    Full story:
      RSA keygen → encrypt → “quantum” factor n → rebuild d → decrypt.
    """
    console: List[str] = []
    console.append("Quantum lab — toy RSA, real Shor path on Aer (educational)")

    console.append("① Keypair minted for the victim modulus (intentionally tiny primes)")
    if n_override in (15, 21, 35):
        if n_override == 15:
            pub, priv_true = generate_rsa_keys(3, 5)
        elif n_override == 21:
            pub, priv_true = generate_rsa_keys(3, 7)
        else:
            pub, priv_true = generate_rsa_keys(5, 7)
    else:
        pub, priv_true = generate_rsa_keys()
    e, n = pub
    console.append(f"   Published material only: exponent e={e}, modulus n={n} (bits ≈ {n.bit_length()})")

    console.append("② Alice’s message sealed — ciphertext leaves the wire")
    ct = encrypt(message, pub)
    console.append(f"   {len(ct)} integer block(s) produced; intercept holds numbers, not the factorisation")

    console.append("③ Adversary runs Shor on n — period finding, not trial division")
    shor = simulate_shor(n)

    for line in shor.steps:
        console.append(f"   ▸ {line}")

    console.append("④ From factors to φ(n) to d — same algebra a real break would use")
    p, q = shor.p, shor.q
    priv_attack = _reconstruct_private_key_from_factors(p, q, pub)
    console.append(f"   Derived decryption exponent matches structure of a legitimate private key")

    console.append("⑤ Decrypt with the synthesised key — no oracle to the original d")
    recovered = decrypt(ct, priv_attack)
    preview = recovered if len(recovered) <= 48 else recovered[:45] + "…"
    console.append(f"   Recovered text (preview): {preview!r}")

    # Sanity: matches ground-truth key decrypt
    truth = decrypt(ct, priv_true)
    assert truth == message

    ok = recovered == message
    status = "ENCRYPTION BROKEN" if ok else "DEMO INCONSISTENT"

    console.append("⑥ Verdict")
    console.append(f"   {status} — intercept-and-break narrative complete")
    console.append("   Takeaway: once n factors cheaply, textbook RSA confidentiality evaporates; PQC mitigates this class of threat.")

    return {
        "rsa_modulus": n,
        "public_key": [e, n],
        "private_key_ground_truth": [priv_true[0], n],
        "encrypted_message": ct,
        "encrypted_message_repr": str(ct),
        "factored_primes": sorted([p, q]),
        "time_taken_seconds": round(shor.time_seconds, 6),
        "time_taken": f"{shor.time_seconds:.4f}s",
        "decrypted_message": recovered,
        "status": status,
        "message_matches": ok,
        "used_library_shor": shor.used_qiskit_shor,
        "console_log": "\n".join(console),
    }
