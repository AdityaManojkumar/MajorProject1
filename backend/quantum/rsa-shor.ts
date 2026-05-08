/**
 * Educational RSA demo with small integers + simulated Shor factorization.
 * Not cryptographically secure.
 */

function modPow(a: number, e: number, m: number): number {
  let r = 1;
  a %= m;
  while (e > 0) {
    if (e & 1) r = (r * a) % m;
    a = (a * a) % m;
    e >>= 1;
  }
  return r;
}

function gcd(a: number, b: number): number {
  while (b) {
    const t = b;
    b = a % b;
    a = t;
  }
  return Math.abs(a);
}

function extendedGcd(a: number, b: number): [number, number, number] {
  if (b === 0) return [a, 1, 0];
  const [g, x1, y1] = extendedGcd(b, a % b);
  return [g, y1, x1 - Math.floor(a / b) * y1];
}

function modInverse(a: number, m: number): number {
  const [g, x] = extendedGcd(a, m);
  if (g !== 1) throw new Error("no inverse");
  return ((x % m) + m) % m;
}

/** Pick small demo primes */
export function runRsaShorDemo(plaintext = "OK"): {
  steps: string[];
  p: number;
  q: number;
  n: number;
  phi: number;
  e: number;
  d: number;
  ciphertext: number[];
  decrypted: string;
  shorFactors: { p: number; q: number; method: string };
  privateKeyRecovered: boolean;
} {
  const p = 17;
  const q = 19;
  const n = p * q;
  const phi = (p - 1) * (q - 1);
  const e_pub = 5;
  const d = modInverse(e_pub, phi);

  const steps: string[] = [
    `Key generation: small primes yield n=${n}; φ(n)=${phi}; public e=${e_pub} hides private d behind integer factorisation.`,
    `Threat model: classical adversaries must brute-force factors or GNFS; quantum adversaries target period structure instead.`,
  ];

  const bytes = Array.from(plaintext).map((c) => c.charCodeAt(0) % n);
  const ciphertext = bytes.map((m) => modPow(m, e_pub, n));
  steps.push(
    `Encrypt: ${plaintext.length} byte(s) → modular exponentials (blocks omitted here — inspect DevTools payload for numbers).`
  );

  const decrypted = ciphertext
    .map((c) => String.fromCharCode(modPow(c, d, n)))
    .join("");
  steps.push(`Legitimate decrypt recovers “${decrypted}” using the true private exponent.`);

  // Simulated Shor: in reality period finding on a quantum circuit; here we "reveal" factors for demo
  const shorFactors = {
    p,
    q,
    method:
      "Educational stand-in: real Shor finds periods via quantum Fourier sampling; this UI reveals factors to narrate the breach.",
  };
  steps.push(
    `Simulated Shor phase: modulus factors as ${p}×${q}; attacker rebuilds φ(n), derives an equivalent d, and breaks confidentiality at scale.`
  );

  return {
    steps,
    p,
    q,
    n,
    phi,
    e: e_pub,
    d,
    ciphertext,
    decrypted,
    shorFactors,
    privateKeyRecovered: true,
  };
}
