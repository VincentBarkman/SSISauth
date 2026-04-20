import type { JWK, JWKSet, JWTClaims } from "./types.js";

interface JWTHeader {
  alg: string;
  kid?: string;
  typ?: string;
}

function base64UrlDecodeToBuffer(str: string): ArrayBuffer {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function decodeBase64UrlJson<T>(segment: string): T {
  return JSON.parse(
    new TextDecoder().decode(base64UrlDecodeToBuffer(segment))
  ) as T;
}

async function importRSAPublicKey(jwk: JWK): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    jwk as JsonWebKey,
    { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
    false,
    ["verify"]
  );
}

function selectKey(jwks: JWKSet, header: JWTHeader): JWK {
  if (header.kid) {
    const byKid = jwks.keys.find((k) => k.kid === header.kid);
    if (byKid) return byKid;
  }
  const sig = jwks.keys.find((k) => k.use === "sig" || !k.use);
  if (sig) return sig;
  throw new Error(
    `No key found in JWKS matching kid="${header.kid ?? "(none)"}"`
  );
}

export interface VerifyOptions {
  issuer?: string;
  audience?: string;
  clockSkewSeconds?: number;
}

export async function verifyIdToken(
  token: string,
  jwks: JWKSet,
  options: VerifyOptions = {}
): Promise<JWTClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT: expected 3 segments");

  const [headerB64, payloadB64, signatureB64] = parts;

  const header = decodeBase64UrlJson<JWTHeader>(headerB64);

  if (header.alg !== "RS256") {
    throw new Error(`Unsupported algorithm: ${header.alg}. Only RS256 is supported.`);
  }

  const key = selectKey(jwks, header);
  const cryptoKey = await importRSAPublicKey(key);

  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = base64UrlDecodeToBuffer(signatureB64);

  const valid = await crypto.subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    cryptoKey,
    signature,
    signingInput
  );

  if (!valid) throw new Error("JWT signature verification failed");

  const claims = decodeBase64UrlJson<JWTClaims>(payloadB64);
  const skew = options.clockSkewSeconds ?? 0;
  const nowSec = Math.floor(Date.now() / 1000);

  if (claims.exp !== undefined && claims.exp + skew < nowSec) {
    throw new Error("JWT has expired");
  }
  if (claims.nbf !== undefined && claims.nbf - skew > nowSec) {
    throw new Error("JWT is not yet valid (nbf)");
  }
  if (options.issuer && claims.iss !== options.issuer) {
    throw new Error(
      `JWT issuer mismatch: expected "${options.issuer}", got "${claims.iss}"`
    );
  }
  if (options.audience) {
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!aud.includes(options.audience)) {
      throw new Error(
        `JWT audience mismatch: "${options.audience}" not in [${aud.join(", ")}]`
      );
    }
  }

  return claims;
}
