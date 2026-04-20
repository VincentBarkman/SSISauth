import { describe, it, expect, beforeAll } from "vitest";
import { verifyIdToken } from "../src/verify.js";
import type { JWK, JWKSet } from "../src/types.js";

const ISSUER = "https://auth.example.com";
const CLIENT_ID = "test-client";

let _privateKey: CryptoKey;
let _testJwks: JWKSet;

beforeAll(async () => {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
    },
    true,
    ["sign", "verify"]
  );
  _privateKey = pair.privateKey;
  const pubJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  _testJwks = {
    keys: [{ ...pubJwk, kid: "test-key-1", use: "sig" } as JWK],
  };
});

function base64UrlEncode(buf: ArrayBuffer | Uint8Array): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function signJWT(
  payload: Record<string, unknown>,
  overrideHeader?: Record<string, unknown>
): Promise<string> {
  const header = {
    alg: "RS256",
    typ: "JWT",
    kid: "test-key-1",
    ...overrideHeader,
  };

  const enc = new TextEncoder();
  const h = base64UrlEncode(enc.encode(JSON.stringify(header)).buffer as ArrayBuffer);
  const p = base64UrlEncode(enc.encode(JSON.stringify(payload)).buffer as ArrayBuffer);
  const signingInput = enc.encode(`${h}.${p}`);

  const sig = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    _privateKey,
    signingInput
  );

  return `${h}.${p}.${base64UrlEncode(sig)}`;
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

describe("verifyIdToken", () => {
  it("verifies a valid RS256 token", async () => {
    const token = await signJWT({
      sub: "user-1",
      iss: ISSUER,
      aud: CLIENT_ID,
      iat: nowSec(),
      exp: nowSec() + 3600,
      email: "user@ssis.nu",
    });

    const claims = await verifyIdToken(token, _testJwks, {
      issuer: ISSUER,
      audience: CLIENT_ID,
    });

    expect(claims.sub).toBe("user-1");
    expect(claims.email).toBe("user@ssis.nu");
  });

  it("selects the correct key by kid", async () => {
    const jwksWithExtra: JWKSet = {
      keys: [
        { kty: "RSA", use: "sig", kid: "other-key", alg: "RS256", n: "x", e: "AQAB" },
        ..._testJwks.keys,
      ],
    };

    const token = await signJWT({
      sub: "u2",
      iss: ISSUER,
      aud: CLIENT_ID,
      exp: nowSec() + 3600,
    });

    const claims = await verifyIdToken(token, jwksWithExtra);
    expect(claims.sub).toBe("u2");
  });

  it("throws on expired token", async () => {
    const token = await signJWT({
      sub: "u",
      iss: ISSUER,
      aud: CLIENT_ID,
      exp: nowSec() - 10,
    });

    await expect(
      verifyIdToken(token, _testJwks)
    ).rejects.toThrow(/expired/i);
  });

  it("accepts an expired token within clock skew", async () => {
    const token = await signJWT({
      sub: "u",
      iss: ISSUER,
      aud: CLIENT_ID,
      exp: nowSec() - 5,
    });

    const claims = await verifyIdToken(token, _testJwks, {
      clockSkewSeconds: 30,
    });
    expect(claims.sub).toBe("u");
  });

  it("throws on nbf in the future", async () => {
    const token = await signJWT({
      sub: "u",
      iss: ISSUER,
      aud: CLIENT_ID,
      exp: nowSec() + 3600,
      nbf: nowSec() + 600,
    });

    await expect(
      verifyIdToken(token, _testJwks)
    ).rejects.toThrow(/not yet valid/i);
  });

  it("throws on issuer mismatch", async () => {
    const token = await signJWT({
      sub: "u",
      iss: "https://wrong-issuer.example.com",
      aud: CLIENT_ID,
      exp: nowSec() + 3600,
    });

    await expect(
      verifyIdToken(token, _testJwks, { issuer: ISSUER })
    ).rejects.toThrow(/issuer mismatch/i);
  });

  it("throws on audience mismatch", async () => {
    const token = await signJWT({
      sub: "u",
      iss: ISSUER,
      aud: "other-client",
      exp: nowSec() + 3600,
    });

    await expect(
      verifyIdToken(token, _testJwks, { audience: CLIENT_ID })
    ).rejects.toThrow(/audience mismatch/i);
  });

  it("throws when no matching key is found in JWKS", async () => {
    const emptyJwks: JWKSet = { keys: [] };
    const token = await signJWT({
      sub: "u",
      exp: nowSec() + 3600,
    });

    await expect(
      verifyIdToken(token, emptyJwks)
    ).rejects.toThrow(/no key found/i);
  });

  it("throws on invalid JWT format (wrong segment count)", async () => {
    await expect(
      verifyIdToken("not.a.valid.jwt.here", _testJwks)
    ).rejects.toThrow(/3 segments/i);
  });

  it("throws on unsupported algorithm", async () => {
    const token = await signJWT(
      { sub: "u", exp: nowSec() + 3600 },
      { alg: "HS256", kid: "test-key-1" }
    );

    await expect(
      verifyIdToken(token, _testJwks)
    ).rejects.toThrow(/unsupported algorithm/i);
  });

  it("throws when signature is tampered", async () => {
    const token = await signJWT({
      sub: "u",
      iss: ISSUER,
      aud: CLIENT_ID,
      exp: nowSec() + 3600,
    });

    const [h, p] = token.split(".");
    const tampered = `${h}.${p}.aW52YWxpZHNpZ25hdHVyZQ`;

    await expect(
      verifyIdToken(tampered, _testJwks)
    ).rejects.toThrow(/signature verification failed/i);
  });
});
