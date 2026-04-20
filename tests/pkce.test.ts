import { describe, it, expect } from "vitest";
import {
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
} from "../src/pkce.js";

describe("PKCE helpers", () => {
  describe("generateCodeVerifier", () => {
    it("produces a non-empty string", () => {
      expect(generateCodeVerifier()).toBeTruthy();
    });

    it("produces only URL-safe base64 characters", () => {
      const verifier = generateCodeVerifier();
      expect(verifier).toMatch(/^[A-Za-z0-9\-_]+$/);
    });

    it("produces at least 43 characters (RFC 7636 minimum)", () => {
      const verifier = generateCodeVerifier();
      expect(verifier.length).toBeGreaterThanOrEqual(43);
    });

    it("generates a different value each time", () => {
      expect(generateCodeVerifier()).not.toBe(generateCodeVerifier());
    });
  });

  describe("generateCodeChallenge", () => {
    it("returns a non-empty string", async () => {
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      expect(challenge).toBeTruthy();
    });

    it("returns only URL-safe base64 characters (no padding)", async () => {
      const challenge = await generateCodeChallenge("test-verifier-value");
      expect(challenge).toMatch(/^[A-Za-z0-9\-_]+$/);
    });

    it("is deterministic for the same verifier", async () => {
      const verifier = "stable-verifier-for-testing";
      const c1 = await generateCodeChallenge(verifier);
      const c2 = await generateCodeChallenge(verifier);
      expect(c1).toBe(c2);
    });

    it("produces the correct SHA-256 S256 challenge for a known verifier", async () => {
      // RFC 7636 example: verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
      // challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
      const challenge = await generateCodeChallenge(
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
      );
      expect(challenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    });
  });

  describe("generateState", () => {
    it("produces a non-empty string", () => {
      expect(generateState()).toBeTruthy();
    });

    it("generates different values each time", () => {
      expect(generateState()).not.toBe(generateState());
    });

    it("contains only URL-safe characters", () => {
      const state = generateState();
      expect(state).toMatch(/^[A-Za-z0-9\-_]+$/);
    });
  });
});
