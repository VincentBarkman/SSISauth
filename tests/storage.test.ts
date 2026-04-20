import { describe, it, expect, beforeEach } from "vitest";
import {
  saveSession,
  loadSession,
  clearSession,
  savePKCEState,
  loadPKCEState,
  clearPKCEState,
} from "../src/storage.js";
import type { Session, PKCEState } from "../src/types.js";

function makeSession(overrides: Partial<Session> = {}): Session {
  return {
    accessToken: "tok_abc123",
    tokenType: "Bearer",
    expiresAt: Date.now() + 3600_000,
    ...overrides,
  };
}

describe("Session storage", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("saves and loads a session", () => {
    const session = makeSession();
    saveSession(session);
    expect(loadSession()).toEqual(session);
  });

  it("returns null when nothing is stored", () => {
    expect(loadSession()).toBeNull();
  });

  it("returns null and clears for an expired session", () => {
    const expired = makeSession({ expiresAt: Date.now() - 1 });
    saveSession(expired);
    expect(loadSession()).toBeNull();
    expect(localStorage.getItem("ssisauth:session")).toBeNull();
  });

  it("returns null and clears for malformed JSON", () => {
    localStorage.setItem("ssisauth:session", "not-json{{{");
    expect(loadSession()).toBeNull();
  });

  it("clears the session", () => {
    saveSession(makeSession());
    clearSession();
    expect(loadSession()).toBeNull();
  });

  it("preserves user info in the session", () => {
    const session = makeSession({
      user: { sub: "user-1", email: "test@example.com" },
    });
    saveSession(session);
    expect(loadSession()?.user?.email).toBe("test@example.com");
  });
});

describe("PKCE state storage", () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  const pkce: PKCEState = {
    codeVerifier: "verifier-xyz",
    state: "state-abc",
    redirectUri: "http://localhost:3000/callback",
  };

  it("saves and loads PKCE state", () => {
    savePKCEState(pkce);
    expect(loadPKCEState()).toEqual(pkce);
  });

  it("returns null when nothing is stored", () => {
    expect(loadPKCEState()).toBeNull();
  });

  it("returns null for malformed JSON", () => {
    sessionStorage.setItem("ssisauth:pkce", "bad{{json");
    expect(loadPKCEState()).toBeNull();
  });

  it("clears PKCE state", () => {
    savePKCEState(pkce);
    clearPKCEState();
    expect(loadPKCEState()).toBeNull();
  });
});
