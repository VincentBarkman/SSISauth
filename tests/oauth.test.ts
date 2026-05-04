import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { createOAuthClient } from "../src/oauth.js";
import { savePKCEState } from "../src/storage.js";
import type { PKCEState } from "../src/types.js";

const BASE_ISSUER = "https://elevkar-auth.ssis.nu";
const TOKEN_URL = `${BASE_ISSUER}/api/auth/oauth2/token`;
const USERINFO_URL = `${BASE_ISSUER}/api/auth/oauth2/userinfo`;

function makeConfig(overrides = {}) {
  return {
    secrets: { clientId: "test-client-id", clientSecret: "test-secret" },
    scopes: ["openid", "profile", "email"],
    discover: false,
    issuer: BASE_ISSUER,
    ...overrides,
  };
}

function mockTokenResponse(overrides: Record<string, unknown> = {}) {
  return {
    access_token: "access-token-xyz",
    id_token: buildFakeJwt({ sub: "user-1", email: "user@example.com" }),
    token_type: "Bearer",
    expires_in: 3600,
    ...overrides,
  };
}

function buildFakeJwt(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const body = btoa(JSON.stringify(payload));
  return `${header}.${body}.fakesig`;
}

function setPKCEState(
  partial: Partial<PKCEState> & { state: string } = { state: "test-state" }
) {
  savePKCEState({
    codeVerifier: "test-verifier",
    redirectUri: "http://localhost:3000/callback",
    ...partial,
  });
}

function setUrl(url: string) {
  Object.defineProperty(window, "location", {
    value: new URL(url),
    writable: true,
    configurable: true,
  });
  window.history.replaceState = vi.fn();
}

describe("createOAuthClient", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.restoreAllMocks();
    setUrl("http://localhost:3000/");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("useSession getter", () => {
    it("returns null when no session is stored", () => {
      const auth = createOAuthClient(makeConfig());
      expect(auth.useSession).toBeNull();
    });

    it("returns null for expired sessions", async () => {
      const auth = createOAuthClient(makeConfig());
      setUrl(`http://localhost:3000/?code=mycode&state=test-state`);
      setPKCEState({ state: "test-state" });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValueOnce({
          ok: true,
          json: async () =>
            mockTokenResponse({ expires_in: -1, id_token: undefined }),
        })
      );

      await auth.initialize();
      expect(auth.useSession).toBeNull();
    });
  });

  describe("initialize()", () => {
    it("does nothing if there is no code in the URL", async () => {
      const fetchMock = vi.fn();
      vi.stubGlobal("fetch", fetchMock);
      const auth = createOAuthClient(makeConfig());
      await auth.initialize();
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("exchanges code for tokens and sets session", async () => {
      setUrl(`http://localhost:3000/?code=auth-code-abc&state=test-state`);
      setPKCEState({ state: "test-state" });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValueOnce({
          ok: true,
          json: async () => mockTokenResponse(),
        })
      );

      const auth = createOAuthClient(makeConfig());
      await auth.initialize();

      expect(auth.useSession).not.toBeNull();
      expect(auth.useSession?.accessToken).toBe("access-token-xyz");
    });

    it("populates user from id_token claims", async () => {
      setUrl(`http://localhost:3000/?code=auth-code-abc&state=test-state`);
      setPKCEState({ state: "test-state" });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValueOnce({
          ok: true,
          json: async () =>
            mockTokenResponse({
              id_token: buildFakeJwt({
                sub: "user-123",
                email: "hello@ssis.nu",
                name: "Test User",
              }),
            }),
        })
      );

      const auth = createOAuthClient(makeConfig());
      await auth.initialize();

      expect(auth.useSession?.user?.email).toBe("hello@ssis.nu");
      expect(auth.useSession?.user?.name).toBe("Test User");
    });

    it("throws on state mismatch", async () => {
      setUrl(`http://localhost:3000/?code=abc&state=wrong-state`);
      setPKCEState({ state: "correct-state" });

      const auth = createOAuthClient(makeConfig());
      await expect(auth.initialize()).rejects.toThrow(/state mismatch/i);
    });

    it("throws when no PKCE state is found", async () => {
      setUrl(`http://localhost:3000/?code=abc&state=test-state`);

      const auth = createOAuthClient(makeConfig());
      await expect(auth.initialize()).rejects.toThrow(/no pkce state/i);
    });

    it("throws on OAuth error in the redirect URL", async () => {
      setUrl(
        `http://localhost:3000/?error=access_denied&error_description=User+denied+access`
      );

      const auth = createOAuthClient(makeConfig());
      await expect(auth.initialize()).rejects.toThrow(/user denied access/i);
    });

    it("throws when the token endpoint returns an error", async () => {
      setUrl(`http://localhost:3000/?code=bad-code&state=test-state`);
      setPKCEState({ state: "test-state" });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValueOnce({
          ok: false,
          json: async () => ({
            error: "invalid_grant",
            error_description: "Code expired",
          }),
        })
      );

      const auth = createOAuthClient(makeConfig());
      await expect(auth.initialize()).rejects.toThrow(/code expired/i);
    });

    it("throws on invalid_client error from the token endpoint", async () => {
      setUrl(`http://localhost:3000/?code=bad-code&state=test-state`);
      setPKCEState({ state: "test-state" });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValueOnce({
          ok: false,
          json: async () => ({
            error: "invalid_client",
            error_description: "Client authentication failed",
          }),
        })
      );

      const auth = createOAuthClient(makeConfig());
      await expect(auth.initialize()).rejects.toThrow(/client authentication failed/i);
    });

    it("sends the token request to the correct endpoint URL", async () => {
      setUrl(`http://localhost:3000/?code=auth-code-abc&state=test-state`);
      setPKCEState({ state: "test-state" });

      const fetchMock = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => mockTokenResponse(),
      });
      vi.stubGlobal("fetch", fetchMock);

      const auth = createOAuthClient(makeConfig());
      await auth.initialize();

      expect(fetchMock).toHaveBeenCalledWith(TOKEN_URL, expect.any(Object));
    });

    it("sends correct body params in the token request", async () => {
      setUrl(`http://localhost:3000/?code=auth-code-abc&state=test-state`);
      setPKCEState({ state: "test-state" });

      const fetchMock = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => mockTokenResponse(),
      });
      vi.stubGlobal("fetch", fetchMock);

      const auth = createOAuthClient(makeConfig());
      await auth.initialize();

      const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
      const body = new URLSearchParams(init.body as string);
      expect(body.get("grant_type")).toBe("authorization_code");
      expect(body.get("client_id")).toBe("test-client-id");
      expect(body.get("code")).toBe("auth-code-abc");
      expect(body.get("redirect_uri")).toBe("http://localhost:3000/callback");
      expect(body.get("code_verifier")).toBe("test-verifier");
    });

    it("does not send a spoofed Origin header in the token request", async () => {
      setUrl(`http://localhost:3000/?code=auth-code-abc&state=test-state`);
      setPKCEState({ state: "test-state" });

      const fetchMock = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => mockTokenResponse(),
      });
      vi.stubGlobal("fetch", fetchMock);

      const auth = createOAuthClient(makeConfig());
      await auth.initialize();

      const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
      const headers = init.headers as Record<string, string>;
      expect(headers["Origin"]).toBeUndefined();
    });

    it("cleans code and state from the URL after exchange", async () => {
      setUrl(`http://localhost:3000/?code=auth-code&state=test-state`);
      setPKCEState({ state: "test-state" });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValueOnce({
          ok: true,
          json: async () => mockTokenResponse(),
        })
      );

      const replaceState = vi.spyOn(window.history, "replaceState");

      const auth = createOAuthClient(makeConfig());
      await auth.initialize();

      expect(replaceState).toHaveBeenCalled();
      const calledUrl = (replaceState.mock.calls[0] as unknown[])[2] as string;
      expect(calledUrl).not.toContain("code=");
      expect(calledUrl).not.toContain("state=");
    });
  });

  describe("signin()", () => {
    it("redirects to the authorization endpoint", async () => {
      const auth = createOAuthClient(makeConfig());

      let redirectedTo = "";
      Object.defineProperty(window, "location", {
        value: {
          ...window.location,
          set href(url: string) {
            redirectedTo = url;
          },
          get href() {
            return "http://localhost:3000/";
          },
          origin: "http://localhost:3000",
          pathname: "/",
        },
        configurable: true,
        writable: true,
      });

      await auth.signin();

      expect(redirectedTo).toContain(
        "/api/auth/oauth2/authorize"
      );
      expect(redirectedTo).toContain("response_type=code");
      expect(redirectedTo).toContain("client_id=test-client-id");
      expect(redirectedTo).toContain("code_challenge_method=S256");
    });
  });

  describe("logout()", () => {
    it("clears the session and redirects to end-session endpoint", async () => {
      setUrl(`http://localhost:3000/?code=auth-code&state=test-state`);
      setPKCEState({ state: "test-state" });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValueOnce({
          ok: true,
          json: async () => mockTokenResponse(),
        })
      );

      const auth = createOAuthClient(makeConfig());
      await auth.initialize();
      expect(auth.useSession).not.toBeNull();

      let redirectedTo = "";
      Object.defineProperty(window, "location", {
        value: {
          ...window.location,
          set href(url: string) {
            redirectedTo = url;
          },
          get href() {
            return "http://localhost:3000/";
          },
          origin: "http://localhost:3000",
        },
        configurable: true,
        writable: true,
      });

      auth.logout();

      expect(auth.useSession).toBeNull();
      expect(redirectedTo).toContain("/api/auth/oauth2/logout");
    });
  });

  describe("getUser()", () => {
    it("returns null when not signed in", async () => {
      const auth = createOAuthClient(makeConfig());
      expect(await auth.getUser()).toBeNull();
    });

    it("fetches userinfo from the endpoint when no id_token user data", async () => {
      setUrl(`http://localhost:3000/?code=auth-code&state=test-state`);
      setPKCEState({ state: "test-state" });

      const tokenFetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => mockTokenResponse({ id_token: undefined }),
      });
      const userFetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sub: "u1", email: "me@ssis.nu" }),
      });

      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockImplementationOnce(tokenFetch)
          .mockImplementationOnce(userFetch)
      );

      const auth = createOAuthClient(makeConfig());
      await auth.initialize();

      const user = await auth.getUser();
      expect(user?.email).toBe("me@ssis.nu");
    });
  });
});
