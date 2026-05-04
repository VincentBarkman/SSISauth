import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  fetchOpenIDConfiguration,
  fetchJWKS,
  DiscoveryCache,
} from "../src/discovery.js";

const ISSUER = "https://elevkar-auth.ssis.nu";

const mockOIDCConfig = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/api/auth/oauth2/authorize`,
  token_endpoint: `${ISSUER}/api/auth/oauth2/token`,
  userinfo_endpoint: `${ISSUER}/api/auth/oauth2/userinfo`,
  jwks_uri: `${ISSUER}/api/auth/jwks`,
  end_session_endpoint: `${ISSUER}/api/auth/oauth2/logout`,
  scopes_supported: ["openid", "profile", "email"],
  response_types_supported: ["code"],
  id_token_signing_alg_values_supported: ["RS256"],
};

const mockJWKS = {
  keys: [
    {
      kty: "RSA",
      use: "sig",
      kid: "key-1",
      alg: "RS256",
      n: "sIwr_abc123",
      e: "AQAB",
    },
  ],
};

describe("fetchOpenIDConfiguration", () => {
  beforeEach(() => { vi.restoreAllMocks(); });

  it("fetches from /.well-known/openid-configuration", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => mockOIDCConfig,
    });
    vi.stubGlobal("fetch", fetchMock);

    const cfg = await fetchOpenIDConfiguration(ISSUER);

    expect(fetchMock).toHaveBeenCalledWith(
      `${ISSUER}/.well-known/openid-configuration`,
      expect.objectContaining({ headers: { Accept: "application/json" } })
    );
    expect(cfg.issuer).toBe(ISSUER);
    expect(cfg.jwks_uri).toBe(`${ISSUER}/api/auth/jwks`);
  });

  it("strips a trailing slash from the issuer", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => mockOIDCConfig,
    });
    vi.stubGlobal("fetch", fetchMock);

    await fetchOpenIDConfiguration(ISSUER + "/");

    expect(fetchMock.mock.calls[0][0]).toBe(
      `${ISSUER}/.well-known/openid-configuration`
    );
  });

  it("throws when the response is not OK", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce({ ok: false, status: 404 })
    );
    await expect(fetchOpenIDConfiguration(ISSUER)).rejects.toThrow("404");
  });
});

describe("fetchJWKS", () => {
  beforeEach(() => { vi.restoreAllMocks(); });

  it("fetches and returns the JWKS", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => mockJWKS,
      })
    );

    const jwks = await fetchJWKS(`${ISSUER}/api/auth/jwks`);
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kid).toBe("key-1");
  });

  it("throws when the response is not OK", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce({ ok: false, status: 500 })
    );
    await expect(fetchJWKS(`${ISSUER}/api/auth/jwks`)).rejects.toThrow("500");
  });
});

describe("DiscoveryCache", () => {
  beforeEach(() => { vi.restoreAllMocks(); });

  it("fetches config once and returns cached value on second call", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockOIDCConfig,
    });
    vi.stubGlobal("fetch", fetchMock);

    const cache = new DiscoveryCache();
    await cache.getConfig(ISSUER);
    await cache.getConfig(ISSUER);

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("fetches JWKS once and returns cached value on second call", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockJWKS,
    });
    vi.stubGlobal("fetch", fetchMock);

    const cache = new DiscoveryCache();
    await cache.getJWKS(`${ISSUER}/api/auth/jwks`);
    await cache.getJWKS(`${ISSUER}/api/auth/jwks`);

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("re-fetches after invalidate()", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockOIDCConfig,
    });
    vi.stubGlobal("fetch", fetchMock);

    const cache = new DiscoveryCache();
    await cache.getConfig(ISSUER);
    cache.invalidate();
    await cache.getConfig(ISSUER);

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
