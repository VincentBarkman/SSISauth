import type { JWKSet, OIDCConfiguration } from "./types.js";

export async function fetchOpenIDConfiguration(
  issuer: string
): Promise<OIDCConfiguration> {
  const url = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    throw new Error(
      `Failed to fetch OpenID configuration (${response.status})`
    );
  }
  return response.json() as Promise<OIDCConfiguration>;
}

export async function fetchJWKS(jwksUri: string): Promise<JWKSet> {
  const response = await fetch(jwksUri, {
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch JWKS (${response.status})`);
  }
  return response.json() as Promise<JWKSet>;
}

export class DiscoveryCache {
  private _config: OIDCConfiguration | null = null;
  private _jwks: JWKSet | null = null;

  async getConfig(issuer: string): Promise<OIDCConfiguration> {
    if (!this._config) {
      this._config = await fetchOpenIDConfiguration(issuer);
    }
    return this._config;
  }

  async getJWKS(jwksUri: string): Promise<JWKSet> {
    if (!this._jwks) {
      this._jwks = await fetchJWKS(jwksUri);
    }
    return this._jwks;
  }

  invalidate(): void {
    this._config = null;
    this._jwks = null;
  }
}
