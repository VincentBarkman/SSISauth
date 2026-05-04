import type {
  AuthConfig,
  JWKSet,
  JWTClaims,
  OIDCConfiguration,
  Session,
  SignInOptions,
  TokenResponse,
  UserInfo,
} from "./types.js";
import {
  generateCodeChallenge,
  generateCodeVerifier,
  generateState,
} from "./pkce.js";
import {
  clearPKCEState,
  clearSession,
  loadPKCEState,
  loadSession,
  savePKCEState,
  saveSession,
} from "./storage.js";
import { DiscoveryCache } from "./discovery.js";
import { verifyIdToken } from "./verify.js";

const DEFAULT_ISSUER = "https://elevkar-auth.ssis.nu";
const DEFAULT_SCOPES = ["openid", "profile", "email"];

function buildEndpoints(issuer: string) {
  const base = issuer.replace(/\/$/, "");
  return {
    authorize: `${base}/api/auth/oauth2/authorize`,
    token: `${base}/api/auth/oauth2/token`,
    userinfo: `${base}/api/auth/oauth2/userinfo`,
    endSession: `${base}/api/auth/oauth2/logout`,
    jwks: `${base}/api/auth/jwks`,
    openidConfiguration: `${base}/.well-known/openid-configuration`,
  };
}

async function exchangeCode(
  tokenUrl: string,
  params: {
    code: string;
    redirectUri: string;
    codeVerifier: string;
    clientId: string;
    clientSecret?: string;
  }
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: params.code,
    redirect_uri: params.redirectUri,
    client_id: params.clientId,
    code_verifier: params.codeVerifier,
  });

  if (params.clientSecret) {
    body.set("client_secret", params.clientSecret);
  }

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: body.toString(),
  });

  const data: TokenResponse = await response.json();

  if (!response.ok || data.error) {
    throw new Error(
      data.error_description ?? data.error ?? `Token request failed (${response.status})`
    );
  }

  return data;
}

async function fetchUserInfo(
  userinfoUrl: string,
  accessToken: string
): Promise<UserInfo> {
  const response = await fetch(userinfoUrl, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`UserInfo request failed (${response.status})`);
  }

  return response.json();
}

function decodeIdTokenPayload(idToken: string): Record<string, unknown> | null {
  try {
    const parts = idToken.split(".");
    if (parts.length < 2) return null;
    const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = payload + "=".repeat((4 - (payload.length % 4)) % 4);
    return JSON.parse(atob(padded)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function createOAuthClient(config: AuthConfig) {
  const issuer = config.issuer ?? DEFAULT_ISSUER;
  const scopes = config.scopes?.length ? config.scopes : DEFAULT_SCOPES;
  let endpoints = buildEndpoints(issuer);
  const clientId = config.secrets.clientId;
  const clientSecret = config.secrets.clientSecret;
  const discovery = new DiscoveryCache();

  let _session: Session | null = null;

  function getSession(): Session | null {
    if (_session) {
      if (_session.expiresAt < Date.now()) {
        _session = null;
        clearSession();
        return null;
      }
      return _session;
    }
    _session = loadSession();
    return _session;
  }

  async function initialize(): Promise<void> {
    if (config.discover !== false) {
      try {
        const cfg = await discovery.getConfig(issuer);
        endpoints = {
          authorize: cfg.authorization_endpoint,
          token: cfg.token_endpoint,
          userinfo: cfg.userinfo_endpoint,
          endSession: cfg.end_session_endpoint ?? endpoints.endSession,
          jwks: cfg.jwks_uri,
          openidConfiguration: endpoints.openidConfiguration,
        };
      } catch {
        // discovery failed — fall back to static endpoints
      }
    }

    const url = new URL(window.location.href);
    const code = url.searchParams.get("code");
    const returnedState = url.searchParams.get("state");
    const error = url.searchParams.get("error");

    if (error) {
      const desc = url.searchParams.get("error_description") ?? error;
      clearPKCEState();
      throw new Error(`OAuth error: ${desc}`);
    }

    if (!code) {
      _session = loadSession();
      return;
    }

    const pkce = loadPKCEState();
    if (!pkce) {
      throw new Error("No PKCE state found; cannot complete authorization.");
    }

    if (returnedState !== pkce.state) {
      clearPKCEState();
      throw new Error("State mismatch — possible CSRF attack.");
    }

    clearPKCEState();

    const tokens = await exchangeCode(endpoints.token, {
      code,
      redirectUri: pkce.redirectUri,
      codeVerifier: pkce.codeVerifier,
      clientId,
      clientSecret,
    });

    const expiresAt =
      Date.now() + (tokens.expires_in ?? 3600) * 1000;

    let user: UserInfo | undefined;

    if (tokens.id_token) {
      if (config.verifyTokens) {
        const jwks = await discovery.getJWKS(endpoints.jwks);
        const claims = await verifyIdToken(tokens.id_token, jwks, {
          issuer,
          audience: clientId,
        });
        user = claims as UserInfo;
      } else {
        const claims = decodeIdTokenPayload(tokens.id_token);
        if (claims) user = claims as UserInfo;
      }
    }

    if (!user) {
      try {
        user = await fetchUserInfo(endpoints.userinfo, tokens.access_token);
      } catch {
        // userinfo is optional
      }
    }

    _session = {
      accessToken: tokens.access_token,
      idToken: tokens.id_token,
      refreshToken: tokens.refresh_token,
      tokenType: tokens.token_type,
      expiresAt,
      scope: tokens.scope,
      user,
    };

    saveSession(_session);

    const clean = new URL(window.location.href);
    clean.searchParams.delete("code");
    clean.searchParams.delete("state");
    clean.searchParams.delete("session_state");
    window.history.replaceState({}, "", clean.toString());
  }

  async function signin(options?: SignInOptions): Promise<void> {
    const redirectUri =
      options?.redirectUri ??
      config.redirectUri ??
      window.location.origin + window.location.pathname;

    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    const state = generateState();

    savePKCEState({ codeVerifier, state, redirectUri });

    const params = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scopes.join(" "),
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });

    window.location.href = `${endpoints.authorize}?${params.toString()}`;
  }

  function logout(options?: { redirectTo?: string }): void {
    _session = null;
    clearSession();
    clearPKCEState();

    const redirectTo = options?.redirectTo ?? window.location.origin;

    const params = new URLSearchParams({
      post_logout_redirect_uri: redirectTo,
    });

    window.location.href = `${endpoints.endSession}?${params.toString()}`;
  }

  async function getUser(): Promise<UserInfo | null> {
    const session = getSession();
    if (!session) return null;
    if (session.user) return session.user;

    try {
      const user = await fetchUserInfo(endpoints.userinfo, session.accessToken);
      _session = { ...session, user };
      saveSession(_session);
      return user;
    } catch {
      return null;
    }
  }

  async function getOpenIDConfiguration(): Promise<OIDCConfiguration> {
    return discovery.getConfig(issuer);
  }

  async function getJWKS(): Promise<JWKSet> {
    return discovery.getJWKS(endpoints.jwks);
  }

  async function verifyToken(token: string): Promise<JWTClaims> {
    const jwks = await getJWKS();
    return verifyIdToken(token, jwks, { issuer, audience: clientId });
  }

  return {
    initialize,
    signin,
    logout,
    getUser,
    getOpenIDConfiguration,
    getJWKS,
    verifyToken,
    get useSession() {
      return getSession();
    },
  };
}
