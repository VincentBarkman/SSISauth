export interface AuthSecrets {
  clientId: string;
  clientSecret?: string;
}

export interface AuthConfig {
  secrets: AuthSecrets;
  scopes?: string[];
  issuer?: string;
  redirectUri?: string;
  discover?: boolean;
  verifyTokens?: boolean;
}

export interface Session {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  tokenType: string;
  expiresAt: number;
  scope?: string;
  user?: UserInfo;
}

export interface UserInfo {
  sub: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
  picture?: string;
  [key: string]: unknown;
}

export interface TokenResponse {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  token_type: string;
  expires_in?: number;
  scope?: string;
  error?: string;
  error_description?: string;
}

export interface PKCEState {
  codeVerifier: string;
  state: string;
  redirectUri: string;
}

export interface OIDCConfiguration {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  grant_types_supported?: string[];
  subject_types_supported?: string[];
  id_token_signing_alg_values_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
}

export interface JWK {
  kty: string;
  use?: string;
  kid?: string;
  alg?: string;
  n?: string;
  e?: string;
  x5c?: string[];
  [key: string]: unknown;
}

export interface JWKSet {
  keys: JWK[];
}

export interface JWTClaims {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  email?: string;
  name?: string;
  [key: string]: unknown;
}

export interface AuthInstance {
  initialize(): Promise<void>;
  signin(options?: SignInOptions): void;
  logout(options?: LogoutOptions): void;
  readonly useSession: Session | null;
  getUser(): Promise<UserInfo | null>;
  getOpenIDConfiguration(): Promise<OIDCConfiguration>;
  getJWKS(): Promise<JWKSet>;
  verifyToken(token: string): Promise<JWTClaims>;
}

export interface SignInOptions {
  redirectUri?: string;
}

export interface LogoutOptions {
  redirectTo?: string;
}
