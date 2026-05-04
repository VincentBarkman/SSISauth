# ssisauth

OAuth 2.1 Authorization Code + PKCE-klientbibliotek för SSIS.

## Installation

```bash
npm install @ssis/ssisauth
```


## Snabbstart

```ts
import { ssisauth } from "@ssis/ssisauth";

const auth = ssisauth({
  secrets: {
    clientId: "ditt-client-id",
    clientSecret: "din-client-secret", // valfritt för publika klienter (stable version)
  },
  scopes: ["openid", "profile", "email"],
  // issuer är som standard https://authentication-git-authentication.apps.okd.ssis.nu (beta)
});

// Anropas en gång vid sidladdning — hanterar OAuth-återanropet automatiskt
await auth.initialize();

// Omdirigera användaren till inloggningssidan
auth.signin();

// Läs den aktiva sessionen (null om inte inloggad)
const session = auth.useSession;
console.log(session?.user?.email);

// Logga ut användaren (rensar sessionen och omdirigerar till utloggningsendpunkten)
auth.logout();
```

## API

### `ssisauth(config)`

Skapar en autentiseringsinstans.

| Alternativ | Typ | Obligatorisk | Standard |
|---|---|---|---|
| `secrets.clientId` | `string` | ✅ | — |
| `secrets.clientSecret` | `string` | ❌ | — |
| `scopes` | `string[]` | ❌ | `["openid", "profile", "email"]` |
| `issuer` | `string` | ❌ | SSIS issuer-URL |
| `redirectUri` | `string` | ❌ | aktuell sid-URL |
| `discover` | `boolean` | ❌ | `true` — hämtar endpunkter automatiskt via OIDC-konfigurationen |
| `verifyTokens` | `boolean` | ❌ | `false` — kryptografisk verifiering av id_token via JWKS |

### `auth.initialize(): Promise<void>`

Måste anropas vid sidladdning. Identifierar ett OAuth-återanrop (`?code=…&state=…`), byter koden mot tokens, sparar sessionen och rensar URL:en.

### `auth.signin(options?): void`

Genererar PKCE-parametrar och omdirigerar till auktoriseringsendpunkten.

| Alternativ | Typ | Standard |
|---|---|---|
| `options.redirectUri` | `string` | aktuell sid-URL |

### `auth.useSession`

Getter — returnerar den aktuella `Session` från `localStorage`, eller `null` om användaren inte är inloggad eller om sessionen har gått ut.

```ts
interface Session {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  tokenType: string;
  expiresAt: number;   // epoch ms
  scope?: string;
  user?: UserInfo;
}
```

### `auth.logout(options?): void`

Rensar den lokala sessionen och omdirigerar till utloggningsendpunkten.

| Alternativ | Typ | Standard |
|---|---|---|
| `options.redirectTo` | `string` | `window.location.origin` |

### `auth.getUser(): Promise<UserInfo | null>`

Returnerar användaren från den sparade sessionen. Om sessionen saknar cachad användarinfo hämtas den från `/userinfo`-endpunkten.

### `auth.getOpenIDConfiguration(): Promise<OIDCConfiguration>`

Hämtar och cachar OpenID Connect-konfigurationsdokumentet från `/.well-known/openid-configuration`. Returnerar all leverantörsmetadata inklusive stödda scopes, algoritmer och endpunkt-URL:er.

### `auth.getJWKS(): Promise<JWKSet>`

Hämtar och cachar leverantörens publika nycklar från JWKS-endpunkten (`/api/auth/jwks`). Nycklarna används för verifiering av id_token.

### `auth.verifyToken(token: string): Promise<JWTClaims>`

Verifierar kryptografiskt en JWT (RS256) med hjälp av leverantörens JWKS-nycklar. Validerar signaturen, utgångstid (`exp`), giltighetstid från (`nbf`), issuer och audience.

```ts
const claims = await auth.verifyToken(session.idToken!);
console.log(claims.sub, claims.email);
```

## Utveckling

```bash
npm install
npm run build       # kompilera till dist/
npm run test        # kör tester i bevakningsläge
npm run test:run    # kör tester en gång
npm run typecheck   # typkontroll utan att emittera filer
```

## OAuth-endpunkter (standard-issuer)

| Endpunkt | URL |
|---|---|
| Auktorisering | `/api/auth/oauth2/authorize` |
| Token | `/api/auth/oauth2/token` |
| Användarinfo | `/api/auth/oauth2/userinfo` |
| Utloggning | `/api/auth/oauth2/logout` |
| JWKS | `/api/auth/jwks` |
| OpenID-konfiguration | `/.well-known/openid-configuration` |
