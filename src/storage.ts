import type { Session, PKCEState } from "./types.js";

const SESSION_KEY = "ssisauth:session";
const PKCE_KEY = "ssisauth:pkce";

export function saveSession(session: Session): void {
  localStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function loadSession(): Session | null {
  const raw = localStorage.getItem(SESSION_KEY);
  if (!raw) return null;
  try {
    const session = JSON.parse(raw) as Session;
    if (session.expiresAt < Date.now()) {
      clearSession();
      return null;
    }
    return session;
  } catch {
    clearSession();
    return null;
  }
}

export function clearSession(): void {
  localStorage.removeItem(SESSION_KEY);
}

export function savePKCEState(state: PKCEState): void {
  sessionStorage.setItem(PKCE_KEY, JSON.stringify(state));
}

export function loadPKCEState(): PKCEState | null {
  const raw = sessionStorage.getItem(PKCE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as PKCEState;
  } catch {
    return null;
  }
}

export function clearPKCEState(): void {
  sessionStorage.removeItem(PKCE_KEY);
}
