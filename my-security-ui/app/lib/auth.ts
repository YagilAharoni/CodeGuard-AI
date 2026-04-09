export interface StoredUser {
  id: number;
  username: string;
}

interface StoredAuth {
  token: string;
  expiresAt: number;
}

const USER_KEY = "codeguard_user";
const AUTH_KEY = "codeguard_auth";
const SESSION_API_KEY_STORAGE_KEY = "codeguard_session_api_key";
const hasWindow = () => typeof window !== "undefined";

export const saveAuthSession = (token: string, expiresInSeconds: number, user: StoredUser) => {
  if (!hasWindow()) return;
  const expiresAt = Date.now() + expiresInSeconds * 1000;
  const auth: StoredAuth = { token, expiresAt };
  localStorage.setItem(USER_KEY, JSON.stringify(user));
  localStorage.setItem(AUTH_KEY, JSON.stringify(auth));
};

export const clearAuthSession = () => {
  if (!hasWindow()) return;
  localStorage.removeItem(USER_KEY);
  localStorage.removeItem(AUTH_KEY);
  sessionStorage.removeItem(SESSION_API_KEY_STORAGE_KEY);
};

export const getStoredUser = (): StoredUser | null => {
  if (!hasWindow()) return null;
  try {
    const raw = localStorage.getItem(USER_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<StoredUser>;
    if (!parsed.username || typeof parsed.id !== "number") return null;
    return { id: parsed.id, username: parsed.username };
  } catch {
    return null;
  }
};

export const getAuthToken = (): string | null => {
  if (!hasWindow()) return null;
  try {
    const raw = localStorage.getItem(AUTH_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<StoredAuth>;
    if (!parsed.token || typeof parsed.expiresAt !== "number") return null;

    if (Date.now() > parsed.expiresAt) {
      clearAuthSession();
      return null;
    }

    return parsed.token;
  } catch {
    return null;
  }
};

export const getAuthHeaders = (): Record<string, string> => {
  const token = getAuthToken();
  if (!token) return {};
  return { Authorization: `Bearer ${token}` };
};

export const isAuthenticated = (): boolean => Boolean(getAuthToken() && getStoredUser());
