import axios from "axios";

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
const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

axios.defaults.withCredentials = true;

export const saveAuthSession = (token: string, expiresInSeconds: number, user: StoredUser) => {
  if (!hasWindow()) return;
  localStorage.setItem(USER_KEY, JSON.stringify(user));
  // Persist the token with a TTL so getAuthHeaders() can include it in API requests.
  const expiresAt = Date.now() + (expiresInSeconds || 3600) * 1000;
  localStorage.setItem(AUTH_KEY, JSON.stringify({ token, expiresAt }));
  sessionStorage.removeItem(SESSION_API_KEY_STORAGE_KEY);
};

export const clearAuthSession = () => {
  if (!hasWindow()) return;
  localStorage.removeItem(USER_KEY);
  localStorage.removeItem(AUTH_KEY);
  sessionStorage.removeItem(SESSION_API_KEY_STORAGE_KEY);
};

export const logoutSession = async (): Promise<void> => {
  if (!hasWindow()) {
    return;
  }

  try {
    await axios.post(`${API_BASE}/api/logout`, {});
  } catch {
    // Best-effort logout: local state still gets cleared even if the network call fails.
  } finally {
    clearAuthSession();
  }
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

export const isAuthenticated = (): boolean => Boolean(getStoredUser());
