export const MAX_USERNAME_LEN = 32;
export const MAX_LOGIN_LEN = 128;
export const MAX_EMAIL_LEN = 254;
export const MAX_PASSWORD_LEN = 128;
export const MAX_API_KEY_LEN = 256;
export const MAX_GITHUB_URL_LEN = 300;
export const MAX_FILES_PER_SCAN = 20;

const USERNAME_PATTERN = /^[A-Za-z0-9_.-]{3,32}$/;
const EMAIL_PATTERN = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const normalizeText = (value: string, maxLen: number): string => value.trim().slice(0, maxLen);

export const validateUsername = (value: string): string | null => {
  const normalized = normalizeText(value, MAX_USERNAME_LEN);
  if (!USERNAME_PATTERN.test(normalized)) {
    return "Username must be 3-32 chars and use letters, numbers, ., _, or -.";
  }
  return null;
};

export const validateEmail = (value: string): string | null => {
  const normalized = normalizeText(value, MAX_EMAIL_LEN).toLowerCase();
  if (!EMAIL_PATTERN.test(normalized)) {
    return "Invalid email format.";
  }
  return null;
};

export const validateLoginField = (value: string): string | null => {
  const normalized = normalizeText(value, MAX_LOGIN_LEN);
  if (!normalized) {
    return "Login is required.";
  }
  return null;
};

export const validatePassword = (value: string): string | null => {
  const normalized = value.slice(0, MAX_PASSWORD_LEN);
  if (normalized.length < 8) {
    return "Password must be at least 8 characters.";
  }
  return null;
};

export const validateApiKey = (value: string): string | null => {
  const normalized = value.trim();
  if (!normalized) return null;
  if (normalized.length > MAX_API_KEY_LEN) {
    return "API key is too long.";
  }
  if (/\s/.test(normalized)) {
    return "API key must not contain spaces.";
  }
  return null;
};

export const validateGithubUrl = (value: string): string | null => {
  const normalized = normalizeText(value, MAX_GITHUB_URL_LEN);
  if (!normalized) {
    return "GitHub URL is required.";
  }
  try {
    const parsed = new URL(normalized);
    const host = parsed.hostname.toLowerCase();
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "GitHub URL must start with http:// or https://.";
    }
    if (host !== "github.com" && host !== "www.github.com") {
      return "Only github.com URLs are supported.";
    }
    const parts = parsed.pathname.split("/").filter(Boolean);
    if (parts.length < 2) {
      return "GitHub URL must include owner and repository.";
    }
    return null;
  } catch {
    return "Invalid GitHub URL.";
  }
};

export const validateScanId = (value: string): boolean => UUID_PATTERN.test((value || "").trim());

export const sanitizeQueryText = (value: string): string => value.replace(/[\x00-\x1F\x7F]/g, "").slice(0, 100);
