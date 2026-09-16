// ADR-0031 decision 1: the access token lives in this module's memory and nowhere else —
// never localStorage, sessionStorage or a cookie. A full page load starts with no token,
// by design, so navigation between the two pages is client-side only.
let accessToken: string | null = null;
let lastProjectId = "";

export function getAccessToken(): string | null {
  return accessToken;
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function getLastProjectId(): string {
  return lastProjectId;
}

export function setLastProjectId(projectId: string): void {
  lastProjectId = projectId;
}
