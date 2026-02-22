import { apiFetch, buildApiUrl } from "./client";

export const fetchAllHoneypotItems = async () => {
  return apiFetch("/api/reports/honeypot/items");
};

export const getHoneypotStreamUrl = (limit = 250) => {
  const safeLimit = Math.min(Math.max(Number(limit) || 250, 10), 1500);
  return buildApiUrl(`/api/reports/honeypot/stream?limit=${safeLimit}`);
};
