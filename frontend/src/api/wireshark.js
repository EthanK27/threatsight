import { apiFetch } from "./client";

export const fetchAllWiresharkItems = async () => {
  return apiFetch("/api/reports/wireshark/items");
};
