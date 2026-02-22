export const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info", "None", "Unknown"];

const SEVERITY_LABEL_MAP = {
  "4": "Critical",
  "3": "High",
  "2": "Medium",
  "1": "Low",
  "0": "Info",
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
  informational: "Info",
  none: "None",
  unknown: "Unknown",
};

export const SEVERITY_COLORS = {
  Critical: "#dc2626",
  High: "#ea580c",
  Medium: "#ca8a04",
  Low: "#0284c7",
  Info: "#16a34a",
  None: "#94a3b8",
  Unknown: "#64748b",
};

export function normalizeSeverity(value) {
  if (value === null || value === undefined) return "Unknown";
  const raw = String(value).trim();
  if (!raw) return "Unknown";

  const mapped = SEVERITY_LABEL_MAP[raw.toLowerCase()];
  if (mapped) return mapped;

  return raw.charAt(0).toUpperCase() + raw.slice(1);
}

export function severityRank(value) {
  const label = normalizeSeverity(value);
  const idx = SEVERITY_ORDER.indexOf(label);
  return idx === -1 ? SEVERITY_ORDER.length : idx;
}

export function severityColor(value) {
  return SEVERITY_COLORS[normalizeSeverity(value)] || SEVERITY_COLORS.Unknown;
}