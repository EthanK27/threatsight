export function safeString(value) {
  if (value === null || value === undefined) return "";
  return String(value);
}

export function formatDateTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return safeString(value);
  return date.toLocaleString();
}

export function formatScore(value, digits = 1) {
  if (value === null || value === undefined || value === "") return "-";
  const num = Number(value);
  if (Number.isNaN(num)) return safeString(value);
  return num.toFixed(digits);
}