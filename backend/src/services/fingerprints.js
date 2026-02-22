// Shared normalization + identity logic used by aiRead cross-checking.
// These helpers make model outputs comparable and dedupe-stable.

export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
export const CATEGORY_ORDER = [
  "Patching",
  "Hardening",
  "Cryptography",
  "Authentication",
  "Exposure",
  "Application",
  "Disclosure",
  "Malware",
  "Compliance",
  "Other",
];
const CATEGORY_BY_KEY = new Map(
  CATEGORY_ORDER.map((category) => [category.toUpperCase(), category])
);

export const asStringOrNull = (value) => {
  if (value === undefined || value === null) {
    return null;
  }

  const normalized = String(value).trim();
  return normalized.length > 0 ? normalized : null;
};

export const asNumberOrNull = (value) => {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  const numericValue = Number(value);
  return Number.isFinite(numericValue) ? numericValue : null;
};

export const normalizeSeverity = (value) => {
  const severity = asStringOrNull(value);
  if (!severity) {
    return null;
  }

  const upper = severity.toUpperCase();
  return upper === "INFORMATIONAL" ? "INFO" : upper;
};

export const normalizeName = (value) => {
  const name = asStringOrNull(value);
  if (!name) {
    return null;
  }
  return name.normalize("NFKC").replace(/\s+/g, " ").trim();
};

export const normalizeCategory = (value) => {
  const category = asStringOrNull(value);
  if (!category) {
    return "Other";
  }
  return CATEGORY_BY_KEY.get(category.toUpperCase()) || "Other";
};

const toStableIdentityRecord = (item) => {
  return {
    host: asStringOrNull(item?.host),
    pluginId: asStringOrNull(item?.pluginId),
    severity: normalizeSeverity(item?.severity),
    usn: asStringOrNull(item?.usn),
    name: normalizeName(item?.name),
  };
};

const makeStableIdentityKey = (item) => {
  const record = toStableIdentityRecord(item);
  return [
    record.host || "",
    record.pluginId || "",
    record.severity || "",
    record.usn || "",
    record.name || "",
  ].join("|");
};

const makeFingerprint = (item) => makeStableIdentityKey(item);

const makeSoftFingerprint = (item) => {
  const host = asStringOrNull(item?.host) || "";
  const pluginId = asStringOrNull(item?.pluginId);
  const severity = normalizeSeverity(item?.severity) || "";
  const usn = asStringOrNull(item?.usn) || "";
  const normalizedName = normalizeName(item?.name) || "";

  if (pluginId) {
    return [host, pluginId, severity, usn].join("|");
  }
  return [host, severity, usn, normalizedName].join("|");
};

export const dedupeByFingerprint = (items) => {
  const seen = new Set();
  const deduped = [];

  for (const item of items) {
    const fingerprint = makeFingerprint(item);
    if (!seen.has(fingerprint)) {
      seen.add(fingerprint);
      deduped.push(item);
    }
  }

  return deduped;
};

export const dedupeBySoftFingerprint = (items) => {
  const seen = new Set();
  const deduped = [];

  for (const item of items) {
    const fingerprint = makeSoftFingerprint(item);
    if (!seen.has(fingerprint)) {
      seen.add(fingerprint);
      deduped.push(item);
    }
  }

  return deduped;
};

// Converts model output into strict schema used by database/output files.
export const normalizeVulnerabilityOutput = (rawAnalysis, reportId) => {
  const sourceItems = Array.isArray(rawAnalysis)
    ? rawAnalysis
    : Array.isArray(rawAnalysis?.vulnerabilities)
    ? rawAnalysis.vulnerabilities
    : [];

  return {
    vulnerabilities: sourceItems.map((item) => ({
      _id: null,
      reportId: asStringOrNull(item?.reportId) || reportId,
      host: asStringOrNull(item?.host),
      severity: normalizeSeverity(item?.severity),
      cvssV3: asNumberOrNull(item?.cvssV3 ?? item?.cvss),
      vpr: asNumberOrNull(item?.vpr),
      epss: asNumberOrNull(item?.epss),
      pluginId: asStringOrNull(item?.pluginId),
      name: normalizeName(item?.name),
      usn: asStringOrNull(item?.usn),
      category: normalizeCategory(item?.category),
    })),
  };
};

export const countBySeverity = (items) => {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((severity) => [severity, 0]));

  for (const item of items) {
    const severity = normalizeSeverity(item?.severity);
    if (severity && Object.prototype.hasOwnProperty.call(counts, severity)) {
      counts[severity] += 1;
    }
  }

  return counts;
};

// Canonical comparison payload used to decide if two model responses agree.
export const canonicalizeChunkItems = (items) =>
  JSON.stringify(
    dedupeByFingerprint(items)
      .map((item) => toStableIdentityRecord(item))
      .sort((a, b) => makeStableIdentityKey(a).localeCompare(makeStableIdentityKey(b)))
  );

export default {
  SEVERITY_ORDER,
  CATEGORY_ORDER,
  asStringOrNull,
  asNumberOrNull,
  normalizeSeverity,
  normalizeName,
  normalizeCategory,
  normalizeVulnerabilityOutput,
  dedupeByFingerprint,
  dedupeBySoftFingerprint,
  countBySeverity,
  canonicalizeChunkItems,
};
