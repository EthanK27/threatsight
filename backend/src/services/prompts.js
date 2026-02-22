export const THREAT_CATEGORIES = [
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

// Prompt used for per-page extraction in aiRead.
// The lane tag ("primary"/"secondary") helps cross-check traceability.
export const buildGeminiPdfPrompt = ({
  reportId = "Report1",
  pageNumber = null,
  pageCount = null,
  lane = "primary",
}) => `
You are a vulnerability extraction engine.
Analyze the attached single-page PDF and return only valid JSON.

Context:
- sourcePage: ${pageNumber || "unknown"}
- totalPages: ${pageCount || "unknown"}
- lane: ${lane}

Rules:
1) Return JSON only (no markdown, no code fences, no commentary).
2) Return this exact top-level shape: { "vulnerabilities": [ ... ] }.
3) Each vulnerability item must contain only these fields:
   _id, reportId, host, severity, cvssV3, vpr, epss, pluginId, name, usn.
4) Do not invent custom IDs like "V1". Use _id as null because MongoDB will auto-assign _id.
5) Use reportId = "${reportId}" for every item.
6) If a value is not present in the page, set it to null.
7) Return all vulnerabilities visible on this single page only.
8) Ensure every string is valid JSON escaped text.

Required JSON schema:
{
  "vulnerabilities": [
    {
      "_id": null,
      "reportId": "${reportId}",
      "host": "string|null",
      "severity": "string|null",
      "cvssV3": "number|null",
      "vpr": "number|null",
      "epss": "number|null",
      "pluginId": "string|null",
      "name": "string|null",
      "usn": "string|null"
    }
  ]
}
`.trim();

// Prompt used after cross-check resolves a page to assign one category per row.
export const buildGeminiCategoryPrompt = ({
  reportId = "Report1",
  pageNumber = null,
  pageCount = null,
  items = [],
}) => {
  const rows = Array.isArray(items) ? items : [];
  const rowsForPrompt = rows.map((item, index) => ({
    index,
    host: item?.host ?? null,
    severity: item?.severity ?? null,
    pluginId: item?.pluginId ?? null,
    name: item?.name ?? null,
    usn: item?.usn ?? null,
  }));

  return `
You are a vulnerability categorization engine.
Classify each input row into exactly one threat category.

Context:
- reportId: ${reportId}
- sourcePage: ${pageNumber || "unknown"}
- totalPages: ${pageCount || "unknown"}

Allowed categories:
${THREAT_CATEGORIES.map((category) => `- ${category}`).join("\n")}

Rules:
1) Return JSON only (no markdown, no code fences, no commentary).
2) Return this exact top-level shape: { "categories": [ ... ] }.
3) Return one output row for every input row index.
4) Each output row must contain only:
   index, category.
5) category must be exactly one of the allowed categories.
6) If unsure, use "Other".
7) Do not change or skip indices.

Required JSON schema:
{
  "categories": [
    {
      "index": 0,
      "category": "Patching|Hardening|Cryptography|Authentication|Exposure|Application|Disclosure|Malware|Compliance|Other"
    }
  ]
}

Input rows:
${JSON.stringify(rowsForPrompt, null, 2)}
  `.trim();
};

export default {
  buildGeminiPdfPrompt,
  buildGeminiCategoryPrompt,
  THREAT_CATEGORIES,
};
