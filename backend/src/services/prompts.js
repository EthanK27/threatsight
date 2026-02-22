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

export default {
  buildGeminiPdfPrompt,
};
