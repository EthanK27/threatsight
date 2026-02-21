import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BACKEND_ROOT = path.resolve(__dirname, "..", "..");

dotenv.config({ path: path.join(BACKEND_ROOT, ".env") });

const UPLOADS_DIR = path.join(BACKEND_ROOT, "temp", "uploads");
const OUTPUTS_DIR = path.join(BACKEND_ROOT, "outputs");
const GEMINI_API_BASE_URL =
  process.env.GEMINI_API_BASE_URL ||
  "https://generativelanguage.googleapis.com/v1beta";
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";
const REQUEST_TIMEOUT_MS = Number(process.env.GEMINI_REQUEST_TIMEOUT_MS || 240000);
const CHUNK_SIZE = Number(process.env.GEMINI_CHUNK_SIZE || 20);
const MAX_CHUNK_PASSES = Number(process.env.GEMINI_MAX_CHUNK_PASSES || 8);
const MAX_OUTPUT_TOKENS = Number(process.env.GEMINI_MAX_OUTPUT_TOKENS || 4096);
const THINKING_BUDGET = Number(process.env.GEMINI_THINKING_BUDGET || 0);
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const asStringOrNull = (value) => {
  if (value === undefined || value === null) {
    return null;
  }

  const normalized = String(value).trim();
  return normalized.length > 0 ? normalized : null;
};

const asNumberOrNull = (value) => {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  const numericValue = Number(value);
  return Number.isFinite(numericValue) ? numericValue : null;
};

export const buildGeminiPdfPrompt = (reportId = "Report1") => `
You are a vulnerability extraction engine.
Analyze the attached PDF and return only valid JSON.

Rules:
1) Return JSON only (no markdown, no code fences, no commentary).
2) Return this exact top-level shape: { "vulnerabilities": [ ... ] }.
3) Each vulnerability item must contain only these fields:
   _id, reportId, host, severity, cvssV3, vpr, epss, pluginId, name, usn.
4) Do not invent custom IDs like "V1". Use _id as null because MongoDB will auto-assign _id.
5) Use reportId = "${reportId}" for every item.
6) If a value is not present in the PDF, set it to null.

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

const buildGeminiChunkPrompt = ({
  reportId = "Report1",
  severity,
  limit = CHUNK_SIZE,
  excluded = [],
}) => `
You are a vulnerability extraction engine.
Analyze the attached PDF and return only valid JSON.

Rules:
1) Return JSON only (no markdown, no code fences, no commentary).
2) Return this exact top-level shape: { "vulnerabilities": [ ... ] }.
3) Each vulnerability item must contain only these fields:
   _id, reportId, host, severity, cvssV3, vpr, epss, pluginId, name, usn.
4) Do not invent custom IDs like "V1". Use _id as null because MongoDB will auto-assign _id.
5) Use reportId = "${reportId}" for every item.
6) If a value is not present in the PDF, set it to null.
7) Return at most ${limit} vulnerabilities.
8) Sort output by host (asc), pluginId (asc), name (asc), usn (asc).
9) Include only severity "${severity}" vulnerabilities.
10) Ensure every string is valid JSON escaped text.
11) Exclude any vulnerability with fingerprint in this list (host|pluginId|name|usn|severity):
${excluded.length > 0 ? excluded.map((item) => `- ${item}`).join("\n") : "- none"}

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

const extractJson = (rawText) => {
  const trimmed = (rawText || "").trim();

  if (!trimmed) {
    throw new Error("Gemini returned an empty response.");
  }

  const fencedMatch = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  const candidate = fencedMatch ? fencedMatch[1].trim() : trimmed;

  try {
    return JSON.parse(candidate);
  } catch {
    const firstBrace = candidate.indexOf("{");
    const lastBrace = candidate.lastIndexOf("}");

    if (firstBrace !== -1 && lastBrace > firstBrace) {
      const sliced = candidate.slice(firstBrace, lastBrace + 1);
      return JSON.parse(sliced);
    }

    throw new Error("Failed to parse Gemini response as JSON.");
  }
};

const normalizeSeverity = (value) => {
  const severity = asStringOrNull(value);

  if (!severity) {
    return null;
  }

  const upper = severity.toUpperCase();
  if (upper === "INFORMATIONAL") {
    return "INFO";
  }

  return upper;
};

const makeFingerprint = (item) =>
  [
    asStringOrNull(item?.host) || "",
    asStringOrNull(item?.pluginId) || "",
    asStringOrNull(item?.name) || "",
    asStringOrNull(item?.usn) || "",
    normalizeSeverity(item?.severity) || "",
  ].join("|");

const dedupeByFingerprint = (items) => {
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

const getLatestPdfPath = async (uploadsDir = UPLOADS_DIR) => {
  const entries = await fs.readdir(uploadsDir, { withFileTypes: true });
  const pdfEntries = entries.filter(
    (entry) => entry.isFile() && entry.name.toLowerCase().endsWith(".pdf")
  );

  if (pdfEntries.length === 0) {
    throw new Error(`No PDF files found in uploads directory: ${uploadsDir}`);
  }

  const withStats = await Promise.all(
    pdfEntries.map(async (entry) => {
      const fullPath = path.join(uploadsDir, entry.name);
      const stats = await fs.stat(fullPath);
      return { fullPath, mtimeMs: stats.mtimeMs };
    })
  );

  withStats.sort((a, b) => b.mtimeMs - a.mtimeMs);
  return withStats[0].fullPath;
};

const normalizeVulnerabilityOutput = (rawAnalysis, reportId) => {
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
      severity: asStringOrNull(item?.severity),
      cvssV3: asNumberOrNull(item?.cvssV3 ?? item?.cvss),
      vpr: asNumberOrNull(item?.vpr),
      epss: asNumberOrNull(item?.epss),
      pluginId: asStringOrNull(item?.pluginId),
      name: asStringOrNull(item?.name),
      usn: asStringOrNull(item?.usn),
    })),
  };
};

const callGeminiForPdf = async (pdfPath, prompt, maxOutputTokens = MAX_OUTPUT_TOKENS) => {
  const apiKey = process.env.GEMINI_API_KEY?.trim();

  if (!apiKey) {
    throw new Error("Missing GEMINI_API_KEY in backend/.env.");
  }

  const pdfBuffer = await fs.readFile(pdfPath);
  const endpoint =
    `${GEMINI_API_BASE_URL}/models/${encodeURIComponent(GEMINI_MODEL)}` +
    `:generateContent?key=${encodeURIComponent(apiKey)}`;

  const payload = {
    contents: [
      {
        role: "user",
        parts: [
          { text: prompt },
          {
            inlineData: {
              mimeType: "application/pdf",
              data: pdfBuffer.toString("base64"),
            },
          },
        ],
      },
    ],
    generationConfig: {
      responseMimeType: "application/json",
      temperature: 0,
    },
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let response;

  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...payload,
        generationConfig: {
          ...payload.generationConfig,
          maxOutputTokens,
          thinkingConfig: {
            thinkingBudget: THINKING_BUDGET,
          },
        },
      }),
      signal: controller.signal,
    });
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error(`Gemini API request timed out after ${REQUEST_TIMEOUT_MS}ms.`);
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(
      `Gemini API request failed (${response.status}): ${errorText}`
    );
  }

  const data = await response.json();
  const text = data?.candidates?.[0]?.content?.parts
    ?.map((part) => part?.text)
    .filter(Boolean)
    .join("\n")
    .trim();

  if (!text) {
    throw new Error("Gemini did not return text content in the first candidate.");
  }

  const finishReason = data?.candidates?.[0]?.finishReason || null;

  return {
    analysis: extractJson(text),
    finishReason,
  };
};

const extractInChunks = async (pdfPath, reportId) => {
  const aggregated = [];
  let totalCalls = 0;

  for (const severity of SEVERITY_ORDER) {
    let batchSize = CHUNK_SIZE;

    for (let pass = 0; pass < MAX_CHUNK_PASSES; pass += 1) {
      totalCalls += 1;
      const excludedFingerprints = aggregated
        .filter((item) => normalizeSeverity(item?.severity) === severity)
        .map(makeFingerprint)
        .slice(-200);
      const prompt = buildGeminiChunkPrompt({
        reportId,
        severity,
        limit: batchSize,
        excluded: excludedFingerprints,
      });

      let response;
      try {
        response = await callGeminiForPdf(pdfPath, prompt);
      } catch (error) {
        const isJsonSyntaxError = error instanceof SyntaxError;

        if (
          (isJsonSyntaxError ||
            /Failed to parse Gemini response as JSON|Expected .* in JSON|Unterminated string in JSON/.test(
            String(error?.message || "")
          )) &&
          batchSize > 5
        ) {
          batchSize = Math.max(5, Math.floor(batchSize / 2));
          continue;
        }

        throw error;
      }

      const normalized = normalizeVulnerabilityOutput(response.analysis, reportId);
      const severityItems = normalized.vulnerabilities.filter(
        (item) => normalizeSeverity(item?.severity) === severity
      );
      const before = aggregated.length;
      aggregated.push(...severityItems);
      const deduped = dedupeByFingerprint(aggregated);
      aggregated.length = 0;
      aggregated.push(...deduped);
      const addedCount = aggregated.length - before;

      if (addedCount === 0) {
        break;
      }

      if (response.finishReason === "MAX_TOKENS" && batchSize > 5) {
        batchSize = Math.max(5, Math.floor(batchSize / 2));
        continue;
      }

      if (severityItems.length < batchSize) {
        break;
      }
    }
  }

  return {
    vulnerabilities: aggregated,
    meta: {
      totalCalls,
    },
  };
};

const writeOutputJson = async (pdfPath, analysis, outputsDir = OUTPUTS_DIR) => {
  await fs.mkdir(outputsDir, { recursive: true });

  const source = path.parse(pdfPath).name;
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outputPath = path.join(outputsDir, `${source}-${timestamp}.json`);

  await fs.writeFile(outputPath, JSON.stringify(analysis, null, 2), "utf8");
  return outputPath;
};

export const analyzePdfToJson = async (pdfPath, reportId = "Report1") => {
  const resolvedPdfPath = pdfPath
    ? path.resolve(pdfPath)
    : await getLatestPdfPath(UPLOADS_DIR);

  const rawAnalysis = await extractInChunks(resolvedPdfPath, reportId);
  const analysis = normalizeVulnerabilityOutput(rawAnalysis, reportId);
  const outputPath = await writeOutputJson(resolvedPdfPath, analysis, OUTPUTS_DIR);

  return {
    pdfPath: resolvedPdfPath,
    outputPath,
    analysis,
  };
};

export default {
  analyzePdfToJson,
  buildGeminiPdfPrompt,
};
