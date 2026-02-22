import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import { PDFDocument } from "pdf-lib";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BACKEND_ROOT = path.resolve(__dirname, "..", "..");

dotenv.config({ path: path.join(BACKEND_ROOT, ".env") });

const UPLOADS_DIR = path.join(BACKEND_ROOT, "temp", "uploads");
const OUTPUTS_DIR = path.join(BACKEND_ROOT, "outputs");
const TEMP_OUTPUTS_DIR = path.join(BACKEND_ROOT, "temp", "outputs");
const GEMINI_API_BASE_URL =
  process.env.GEMINI_API_BASE_URL ||
  "https://generativelanguage.googleapis.com/v1beta";
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";
const REQUEST_TIMEOUT_MS = Number(process.env.GEMINI_REQUEST_TIMEOUT_MS || 240000);
const CHUNK_COMPARE_RETRIES = Math.max(
  1,
  Number(process.env.GEMINI_CHUNK_COMPARE_RETRIES || 3)
);
const MAX_OUTPUT_TOKENS = Number(process.env.GEMINI_MAX_OUTPUT_TOKENS || 8192);
const THINKING_BUDGET = Number(process.env.GEMINI_THINKING_BUDGET || 0);
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const APPLY_SOFT_DEDUPE_TO_FINAL_OUTPUT =
  String(process.env.APPLY_SOFT_DEDUPE_TO_FINAL_OUTPUT || "false").toLowerCase() ===
  "true";

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

const normalizeName = (value) => {
  const name = asStringOrNull(value);

  if (!name) {
    return null;
  }

  return name.normalize("NFKC").replace(/\s+/g, " ").trim();
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

const dedupeBySoftFingerprint = (items) => {
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

const countBySeverity = (items) => {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((severity) => [severity, 0]));

  for (const item of items) {
    const severity = normalizeSeverity(item?.severity);
    if (severity && Object.prototype.hasOwnProperty.call(counts, severity)) {
      counts[severity] += 1;
    }
  }

  return counts;
};

const canonicalizeChunkItems = (items) =>
  JSON.stringify(
    dedupeByFingerprint(items)
      .map((item) => toStableIdentityRecord(item))
      .sort((a, b) =>
        makeStableIdentityKey(a).localeCompare(makeStableIdentityKey(b))
      )
  );

const buildGeminiPdfPrompt = ({
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
      severity: normalizeSeverity(item?.severity),
      cvssV3: asNumberOrNull(item?.cvssV3 ?? item?.cvss),
      vpr: asNumberOrNull(item?.vpr),
      epss: asNumberOrNull(item?.epss),
      pluginId: asStringOrNull(item?.pluginId),
      name: normalizeName(item?.name),
      usn: asStringOrNull(item?.usn),
    })),
  };
};

const callGeminiForPdf = async (
  pdfBase64,
  prompt,
  maxOutputTokens = MAX_OUTPUT_TOKENS
) => {
  const apiKey = process.env.GEMINI_API_KEY?.trim();

  if (!apiKey) {
    throw new Error("Missing GEMINI_API_KEY in backend/.env.");
  }

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
              data: pdfBase64,
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

const writeOutputJson = async (pdfPath, analysis, outputsDir = OUTPUTS_DIR) => {
  await fs.mkdir(outputsDir, { recursive: true });

  const source = path.parse(pdfPath).name;
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outputPath = path.join(outputsDir, `${source}-${timestamp}-paged.json`);

  await fs.writeFile(outputPath, JSON.stringify(analysis, null, 2), "utf8");
  return outputPath;
};

const buildCrossCheckOutputPaths = (pdfPath, outputsDir = TEMP_OUTPUTS_DIR) => {
  const source = path.parse(pdfPath).name;
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

  return {
    primaryPath: path.join(outputsDir, `${source}-${timestamp}-crosscheck-a.json`),
    secondaryPath: path.join(outputsDir, `${source}-${timestamp}-crosscheck-b.json`),
  };
};

const writeCrossCheckSnapshot = async (
  outputPath,
  vulnerabilities,
  reportId,
  meta
) => {
  const normalized = normalizeVulnerabilityOutput({ vulnerabilities }, reportId);
  await fs.writeFile(
    outputPath,
    JSON.stringify({ ...normalized, meta }, null, 2),
    "utf8"
  );
};

const syncCrossCheckFiles = async ({
  crossCheckPaths,
  primaryVulnerabilities,
  secondaryVulnerabilities,
  reportId,
  meta,
}) => {
  if (!crossCheckPaths) {
    return;
  }

  await Promise.all([
    writeCrossCheckSnapshot(
      crossCheckPaths.primaryPath,
      primaryVulnerabilities,
      reportId,
      { ...meta, lane: "primary" }
    ),
    writeCrossCheckSnapshot(
      crossCheckPaths.secondaryPath,
      secondaryVulnerabilities,
      reportId,
      { ...meta, lane: "secondary" }
    ),
  ]);
};

const splitPdfIntoPages = async (pdfPath) => {
  const inputBuffer = await fs.readFile(pdfPath);
  const sourcePdf = await PDFDocument.load(inputBuffer);
  const pageCount = sourcePdf.getPageCount();

  if (pageCount <= 0) {
    throw new Error(`PDF has no pages: ${pdfPath}`);
  }

  const sourceName = path.parse(pdfPath).name;
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const pagesDir = path.join(path.dirname(pdfPath), `${sourceName}-pages-${timestamp}`);
  await fs.mkdir(pagesDir, { recursive: true });

  const pagePaths = [];
  for (let index = 0; index < pageCount; index += 1) {
    const splitDoc = await PDFDocument.create();
    const [copiedPage] = await splitDoc.copyPages(sourcePdf, [index]);
    splitDoc.addPage(copiedPage);
    const splitBytes = await splitDoc.save();
    const pageNumber = String(index + 1).padStart(3, "0");
    const pageFileName = `${sourceName}-page-${pageNumber}.pdf`;
    const pagePath = path.join(pagesDir, pageFileName);
    await fs.writeFile(pagePath, Buffer.from(splitBytes));
    pagePaths.push(pagePath);
  }

  return { pageCount, pagePaths, pagesDir };
};

const resolveConsensusItems = (candidateFrequency) => {
  const countRowsWithPluginId = (items) =>
    items.reduce(
      (sum, item) => sum + (asStringOrNull(item?.pluginId) ? 1 : 0),
      0
    );

  const ranked = Array.from(candidateFrequency.values()).sort(
    (a, b) =>
      b.count - a.count ||
      b.items.length - a.items.length ||
      countRowsWithPluginId(b.items) - countRowsWithPluginId(a.items)
  );

  return ranked[0]?.items || [];
};

const extractPageWithCrossCheck = async ({
  pagePdfBase64,
  reportId,
  pageNumber,
  pageCount,
  baseline,
  crossCheckPaths,
  totalCallsRef,
}) => {
  const candidateFrequency = new Map();
  let lastPrimaryItems = [];
  let lastSecondaryItems = [];
  let sawMaxTokens = false;

  for (let attempt = 1; attempt <= CHUNK_COMPARE_RETRIES; attempt += 1) {
    const primaryPrompt = buildGeminiPdfPrompt({
      reportId,
      pageNumber,
      pageCount,
      lane: "primary",
    });
    const secondaryPrompt = buildGeminiPdfPrompt({
      reportId,
      pageNumber,
      pageCount,
      lane: "secondary",
    });

    totalCallsRef.count += 1;
    const primaryResponse = await callGeminiForPdf(pagePdfBase64, primaryPrompt);
    totalCallsRef.count += 1;
    const secondaryResponse = await callGeminiForPdf(pagePdfBase64, secondaryPrompt);

    sawMaxTokens =
      sawMaxTokens ||
      primaryResponse.finishReason === "MAX_TOKENS" ||
      secondaryResponse.finishReason === "MAX_TOKENS";

    const primaryItems = dedupeByFingerprint(
      normalizeVulnerabilityOutput(primaryResponse.analysis, reportId).vulnerabilities
    );
    const secondaryItems = dedupeByFingerprint(
      normalizeVulnerabilityOutput(secondaryResponse.analysis, reportId).vulnerabilities
    );

    lastPrimaryItems = primaryItems;
    lastSecondaryItems = secondaryItems;

    const primaryKey = canonicalizeChunkItems(primaryItems);
    const secondaryKey = canonicalizeChunkItems(secondaryItems);

    if (!candidateFrequency.has(primaryKey)) {
      candidateFrequency.set(primaryKey, {
        count: 0,
        items: primaryItems,
      });
    }
    if (!candidateFrequency.has(secondaryKey)) {
      candidateFrequency.set(secondaryKey, {
        count: 0,
        items: secondaryItems,
      });
    }

    candidateFrequency.get(primaryKey).count += 1;
    candidateFrequency.get(secondaryKey).count += 1;

    const primaryCandidate = dedupeByFingerprint([...baseline, ...primaryItems]);
    const secondaryCandidate = dedupeByFingerprint([...baseline, ...secondaryItems]);

    await syncCrossCheckFiles({
      crossCheckPaths,
      primaryVulnerabilities: primaryCandidate,
      secondaryVulnerabilities: secondaryCandidate,
      reportId,
      meta: {
        status: "cross-checking",
        page: pageNumber,
        pageCount,
        attempt,
        totalCalls: totalCallsRef.count,
        mismatchResolved: false,
      },
    });

    if (primaryKey === secondaryKey) {
      await syncCrossCheckFiles({
        crossCheckPaths,
        primaryVulnerabilities: primaryCandidate,
        secondaryVulnerabilities: secondaryCandidate,
        reportId,
        meta: {
          status: "matched",
          page: pageNumber,
          pageCount,
          attempt,
          totalCalls: totalCallsRef.count,
          mismatchResolved: false,
        },
      });

      return {
        items: primaryItems,
        mismatchResolved: false,
        sawMaxTokens,
      };
    }
  }

  const resolvedItems = resolveConsensusItems(candidateFrequency);
  const resolvedAggregated = dedupeByFingerprint([...baseline, ...resolvedItems]);

  await syncCrossCheckFiles({
    crossCheckPaths,
    primaryVulnerabilities: resolvedAggregated,
    secondaryVulnerabilities: resolvedAggregated,
    reportId,
    meta: {
      status: "mismatch-resolved",
      page: pageNumber,
      pageCount,
      attempt: CHUNK_COMPARE_RETRIES,
      totalCalls: totalCallsRef.count,
      mismatchResolved: true,
      resolvedFromPrimaryCount: lastPrimaryItems.length,
      resolvedFromSecondaryCount: lastSecondaryItems.length,
    },
  });

  return {
    items: resolvedItems,
    mismatchResolved: true,
    sawMaxTokens,
  };
};

const extractByPages = async ({ pdfPath, reportId, crossCheckPaths }) => {
  if (crossCheckPaths) {
    await fs.mkdir(path.dirname(crossCheckPaths.primaryPath), { recursive: true });
  }

  const { pageCount, pagePaths, pagesDir } = await splitPdfIntoPages(pdfPath);
  const aggregated = [];
  const totalCallsRef = { count: 0 };
  let mismatchedPagesResolved = 0;
  const pageProgress = [];

  for (let index = 0; index < pagePaths.length; index += 1) {
    const pageNumber = index + 1;
    const pagePath = pagePaths[index];
    const pageBuffer = await fs.readFile(pagePath);
    const pagePdfBase64 = pageBuffer.toString("base64");
    const before = aggregated.length;
    const callsBefore = totalCallsRef.count;

    const result = await extractPageWithCrossCheck({
      pagePdfBase64,
      reportId,
      pageNumber,
      pageCount,
      baseline: [...aggregated],
      crossCheckPaths,
      totalCallsRef,
    });

    if (result.mismatchResolved) {
      mismatchedPagesResolved += 1;
    }

    const merged = dedupeByFingerprint([...aggregated, ...result.items]);
    aggregated.length = 0;
    aggregated.push(...merged);

    pageProgress.push({
      page: pageNumber,
      pagePdf: pagePath,
      callsUsed: totalCallsRef.count - callsBefore,
      addedCount: aggregated.length - before,
      mismatchResolved: result.mismatchResolved,
      sawMaxTokens: result.sawMaxTokens,
    });
  }

  await syncCrossCheckFiles({
    crossCheckPaths,
    primaryVulnerabilities: aggregated,
    secondaryVulnerabilities: aggregated,
    reportId,
    meta: {
      status: "complete",
      page: pageCount,
      pageCount,
      totalCalls: totalCallsRef.count,
      mismatchResolved: false,
      mismatchedPagesResolved,
    },
  });

  return {
    vulnerabilities: aggregated,
    meta: {
      totalCalls: totalCallsRef.count,
      mismatchedPagesResolved,
      pageCount,
      pagesDir,
      pageProgress,
    },
  };
};

export const analyzePdfToJson = async (pdfPath, reportId = "Report1") => {
  const resolvedPdfPath = pdfPath
    ? path.resolve(pdfPath)
    : await getLatestPdfPath(UPLOADS_DIR);

  const crossCheckOutputPaths = buildCrossCheckOutputPaths(
    resolvedPdfPath,
    TEMP_OUTPUTS_DIR
  );
  const rawAnalysis = await extractByPages({
    pdfPath: resolvedPdfPath,
    reportId,
    crossCheckPaths: crossCheckOutputPaths,
  });
  const normalized = normalizeVulnerabilityOutput(rawAnalysis, reportId);
  const strictVulnerabilities = normalized.vulnerabilities;
  const softVulnerabilities = dedupeBySoftFingerprint(strictVulnerabilities);
  const strictCount = strictVulnerabilities.length;
  const softCount = softVulnerabilities.length;
  const softDuplicatesRemoved = strictCount - softCount;
  const severityCountsStrict = countBySeverity(strictVulnerabilities);
  const severityCountsSoft = countBySeverity(softVulnerabilities);
  const finalVulnerabilities = APPLY_SOFT_DEDUPE_TO_FINAL_OUTPUT
    ? softVulnerabilities
    : strictVulnerabilities;
  const analysis = {
    vulnerabilities: finalVulnerabilities,
    meta: {
      ...rawAnalysis.meta,
      strictCount,
      softCount,
      softDuplicatesRemoved,
      severityCountsStrict,
      severityCountsSoft,
      applySoftDedupeToFinalOutput: APPLY_SOFT_DEDUPE_TO_FINAL_OUTPUT,
    },
  };
  const outputPath = await writeOutputJson(resolvedPdfPath, analysis, OUTPUTS_DIR);

  return {
    pdfPath: resolvedPdfPath,
    outputPath,
    crossCheckOutputPaths,
    pagesDir: rawAnalysis.meta.pagesDir,
    pageCount: rawAnalysis.meta.pageCount,
    analysis,
  };
};

export default {
  analyzePdfToJson,
  buildGeminiPdfPrompt,
};
