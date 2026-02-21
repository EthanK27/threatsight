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
const TEMP_OUTPUTS_DIR = path.join(BACKEND_ROOT, "temp", "outputs");
const GEMINI_API_BASE_URL =
  process.env.GEMINI_API_BASE_URL ||
  "https://generativelanguage.googleapis.com/v1beta";
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";
const REQUEST_TIMEOUT_MS = Number(process.env.GEMINI_REQUEST_TIMEOUT_MS || 240000);
const MIN_CHUNK_SIZE = Math.max(
  1,
  Number(process.env.GEMINI_MIN_CHUNK_SIZE || 3)
);
const CHUNK_SIZE = Math.max(
  MIN_CHUNK_SIZE,
  Number(process.env.GEMINI_CHUNK_SIZE || 8)
);
const MAX_CHUNK_PASSES = Number(process.env.GEMINI_MAX_CHUNK_PASSES || 40);
const CHUNK_COMPARE_RETRIES = Math.max(
  1,
  Number(process.env.GEMINI_CHUNK_COMPARE_RETRIES || 3)
);
const MAX_OUTPUT_TOKENS = Number(process.env.GEMINI_MAX_OUTPUT_TOKENS || 8192);
const THINKING_BUDGET = Number(process.env.GEMINI_THINKING_BUDGET || 0);
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SORT_MODES = ["pluginAsc", "pluginDesc", "nameAsc", "nameDesc"];

const getSortInstruction = (sortMode) => {
  switch (sortMode) {
    case "pluginDesc":
      return "Sort output by host (asc), pluginId (desc), name (asc), usn (asc).";
    case "nameAsc":
      return "Sort output by host (asc), name (asc), pluginId (asc), usn (asc).";
    case "nameDesc":
      return "Sort output by host (asc), name (desc), pluginId (asc), usn (asc).";
    case "pluginAsc":
    default:
      return "Sort output by host (asc), pluginId (asc), name (asc), usn (asc).";
  }
};

const getStagnationLevel = (noGrowthStreak) => {
  if (noGrowthStreak <= 0) {
    return 0;
  }

  if (noGrowthStreak <= 2) {
    return 1;
  }

  if (noGrowthStreak <= 4) {
    return 2;
  }

  return 3;
};

const getFocusHint = (stagnationLevel, severity) => {
  if (stagnationLevel === 1) {
    return `Continue scanning later entries in the ${severity} section. Return unseen rows only.`;
  }

  if (stagnationLevel === 2) {
    return `Continue scanning deeper in the ${severity} section. Prioritize rows not previously returned and avoid repeating earlier rows.`;
  }

  if (stagnationLevel >= 3) {
    return `Return only unseen rows from later/deeper parts of the ${severity} section. Prioritize different pluginId values than previously returned rows.`;
  }

  return "";
};

const getEffectiveBatchSize = (batchSize, stagnationLevel) => {
  if (stagnationLevel >= 3) {
    return MIN_CHUNK_SIZE;
  }

  if (stagnationLevel === 2) {
    return Math.max(MIN_CHUNK_SIZE, batchSize - 2);
  }

  return batchSize;
};

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
  sortMode = "pluginAsc",
  focusHint = "",
  stagnationLevel = 0,
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
8) ${getSortInstruction(sortMode)}
9) Include only severity "${severity}" vulnerabilities.
10) Ensure every string is valid JSON escaped text.
11) Exclude any vulnerability with identity key in this list (host|pluginId|severity|usn|normalizedName):
${excluded.length > 0 ? excluded.map((item) => `- ${item}`).join("\n") : "- none"}
${focusHint ? `12) Focus hint for stagnation level ${stagnationLevel}: ${focusHint}` : ""}

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

const makeComparisonKey = (record) => makeStableIdentityKey(record);

const canonicalizeChunkItems = (items) =>
  JSON.stringify(
    dedupeByFingerprint(items)
      .map((item) => toStableIdentityRecord(item))
      .sort((a, b) =>
        makeComparisonKey(a).localeCompare(makeComparisonKey(b))
      )
  );

const pickConsensusChunkItems = (candidateFrequencyMap) => {
  const candidates = Array.from(candidateFrequencyMap.values());
  const hasNonEmptyCandidate = candidates.some(
    (candidate) => candidate.items.length > 0
  );
  const filteredCandidates = hasNonEmptyCandidate
    ? candidates.filter((candidate) => candidate.items.length > 0)
    : candidates;
  const countWithPluginId = (items) =>
    items.reduce(
      (sum, item) => sum + (asStringOrNull(item?.pluginId) ? 1 : 0),
      0
    );
  const ranked = filteredCandidates.sort(
    (a, b) =>
      b.count - a.count ||
      b.items.length - a.items.length ||
      countWithPluginId(b.items) - countWithPluginId(a.items)
  );

  return ranked[0]?.items || [];
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

const extractInChunks = async (pdfBuffer, reportId, crossCheckPaths = null) => {
  const aggregated = [];
  let totalCalls = 0;
  let mismatchedChunksResolved = 0;
  const severityProgress = [];
  const pdfBase64 = pdfBuffer.toString("base64");

  if (crossCheckPaths) {
    await fs.mkdir(path.dirname(crossCheckPaths.primaryPath), { recursive: true });
  }

  const executeCrossCheckedPass = async ({
    baseline,
    prompt,
    severity,
    passNumber,
    batchSizeForMeta,
    currentBatchSize,
    reduceBatchSizeForJsonRecovery,
  }) => {
    let reducedChunkForJsonRecovery = false;
    let matched = false;
    let matchedAggregated = baseline;
    let sawMaxTokens = false;
    const candidateFrequency = new Map();

    for (let attempt = 1; attempt <= CHUNK_COMPARE_RETRIES; attempt += 1) {
      let primaryResponse;
      let secondaryResponse;

      try {
        totalCalls += 1;
        primaryResponse = await callGeminiForPdf(pdfBase64, prompt);
        totalCalls += 1;
        secondaryResponse = await callGeminiForPdf(pdfBase64, prompt);
      } catch (error) {
        const isJsonSyntaxError = error instanceof SyntaxError;

        if (
          (isJsonSyntaxError ||
            /Failed to parse Gemini response as JSON|Expected .* in JSON|Unterminated string in JSON/.test(
              String(error?.message || "")
            )) &&
          currentBatchSize > MIN_CHUNK_SIZE
        ) {
          reduceBatchSizeForJsonRecovery();
          reducedChunkForJsonRecovery = true;
          break;
        }

        throw error;
      }

      const primaryItems = normalizeVulnerabilityOutput(
        primaryResponse.analysis,
        reportId
      ).vulnerabilities.filter(
        (item) => normalizeSeverity(item?.severity) === severity
      );
      const secondaryItems = normalizeVulnerabilityOutput(
        secondaryResponse.analysis,
        reportId
      ).vulnerabilities.filter(
        (item) => normalizeSeverity(item?.severity) === severity
      );

      const primaryKey = canonicalizeChunkItems(primaryItems);
      const secondaryKey = canonicalizeChunkItems(secondaryItems);
      if (!candidateFrequency.has(primaryKey)) {
        candidateFrequency.set(primaryKey, { count: 0, items: primaryItems });
      }
      if (!candidateFrequency.has(secondaryKey)) {
        candidateFrequency.set(secondaryKey, { count: 0, items: secondaryItems });
      }
      candidateFrequency.get(primaryKey).count += 1;
      candidateFrequency.get(secondaryKey).count += 1;
      sawMaxTokens =
        sawMaxTokens ||
        primaryResponse.finishReason === "MAX_TOKENS" ||
        secondaryResponse.finishReason === "MAX_TOKENS";

      const primaryCandidate = dedupeByFingerprint([...baseline, ...primaryItems]);
      const secondaryCandidate = dedupeByFingerprint([
        ...baseline,
        ...secondaryItems,
      ]);

      await syncCrossCheckFiles({
        crossCheckPaths,
        primaryVulnerabilities: primaryCandidate,
        secondaryVulnerabilities: secondaryCandidate,
        reportId,
        meta: {
          status: "cross-checking",
          severity,
          pass: passNumber,
          attempt,
          batchSize: batchSizeForMeta,
          totalCalls,
          mismatchResolved: false,
        },
      });

      if (primaryKey === secondaryKey) {
        matched = true;
        matchedAggregated = primaryCandidate;

        await syncCrossCheckFiles({
          crossCheckPaths,
          primaryVulnerabilities: matchedAggregated,
          secondaryVulnerabilities: matchedAggregated,
          reportId,
          meta: {
            status: "matched",
            severity,
            pass: passNumber,
            attempt,
            batchSize: batchSizeForMeta,
            totalCalls,
            mismatchResolved: false,
          },
        });

        break;
      }
    }

    if (reducedChunkForJsonRecovery) {
      return {
        reducedChunkForJsonRecovery: true,
        sawMaxTokens,
        aggregated: baseline,
      };
    }

    if (matched) {
      return {
        reducedChunkForJsonRecovery: false,
        sawMaxTokens,
        aggregated: matchedAggregated,
      };
    }

    mismatchedChunksResolved += 1;
    const resolvedItems = pickConsensusChunkItems(candidateFrequency);
    const resolvedAggregated = dedupeByFingerprint([...baseline, ...resolvedItems]);

    await syncCrossCheckFiles({
      crossCheckPaths,
      primaryVulnerabilities: resolvedAggregated,
      secondaryVulnerabilities: resolvedAggregated,
      reportId,
      meta: {
        status: "mismatch-resolved",
        severity,
        pass: passNumber,
        attempt: CHUNK_COMPARE_RETRIES,
        batchSize: batchSizeForMeta,
        totalCalls,
        mismatchResolved: true,
        resolvedWithConsensus: true,
      },
    });

    return {
      reducedChunkForJsonRecovery: false,
      sawMaxTokens,
      aggregated: resolvedAggregated,
    };
  };

  for (const severity of SEVERITY_ORDER) {
    let batchSize = CHUNK_SIZE;
    let consecutiveNoGrowthPasses = 0;

    for (let pass = 0; pass < MAX_CHUNK_PASSES; pass += 1) {
      const stagnationLevel = getStagnationLevel(consecutiveNoGrowthPasses);
      const sortMode = SORT_MODES[(pass + stagnationLevel) % SORT_MODES.length];
      const focusHint = getFocusHint(stagnationLevel, severity);
      const effectiveBatchSize = getEffectiveBatchSize(batchSize, stagnationLevel);
      const before = aggregated.length;
      const baseline = [...aggregated];
      const excludedFingerprints = baseline
        .filter((item) => normalizeSeverity(item?.severity) === severity)
        .map(makeFingerprint)
        .slice(-200);
      const prompt = buildGeminiChunkPrompt({
        reportId,
        severity,
        limit: effectiveBatchSize,
        excluded: excludedFingerprints,
        sortMode,
        focusHint,
        stagnationLevel,
      });

      const passResult = await executeCrossCheckedPass({
        baseline,
        prompt,
        severity,
        passNumber: pass + 1,
        batchSizeForMeta: effectiveBatchSize,
        currentBatchSize: batchSize,
        reduceBatchSizeForJsonRecovery: () => {
          batchSize = Math.max(MIN_CHUNK_SIZE, Math.floor(batchSize / 2));
        },
      });

      if (passResult.reducedChunkForJsonRecovery) {
        continue;
      }

      let sawMaxTokens = passResult.sawMaxTokens;
      aggregated.length = 0;
      aggregated.push(...passResult.aggregated);
      const addedCount = aggregated.length - before;
      let resolvedAddedCount = addedCount;
      let escapeAttemptUsed = false;
      let escapeAddedCount = 0;

      if (resolvedAddedCount === 0) {
        escapeAttemptUsed = true;
        const escapeStagnationLevel = Math.min(3, stagnationLevel + 1);
        const escapeSortMode =
          SORT_MODES[(pass + escapeStagnationLevel) % SORT_MODES.length];
        const escapeFocusHint = getFocusHint(escapeStagnationLevel, severity);
        const escapeEffectiveBatchSize = getEffectiveBatchSize(
          batchSize,
          escapeStagnationLevel
        );
        const escapeBaseline = [...aggregated];
        const escapeExcludedFingerprints = escapeBaseline
          .filter((item) => normalizeSeverity(item?.severity) === severity)
          .map(makeFingerprint)
          .slice(-200);
        const escapePrompt = buildGeminiChunkPrompt({
          reportId,
          severity,
          limit: escapeEffectiveBatchSize,
          excluded: escapeExcludedFingerprints,
          sortMode: escapeSortMode,
          focusHint: escapeFocusHint,
          stagnationLevel: escapeStagnationLevel,
        });
        const escapeResult = await executeCrossCheckedPass({
          baseline: escapeBaseline,
          prompt: escapePrompt,
          severity,
          passNumber: pass + 1,
          batchSizeForMeta: escapeEffectiveBatchSize,
          currentBatchSize: batchSize,
          reduceBatchSizeForJsonRecovery: () => {
            batchSize = Math.max(MIN_CHUNK_SIZE, Math.floor(batchSize / 2));
          },
        });

        if (escapeResult.reducedChunkForJsonRecovery) {
          continue;
        }

        sawMaxTokens = sawMaxTokens || escapeResult.sawMaxTokens;
        aggregated.length = 0;
        aggregated.push(...escapeResult.aggregated);
        escapeAddedCount = aggregated.length - escapeBaseline.length;
        resolvedAddedCount = aggregated.length - before;

        if (escapeAddedCount > 0) {
          consecutiveNoGrowthPasses = 0;
        } else {
          consecutiveNoGrowthPasses += 1;
        }
      } else {
        consecutiveNoGrowthPasses = 0;
      }

      const collectedCountForSeverity = aggregated.filter(
        (item) => normalizeSeverity(item?.severity) === severity
      ).length;
      severityProgress.push({
        severity,
        pass: pass + 1,
        batchSize,
        addedCount: resolvedAddedCount,
        consecutiveNoGrowthPasses,
        collectedCountForSeverity,
        sawMaxTokens,
        stagnationLevel,
        sortMode,
        effectiveBatchSize,
        focusHintApplied: focusHint.length > 0,
        escapeAttemptUsed,
        escapeAddedCount,
      });

      if (sawMaxTokens && batchSize > MIN_CHUNK_SIZE) {
        batchSize = Math.max(MIN_CHUNK_SIZE, Math.floor(batchSize / 2));
        continue;
      }

      if (consecutiveNoGrowthPasses >= 3) {
        break;
      }
    }
  }

  return {
    vulnerabilities: aggregated,
    meta: {
      totalCalls,
      mismatchedChunksResolved,
      severityProgress,
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

export const analyzePdfToJson = async (pdfPath, reportId = "Report1") => {
  const resolvedPdfPath = pdfPath
    ? path.resolve(pdfPath)
    : await getLatestPdfPath(UPLOADS_DIR);
  const pdfBuffer = await fs.readFile(resolvedPdfPath);

  const crossCheckOutputPaths = buildCrossCheckOutputPaths(
    resolvedPdfPath,
    TEMP_OUTPUTS_DIR
  );
  const rawAnalysis = await extractInChunks(
    pdfBuffer,
    reportId,
    crossCheckOutputPaths
  );
  const analysis = {
    ...normalizeVulnerabilityOutput(rawAnalysis, reportId),
    meta: rawAnalysis.meta,
  };
  const outputPath = await writeOutputJson(resolvedPdfPath, analysis, OUTPUTS_DIR);

  return {
    pdfPath: resolvedPdfPath,
    outputPath,
    crossCheckOutputPaths,
    analysis,
  };
};

export default {
  analyzePdfToJson,
  buildGeminiPdfPrompt,
};
