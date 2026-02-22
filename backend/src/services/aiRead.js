import fs from "node:fs/promises";
import path from "node:path";
import {
  CHUNK_COMPARE_RETRIES,
  callGeminiForJsonPrompt,
  callGeminiForPdf,
} from "./geminiClient.js";
import {
  asStringOrNull,
  canonicalizeChunkItems,
  countBySeverity,
  dedupeByFingerprint,
  dedupeBySoftFingerprint,
  normalizeCategory,
  normalizeVulnerabilityOutput,
} from "./fingerprints.js";
import { buildGeminiCategoryPrompt, buildGeminiPdfPrompt } from "./prompts.js";
import {
  TEMP_OUTPUTS_DIR,
  UPLOADS_DIR,
  buildCrossCheckOutputPaths,
  getLatestPdfPath,
  splitPdfIntoPages,
  writeOutputJson,
} from "./pdfSplit.js";

const APPLY_SOFT_DEDUPE_TO_FINAL_OUTPUT =
  String(process.env.APPLY_SOFT_DEDUPE_TO_FINAL_OUTPUT || "false").toLowerCase() ===
  "true";

// Writes one lane snapshot file (primary or secondary).
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

// Keeps both cross-check files in sync so progress is inspectable while running.
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

// If retries never match exactly, choose the most frequent/highest-signal candidate.
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

const toValidCategoryIndex = (value, itemCount) => {
  const numeric = Number(value);
  if (
    Number.isInteger(numeric) &&
    numeric >= 0 &&
    numeric < itemCount
  ) {
    return numeric;
  }
  return null;
};

const categorizeResolvedChunk = async ({
  items,
  reportId,
  pageNumber,
  pageCount,
  totalCallsRef,
}) => {
  if (!Array.isArray(items) || items.length === 0) {
    return { items: [], sawMaxTokens: false };
  }

  const prompt = buildGeminiCategoryPrompt({
    reportId,
    pageNumber,
    pageCount,
    items,
  });
  let categoryResponse;
  try {
    totalCallsRef.count += 1;
    categoryResponse = await callGeminiForJsonPrompt(prompt);
  } catch (_error) {
    return {
      items: items.map((item) => ({ ...item, category: "Other" })),
      sawMaxTokens: false,
    };
  }

  const categoryRows = Array.isArray(categoryResponse.analysis?.categories)
    ? categoryResponse.analysis.categories
    : [];

  const categoryByIndex = new Map();
  for (const row of categoryRows) {
    const index = toValidCategoryIndex(row?.index, items.length);
    if (index === null || categoryByIndex.has(index)) {
      continue;
    }
    categoryByIndex.set(index, normalizeCategory(row?.category));
  }

  const categorizedItems = items.map((item, index) => ({
    ...item,
    category: categoryByIndex.get(index) || "Other",
  }));

  return {
    items: categorizedItems,
    sawMaxTokens: categoryResponse.finishReason === "MAX_TOKENS",
  };
};

// Runs primary/secondary prompts against a single page and resolves agreement.
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
      const categorized = await categorizeResolvedChunk({
        items: primaryItems,
        reportId,
        pageNumber,
        pageCount,
        totalCallsRef,
      });

      await syncCrossCheckFiles({
        crossCheckPaths,
        primaryVulnerabilities: dedupeByFingerprint([
          ...baseline,
          ...categorized.items,
        ]),
        secondaryVulnerabilities: dedupeByFingerprint([
          ...baseline,
          ...categorized.items,
        ]),
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
        items: categorized.items,
        mismatchResolved: false,
        sawMaxTokens: sawMaxTokens || categorized.sawMaxTokens,
      };
    }
  }

  const resolvedItems = resolveConsensusItems(candidateFrequency);
  const categorized = await categorizeResolvedChunk({
    items: resolvedItems,
    reportId,
    pageNumber,
    pageCount,
    totalCallsRef,
  });

  await syncCrossCheckFiles({
    crossCheckPaths,
    primaryVulnerabilities: dedupeByFingerprint([
      ...baseline,
      ...categorized.items,
    ]),
    secondaryVulnerabilities: dedupeByFingerprint([
      ...baseline,
      ...categorized.items,
    ]),
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
    items: categorized.items,
    mismatchResolved: true,
    sawMaxTokens: sawMaxTokens || categorized.sawMaxTokens,
  };
};

// End-to-end page loop: split PDF, process each page, accumulate deduped rows.
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

// Public entrypoint used by routes/scripts.
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

  const outputPath = await writeOutputJson(resolvedPdfPath, analysis);

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
