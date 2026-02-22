import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import { extractJson } from "./jsonExtract.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BACKEND_ROOT = path.resolve(__dirname, "..", "..");

// Load backend/.env once so direct script runs and server runs behave the same.
dotenv.config({ path: path.join(BACKEND_ROOT, ".env") });

const GEMINI_API_BASE_URL =
  process.env.GEMINI_API_BASE_URL ||
  "https://generativelanguage.googleapis.com/v1beta";
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";
const REQUEST_TIMEOUT_MS = Number(process.env.GEMINI_REQUEST_TIMEOUT_MS || 240000);
const MAX_OUTPUT_TOKENS = Number(process.env.GEMINI_MAX_OUTPUT_TOKENS || 8192);
const THINKING_BUDGET = Number(process.env.GEMINI_THINKING_BUDGET || 0);

export const CHUNK_COMPARE_RETRIES = Math.max(
  1,
  Number(process.env.GEMINI_CHUNK_COMPARE_RETRIES || 3)
);

const buildGeminiEndpoint = () => {
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  if (!apiKey) {
    throw new Error("Missing GEMINI_API_KEY in backend/.env.");
  }

  return (
    `${GEMINI_API_BASE_URL}/models/${encodeURIComponent(GEMINI_MODEL)}` +
    `:generateContent?key=${encodeURIComponent(apiKey)}`
  );
};

const callGemini = async ({ contents, maxOutputTokens = MAX_OUTPUT_TOKENS }) => {
  const endpoint = buildGeminiEndpoint();

  const payload = {
    contents,
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

  return {
    analysis: extractJson(text),
    finishReason: data?.candidates?.[0]?.finishReason || null,
  };
};

// Sends a single PDF+prompt request and returns parsed JSON plus finish reason.
export const callGeminiForPdf = async (
  pdfBase64,
  prompt,
  maxOutputTokens = MAX_OUTPUT_TOKENS
) => {
  return callGemini({
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
    maxOutputTokens,
  });
};

// Sends a single prompt-only request and returns parsed JSON plus finish reason.
export const callGeminiForJsonPrompt = async (
  prompt,
  maxOutputTokens = MAX_OUTPUT_TOKENS
) => {
  return callGemini({
    contents: [
      {
        role: "user",
        parts: [{ text: prompt }],
      },
    ],
    maxOutputTokens,
  });
};

export default {
  CHUNK_COMPARE_RETRIES,
  callGeminiForPdf,
  callGeminiForJsonPrompt,
};
