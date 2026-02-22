// Extract JSON safely from model text responses.
// Handles plain JSON, fenced markdown JSON, and extra leading/trailing text.
export const extractJson = (rawText) => {
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

export default {
  extractJson,
};
