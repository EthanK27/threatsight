import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PDFDocument } from "pdf-lib";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BACKEND_ROOT = path.resolve(__dirname, "..", "..");

export const UPLOADS_DIR = path.join(BACKEND_ROOT, "temp", "uploads");
export const OUTPUTS_DIR = path.join(BACKEND_ROOT, "outputs");
export const TEMP_OUTPUTS_DIR = path.join(BACKEND_ROOT, "temp", "outputs");

// Picks the latest uploaded PDF when no explicit path is passed.
export const getLatestPdfPath = async (uploadsDir = UPLOADS_DIR) => {
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

// Splits one source PDF into one PDF per page under a dedicated folder.
export const splitPdfIntoPages = async (pdfPath) => {
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
    const pagePath = path.join(pagesDir, `${sourceName}-page-${pageNumber}.pdf`);
    await fs.writeFile(pagePath, Buffer.from(splitBytes));
    pagePaths.push(pagePath);
  }

  return { pageCount, pagePaths, pagesDir };
};

export const buildCrossCheckOutputPaths = (pdfPath, outputsDir = TEMP_OUTPUTS_DIR) => {
  const source = path.parse(pdfPath).name;
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  return {
    primaryPath: path.join(outputsDir, `${source}-${timestamp}-crosscheck-a.json`),
    secondaryPath: path.join(outputsDir, `${source}-${timestamp}-crosscheck-b.json`),
  };
};

export const writeOutputJson = async (pdfPath, analysis, outputsDir = OUTPUTS_DIR) => {
  await fs.mkdir(outputsDir, { recursive: true });
  const source = path.parse(pdfPath).name;
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outputPath = path.join(outputsDir, `${source}-${timestamp}-paged.json`);
  await fs.writeFile(outputPath, JSON.stringify(analysis, null, 2), "utf8");
  return outputPath;
};

export default {
  UPLOADS_DIR,
  OUTPUTS_DIR,
  TEMP_OUTPUTS_DIR,
  getLatestPdfPath,
  splitPdfIntoPages,
  buildCrossCheckOutputPaths,
  writeOutputJson,
};
