import express from "express";
import multer from "multer";
import path from "node:path";
import fs from "node:fs/promises";
import { fileURLToPath } from "node:url";
import Report from "../models/Report.js";
import { analyzePdfToJson } from "../services/aiRead.js";
import { importNessusReport } from "../services/pdfService.js";
import {
    getLatestNessusReport,
    getNessusFindings,
} from "../controllers/analysisController.js";


const router = express.Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// backend/src/routes -> backend
const BACKEND_ROOT = path.resolve(__dirname, "..", "..");

// Uploaded PDFs are staged here
const UPLOADS_DIR = path.join(BACKEND_ROOT, "temp", "uploads");
await fs.mkdir(UPLOADS_DIR, { recursive: true });

const storage = multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
    filename: (_req, file, cb) => {
        const safeBase = path
            .parse(file.originalname)
            .name
            .replace(/[^a-z0-9-_]/gi, "_");

        const ext = path.extname(file.originalname).toLowerCase() || ".pdf";
        const stamp = new Date().toISOString().replace(/[:.]/g, "-");
        cb(null, `${safeBase}-${stamp}${ext}`);
    },
});

const upload = multer({
    storage,
    limits: { fileSize: 25 * 1024 * 1024 }, // 25MB
    fileFilter: (_req, file, cb) => {
        const isPdfMime = file.mimetype === "application/pdf";
        const isPdfExt = path.extname(file.originalname).toLowerCase() === ".pdf";
        if (!isPdfMime && !isPdfExt) return cb(new Error("Only PDF files allowed."));
        cb(null, true);
    },
});

const normalizeReportName = (name) => {
    if (!name || typeof name !== "string") return null;
    const trimmed = name.trim();
    return trimmed.length > 0 ? trimmed : null;
};

// Upload PDF -> AI extract -> store in DB.
router.post("/nessus/upload", upload.single("nessusPdf"), async (req, res, next) => {
    try {
        if (!req.file) return res.status(400).json({ error: "Missing file: nessusPdf" });
        const stat = await fs.stat(req.file.path);
        const reportNameFromBody = normalizeReportName(req.body?.reportName);
        const inferredName = path.parse(req.file.originalname).name;
        const reportName = reportNameFromBody || inferredName || "Nessus Report";

        const analysisResult = await analyzePdfToJson(req.file.path, reportName);
        const importResult = await importNessusReport({
            reportName,
            payload: analysisResult.analysis,
        });

        return res.json({
            ok: true,
            reportName,
            savedAs: req.file.filename,
            fullPath: req.file.path,
            bytes: stat.size,
            mimetype: req.file.mimetype,
            originalname: req.file.originalname,
            analysis: {
                outputPath: analysisResult.outputPath,
                pageCount: analysisResult.pageCount,
                vulnerabilityCount: analysisResult.analysis?.vulnerabilities?.length || 0,
            },
            db: importResult,
        });
    } catch (err) {
        next(err);
    }
});

router.get("/nessus/reports/latest", getLatestNessusReport);
router.get("/nessus/reports/:reportId/findings", getNessusFindings);

export default router;
