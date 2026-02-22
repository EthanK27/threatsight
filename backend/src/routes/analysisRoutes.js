import express from "express";
import multer from "multer";
import path from "node:path";
import fs from "node:fs/promises";
import { fileURLToPath } from "node:url";

const router = express.Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// backend/src/routes -> backend
const BACKEND_ROOT = path.resolve(__dirname, "..", "..");

// Your desired folder: backend/uploads
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

// ✅ New route: upload pdf
router.post("/nessus/upload", upload.single("nessusPdf"), async (req, res, next) => {
    try {
        if (!req.file) return res.status(400).json({ error: "Missing file: nessusPdf" });

        // “for now”: confirm multer saved it + we can read it
        const stat = await fs.stat(req.file.path);

        return res.json({
            ok: true,
            savedAs: req.file.filename,
            fullPath: req.file.path,
            bytes: stat.size,
            mimetype: req.file.mimetype,
            originalname: req.file.originalname,
        });
    } catch (err) {
        next(err);
    }
});

export default router;
