import express from "express";
import { importNessusJson } from "../controllers/analysisController.js";

const router = express.Router();

router.post("/nessus/import", importNessusJson);

export default router;