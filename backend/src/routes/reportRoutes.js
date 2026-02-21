import { Router } from "express";
import { createReportWithData } from "../controllers/reportController.js";

const router = Router();
router.post("/", createReportWithData);

export default router;