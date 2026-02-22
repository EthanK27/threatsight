import { Router } from "express";
import { createReportWithData, getLatestReportWithItems } from "../controllers/reportController.js";

const router = Router();

router.get("/", (_req, res) => {
  res.json({
    ok: true,
    route: "/api/reports",
    message: "reportRoutes GET is working",
  });
});

router.post("/", createReportWithData);
router.get("/latest", getLatestReportWithItems);

export default router;
