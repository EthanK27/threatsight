import { Router } from "express";
import { createReportWithData, getAllWiresharkItems, getLatestReportWithItems } from "../controllers/reportController.js";

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
router.get("/wireshark/items", getAllWiresharkItems);

export default router;
