import { Router } from "express";
import {
  createReportWithData,
  getAllHoneypotItems,
  getAllWiresharkItems,
  getLatestReportWithItems,
  streamHoneypotEvents,
} from "../controllers/reportController.js";

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
router.get("/honeypot/items", getAllHoneypotItems);
router.get("/honeypot/stream", streamHoneypotEvents);

export default router;
