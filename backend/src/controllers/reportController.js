import Report from "../models/Report.js";
import VulnNessus from "../models/VulnNessus.js";
import VulnWireshark from "../models/VulnWireshark.js";
import VulnHoneypot from "../models/VulnHoneypot.js";

export const createReportWithData = async (req, res, next) => {
  try {
    const { reportName, generatedAt, uploadedAt, mode, items = [] } = req.body;

    // Basic request validation
    if (!reportName || !mode) {
      return res.status(400).json({
        ok: false,
        error: "reportName and mode are required",
      });
    }

    if (!["Nessus", "Wireshark", "Honeypot"].includes(mode)) {
      return res.status(400).json({
        ok: false,
        error: "mode must be Nessus, Wireshark, or Honeypot",
      });
    }

    // Create report (Mongo auto-generates _id)
    const report = await Report.create({
      reportName,
      generatedAt: generatedAt ? new Date(generatedAt) : null,
      uploadedAt: uploadedAt ? new Date(uploadedAt) : new Date(),
      mode,
    });

    // Insert related data
    if (Array.isArray(items) && items.length > 0) {
      if (mode === "Nessus") {
        await VulnNessus.insertMany(
          items.map((v) => ({
            ...v,
            reportId: report._id,
          }))
        );
      }

      if (mode === "Wireshark") {
        await VulnWireshark.insertMany(
          items.map((e) => ({
            ...e,
            reportId: report._id,
            timestamp: new Date(e.timestamp),
          }))
        );
      }

      if (mode === "Honeypot") {
        await VulnHoneypot.insertMany(
          items.map((v) => ({
            ...v,
            reportId: report._id,
          }))
        );
      }
    }

    // Success response
    return res.status(201).json({
      ok: true,
      reportId: report._id,
      inserted: items.length,
    });
  } catch (err) {
    console.error("Create report error:", err);
    next(err);
  }
};

export const getLatestReportWithItems = async (req, res, next) => {
  try {
    const mode = req.query.mode || "Nessus";
    if (mode !== "Nessus") {
      return res.status(400).json({
        ok: false,
        error: "Only mode=Nessus is currently supported on this endpoint",
      });
    }

    const report = await Report.findOne({ mode }).sort({ uploadedAt: -1, createdAt: -1 }).lean();
    if (!report) {
      return res.json({
        ok: true,
        report: null,
        items: [],
      });
    }

    const items = await VulnNessus.find({ reportId: report._id }).lean();
    return res.json({
      ok: true,
      report,
      items,
    });
  } catch (err) {
    next(err);
  }
};
