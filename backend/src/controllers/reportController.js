import mongoose from "mongoose";
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
    if (!["Nessus", "Wireshark", "Honeypot"].includes(mode)) {
      return res.status(400).json({
        ok: false,
        error: "mode must be Nessus, Wireshark, or Honeypot",
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

    const modelByMode = {
      Nessus: VulnNessus,
      Wireshark: VulnWireshark,
      Honeypot: VulnHoneypot,
    };

    const items = await modelByMode[mode].find({ reportId: report._id }).lean();
    return res.json({
      ok: true,
      report,
      items,
    });
  } catch (err) {
    next(err);
  }
};

export const getAllWiresharkItems = async (_req, res, next) => {
  try {
    const collection = mongoose.connection.db.collection("vulnwiresharks");
    const items = await collection.find({}).sort({ timestamp: -1, _id: -1 }).toArray();

    return res.json({
      ok: true,
      items,
      count: items.length,
    });
  } catch (err) {
    next(err);
  }
};

const normalizeHoneypotSeverity = (item = {}) => {
  const explicit = item?.severity ?? item?.Severity ?? item?.level;
  if (explicit !== undefined && explicit !== null && String(explicit).trim()) {
    return String(explicit).trim();
  }

  const logType = Number(item?.logtype ?? item?.log_type);
  if (!Number.isNaN(logType)) {
    if (logType >= 5000) return "Critical";
    if (logType >= 4000) return "High";
    if (logType >= 3000) return "Medium";
  }

  const text = String(item?.attack_type || item?.name || item?.info || "").toLowerCase();
  if (/(ransom|malware|trojan|backdoor|beacon)/.test(text)) return "Critical";
  if (/(brute|failed login|ssh login|credential|auth)/.test(text)) return "High";
  if (/(scan|probe|recon)/.test(text)) return "Medium";
  return "Low";
};

const normalizeHoneypotRecord = (item = {}) => {
  const timestamp = item?.timestamp || item?.createdAt || item?.updatedAt || new Date().toISOString();
  const src = item?.src_ip || item?.srcIP || item?.source_ip || item?.source || "-";
  const dst = item?.dst_ip || item?.dstIP || item?.dest_ip || item?.destination || "-";
  const srcPort = item?.src_port ?? item?.source_port ?? null;
  const dstPort = item?.dst_port ?? item?.dest_port ?? null;
  const proto = item?.protocol || item?.proto || item?.service || item?.attack_type || "unknown";
  const info = item?.info || item?.name || item?.attack_type || "honeypot event";
  const tags = [
    item?.attack_type,
    item?.logtype ? `logtype:${item.logtype}` : null,
    item?.country ? `country:${item.country}` : null,
    item?.asn ? `asn:${item.asn}` : null,
  ].filter(Boolean);

  return {
    ...item,
    _id: item?._id,
    timestamp,
    src_ip: src,
    dst_ip: dst,
    src_port: srcPort,
    dst_port: dstPort,
    protocol: proto,
    info,
    severity: normalizeHoneypotSeverity(item),
    tags,
  };
};

export const getAllHoneypotItems = async (_req, res, next) => {
  try {
    const collection = mongoose.connection.db.collection("vulnhoneypots");
    const items = await collection.find({}).sort({ _id: -1 }).limit(2000).toArray();
    const normalized = items.map(normalizeHoneypotRecord);

    return res.json({
      ok: true,
      items: normalized,
      count: normalized.length,
    });
  } catch (err) {
    next(err);
  }
};

export const streamHoneypotEvents = async (req, res, next) => {
  try {
    const collection = mongoose.connection.db.collection("vulnhoneypots");
    const limit = Math.min(Math.max(Number(req.query.limit) || 250, 10), 1500);

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders?.();
    res.write("retry: 4000\n\n");

    const sendEvent = (eventName, payload) => {
      res.write(`event: ${eventName}\n`);
      res.write(`data: ${JSON.stringify(payload)}\n\n`);
    };

    const initial = await collection.find({}).sort({ _id: -1 }).limit(limit).toArray();
    const ordered = [...initial].reverse();
    const normalizedSnapshot = ordered.map(normalizeHoneypotRecord);
    let lastSeenId = initial[0]?._id || null;
    let polling = false;

    sendEvent("snapshot", {
      ok: true,
      generatedAt: new Date().toISOString(),
      items: normalizedSnapshot,
    });

    const pollHandle = setInterval(async () => {
      if (polling) return;
      polling = true;

      try {
        const query = lastSeenId ? { _id: { $gt: lastSeenId } } : {};
        const fresh = await collection.find(query).sort({ _id: 1 }).limit(500).toArray();
        if (fresh.length > 0) {
          lastSeenId = fresh[fresh.length - 1]._id;
          sendEvent("events", {
            ok: true,
            generatedAt: new Date().toISOString(),
            items: fresh.map(normalizeHoneypotRecord),
          });
        }
      } catch (err) {
        sendEvent("stream_error", {
          ok: false,
          message: err?.message || "Failed polling Honeypot events",
        });
      } finally {
        polling = false;
      }
    }, 4000);

    const heartbeatHandle = setInterval(() => {
      res.write(": keepalive\n\n");
    }, 15000);

    req.on("close", () => {
      clearInterval(pollHandle);
      clearInterval(heartbeatHandle);
      res.end();
    });
  } catch (err) {
    next(err);
  }
};
