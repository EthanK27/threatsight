import Report from "../models/Report.js";
import VulnNessus from "../models/VulnNessus.js";

export async function importNessusVulns(vulnerabilities, reportName = "Nessus Scan - Import") {
    // 1) Create a Report record
    const report = await Report.create({
        reportName,
        generatedAt: null,
        uploadedAt: new Date(),
        mode: "Nessus",
    });

    // 2) Insert VulnNessus rows linked to reportId
    const docs = vulnerabilities.map((v) => ({
        ...v,
        reportId: report._id,
    }));

    const inserted = await VulnNessus.insertMany(docs, { ordered: false });

    // 3) Return reportId so frontend can fetch by it
    return {
        ok: true,
        reportId: report._id,
        inserted: inserted.length,
    };
}

export async function getLatestNessusReport(req, res, next) {
    try {
        const latest = await Report.findOne({ mode: "Nessus" })
            .sort({ createdAt: -1 })
            .select("_id reportName createdAt uploadedAt")
            .lean();

        if (!latest) {
            return res.status(404).json({ error: "No Nessus reports found." });
        }

        return res.json({
            ok: true,
            reportId: latest._id,
            reportName: latest.reportName,
            createdAt: latest.createdAt,
            uploadedAt: latest.uploadedAt,
        });
    } catch (err) {
        next(err);
    }
}

export async function getNessusFindings(req, res, next) {
    try {
        const { reportId } = req.params;
        if (!reportId) {
            return res.status(400).json({ error: "Missing reportId." });
        }

        const findings = await VulnNessus.find({ reportId })
            .sort({ severity: -1, createdAt: -1 })
            .lean();

        return res.json({ ok: true, reportId, findings });
    } catch (err) {
        next(err);
    }
}
