import mongoose from "mongoose";
import Report from "../models/Report.js";
import VulnNessus from "../models/VulnNessus.js";
import { normalizeCategory } from "./fingerprints.js";

export async function importNessusReport({ reportName, payload }) {
    if (!reportName?.trim()) throw new Error("reportName is required");
    if (!Array.isArray(payload?.vulnerabilities)) {
        throw new Error("payload.vulnerabilities must be an array");
    }

    const session = await mongoose.startSession();

    try {
        return await session.withTransaction(async () => {
            const [report] = await Report.create(
                [
                    {
                        reportName: reportName.trim(),
                        generatedAt: payload?.generatedAt ?? null,
                        mode: "Nessus",
                    },
                ],
                { session }
            );

            const ops = [];
            let skipped = 0;

            for (const v of payload.vulnerabilities) {
                if (!v?.host || v?.severity == null || v?.pluginId == null || !v?.name) {
                    skipped++;
                    continue;
                }

                const doc = {
                    reportId: report._id,
                    host: String(v.host),
                    severity: v.severity,
                    cvssV3: v.cvssV3 ?? null,
                    vpr: v.vpr ?? null,
                    epss: v.epss ?? null,
                    pluginId: v.pluginId,
                    name: String(v.name),
                    usn: v.usn ?? null,
                    category: normalizeCategory(v.category),
                };

                ops.push({
                    updateOne: {
                        filter: { reportId: report._id, host: doc.host, pluginId: doc.pluginId },
                        update: { $set: doc },
                        upsert: true,
                    },
                });
            }

            const bulkRes =
                ops.length > 0
                    ? await VulnNessus.bulkWrite(ops, { ordered: false, session })
                    : null;

            return {
                reportId: report._id.toString(),
                reportName: report.reportName,
                mode: report.mode,
                vulns: {
                    upserted: bulkRes?.upsertedCount || 0,
                    modified: bulkRes?.modifiedCount || 0,
                    matched: bulkRes?.matchedCount || 0,
                    skipped,
                },
            };
        });
    } finally {
        session.endSession();
    }
}
