import { importNessusVulns } from "../services/nessusImportService.js";

export const importNessusJson = async (req, res, next) => {
    try {
        // Expect JSON body like { vulnerabilities: [...] }
        const { vulnerabilities } = req.body;

        if (!Array.isArray(vulnerabilities) || vulnerabilities.length === 0) {
            return res.status(400).json({ message: "No vulnerabilities provided." });
        }

        const result = await importNessusVulns(vulnerabilities);

        return res.status(200).json({
            message: "Import complete",
            ...result,
        });
    } catch (err) {
        next(err);
    }
};