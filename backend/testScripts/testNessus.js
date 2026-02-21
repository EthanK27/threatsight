import "dotenv/config";
import fs from "fs";
import mongoose from "mongoose";
import { importNessusReport } from "../src/services/pdfService.js";

async function main() {
    const [, , jsonPath, reportName] = process.argv;

    if (!jsonPath || !reportName) {
        console.error(
            'Usage: node testScripts/testNessus.js <path/to/file.json> "<report name>"'
        );
        process.exit(1);
    }

    const mongoUri = process.env.MONGODB_URI;
    if (!mongoUri) {
        throw new Error("Missing MONGODB_URI in backend/.env");
    }

    const payload = JSON.parse(fs.readFileSync(jsonPath, "utf-8"));

    await mongoose.connect(mongoUri);

    try {
        const result = await importNessusReport({
            reportName,
            payload,
        });

        console.log("Import completed successfully:");
        console.log(result);
    } finally {
        await mongoose.disconnect();
    }
}

main().catch((err) => {
    console.error("Import failed:", err);
    process.exit(1);
});