import { useState } from "react";
import {
    uploadNessusPdf,
    fetchLatestNessusReport,
    fetchNessusFindings,
} from "../api/nessus";
import NessusReportView from "./nessus/NessusReportView";

export default function NessusTab() {
    const [file, setFile] = useState(null);
    const [status, setStatus] = useState("idle"); // idle | uploading | success | error
    const [result, setResult] = useState(null);
    const [error, setError] = useState("");

    const [reportId, setReportId] = useState(null);
    const [findings, setFindings] = useState([]);
    const [loadingFindings, setLoadingFindings] = useState(false);

    const loadFindings = async (rid) => {
        setLoadingFindings(true);
        setError("");
        try {
            const rows = await fetchNessusFindings(rid);
            setFindings(rows);
        } catch (err) {
            setError(err?.message || "Failed to load findings");
        } finally {
            setLoadingFindings(false);
        }
    };

    const uploadPdf = async () => {
        if (!file) return;

        setStatus("uploading");
        setError("");
        setResult(null);
        setFindings([]);
        setReportId(null);

        try {
            const data = await uploadNessusPdf(file);
            setResult(data);
            setStatus("success");

            let rid = data?.reportId || data?._id || data?.savedReportId || null;

            // Temporary fallback for upload responses that do not include reportId.
            if (!rid) {
                const latest = await fetchLatestNessusReport();
                rid = latest?.reportId || latest?._id || null;
            }

            if (!rid) {
                throw new Error("Upload succeeded but no Nessus reportId was available.");
            }

            setReportId(rid);
            await loadFindings(rid);
        } catch (err) {
            setError(err?.message || "Upload failed");
            setStatus("error");
        }
    };

    return (
        <div className="w-full">
            <h2 className="mb-4 text-lg font-semibold">Nessus PDF Upload</h2>

            <div className="flex flex-col gap-4">
                <div className="flex max-w-lg flex-col gap-4">
                    <input
                        type="file"
                        accept="application/pdf,.pdf"
                        onChange={(e) => setFile(e.target.files?.[0] || null)}
                        className="text-sm"
                    />

                    <button
                        type="button"
                        onClick={uploadPdf}
                        disabled={!file || status === "uploading"}
                        className={[
                            "rounded-md border border-white/10 px-4 py-2 text-sm font-medium",
                            !file || status === "uploading"
                                ? "cursor-not-allowed bg-white/5 opacity-50"
                                : "bg-accent/30 hover:bg-accent/40",
                        ].join(" ")}
                    >
                        {status === "uploading" ? "Uploading..." : "Upload PDF"}
                    </button>

                    {status === "error" && <div className="text-sm text-red-300">{error}</div>}

                    {status === "success" && result && (
                        <div className="rounded-md border border-white/10 bg-white/5 p-3 text-sm">
                            <div className="mb-1 font-medium">Upload successful</div>
                            {"savedAs" in result ? (
                                <div className="text-textMain/70">Saved as: {result.savedAs}</div>
                            ) : null}
                            {"bytes" in result ? (
                                <div className="text-textMain/70">Size: {result.bytes} bytes</div>
                            ) : null}
                            {reportId ? (
                                <div className="text-textMain/70">Report ID: {reportId}</div>
                            ) : null}
                        </div>
                    )}
                </div>

                {reportId ? (
                    <div className="mt-4">
                        {loadingFindings ? (
                            <div className="text-sm text-textMain/70">Loading findings...</div>
                        ) : (
                            <NessusReportView findings={findings} />
                        )}
                    </div>
                ) : null}
            </div>
        </div>
    );
}
