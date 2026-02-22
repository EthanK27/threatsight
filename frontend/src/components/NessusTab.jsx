import { useState } from "react";
import { fetchLatestNessusReport, uploadAndProcessNessusPdf } from "../api/nessus";

export default function NessusTab() {
    const [file, setFile] = useState(null);
    const [status, setStatus] = useState("idle"); // idle | uploading | success | error | loading
    const [uploadResult, setUploadResult] = useState(null);
    const [latestData, setLatestData] = useState(null);
    const [error, setError] = useState("");

    const loadLatestReport = async () => {
        setStatus("loading");
        setError("");
        try {
            const data = await fetchLatestNessusReport();
            setLatestData(data);
            setStatus("success");
        } catch (err) {
            setStatus("error");
            setError(err?.message || "Failed loading latest report");
        }
    };

    const uploadPdf = async () => {
        if (!file) return;

        setStatus("uploading");
        setError("");
        setUploadResult(null);

        try {
            const reportName = file.name.replace(/\.pdf$/i, "").trim();
            const data = await uploadAndProcessNessusPdf({ file, reportName });
            setUploadResult(data);

            const latest = await fetchLatestNessusReport();
            setLatestData(latest);
            setStatus("success");
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
                        disabled={!file || status === "uploading" || status === "loading"}
                        className={[
                            "px-4 py-2 rounded-md text-sm font-medium border border-white/10",
                            !file || status === "uploading" || status === "loading"
                                ? "bg-white/5 opacity-50 cursor-not-allowed"
                                : "bg-accent/30 hover:bg-accent/40",
                        ].join(" ")}
                    >
                        {status === "uploading"
                            ? "Uploading + Processing..."
                            : status === "loading"
                                ? "Loading..."
                                : "Upload PDF"}
                    </button>

                    <button
                        type="button"
                        onClick={loadLatestReport}
                        disabled={status === "uploading" || status === "loading"}
                        className={[
                            "px-4 py-2 rounded-md text-sm font-medium border border-white/10",
                            status === "uploading" || status === "loading"
                                ? "bg-white/5 opacity-50 cursor-not-allowed"
                                : "bg-white/10 hover:bg-white/20",
                        ].join(" ")}
                    >
                        Load Latest Stored Report
                    </button>

                    {status === "error" && <div className="text-sm text-red-300">{error}</div>}

                    {uploadResult && (
                        <div className="text-sm bg-white/5 border border-white/10 rounded-md p-3">
                            <div className="font-medium mb-1">Upload + AI + DB complete</div>
                            <div className="text-textMain/70">Saved as: {uploadResult.savedAs}</div>
                            <div className="text-textMain/70">
                                Parsed vulnerabilities: {uploadResult?.analysis?.vulnerabilityCount || 0}
                            </div>
                            <div className="text-textMain/70">
                                Report ID: {uploadResult?.db?.reportId || "n/a"}
                            </div>
                        </div>
                    )}

                    {latestData && (
                        <div className="text-sm bg-white/5 border border-white/10 rounded-md p-3">
                            <div className="font-medium mb-1">Latest Report Pull (from DB)</div>
                            <div className="text-textMain/70">
                                Report: {latestData?.report?.reportName || "none"}
                            </div>
                            <div className="text-textMain/70">
                                Items: {Array.isArray(latestData?.items) ? latestData.items.length : 0}
                            </div>
                            <pre className="mt-3 overflow-x-auto max-h-80 text-xs whitespace-pre-wrap break-all">
                                {JSON.stringify(latestData, null, 2)}
                            </pre>
                        </div>
                    )}
                </div>
            </div>
            
        </div>
    );
}
