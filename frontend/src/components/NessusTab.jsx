import { useState } from "react";

export default function NessusTab() {
    const [file, setFile] = useState(null);
    const [status, setStatus] = useState("idle"); // idle | uploading | success | error
    const [result, setResult] = useState(null);
    const [error, setError] = useState("");

    const uploadPdf = async () => {
        if (!file) return;

        setStatus("uploading");
        setError("");
        setResult(null);

        try {
            const formData = new FormData();
            formData.append("nessusPdf", file); // MUST match multer field name

            const res = await fetch("/api/analysis/nessus/upload", {
                method: "POST",
                body: formData,
            });

            const rawBody = await res.text();
            let data = null;

            if (rawBody) {
                try {
                    data = JSON.parse(rawBody);
                } catch {
                    data = null;
                }
            }

            if (!res.ok) {
                throw new Error(data?.error || `Upload failed (${res.status})`);
            }

            if (!data) {
                throw new Error(
                    "Upload succeeded but response was not JSON. Check API route/proxy."
                );
            }

            setResult(data);
            setStatus("success");
        } catch (err) {
            setError(err?.message || "Upload failed");
            setStatus("error");
        }
    };

    return (
        <div>
            <h2 className="text-lg font-semibold mb-4">Nessus PDF Upload</h2>

            <div className="flex flex-col gap-4 max-w-lg">
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
                        "px-4 py-2 rounded-md text-sm font-medium border border-white/10",
                        !file || status === "uploading"
                            ? "bg-white/5 opacity-50 cursor-not-allowed"
                            : "bg-accent/30 hover:bg-accent/40",
                    ].join(" ")}
                >
                    {status === "uploading" ? "Uploading..." : "Upload PDF"}
                </button>

                {status === "error" && (
                    <div className="text-red-300 text-sm">{error}</div>
                )}

                {status === "success" && result && (
                    <div className="text-sm bg-white/5 border border-white/10 rounded-md p-3">
                        <div className="font-medium mb-1">Upload successful</div>
                        <div className="text-textMain/70">Saved as: {result.savedAs}</div>
                        <div className="text-textMain/70">Size: {result.bytes} bytes</div>
                    </div>
                )}
            </div>
        </div>
    );
}
