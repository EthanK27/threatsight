import { useCallback, useEffect, useState } from "react";
import { fetchAllWiresharkItems } from "../api/wireshark";
import WiresharkReportView from "./wireshark/WiresharkReportView";

export default function WiresharkTab() {
    const [status, setStatus] = useState("idle");
    const [wireData, setWireData] = useState(null);
    const [error, setError] = useState("");

    const loadWiresharkItems = useCallback(async () => {
        setStatus("loading");
        setError("");

        try {
            const data = await fetchAllWiresharkItems();
            setWireData(data);
            setStatus("success");
        } catch (err) {
            setError(err?.message || "Failed loading Wireshark packets");
            setStatus("error");
        }
    }, []);

    useEffect(() => {
        loadWiresharkItems();
    }, [loadWiresharkItems]);

    const findings = Array.isArray(wireData?.items) ? wireData.items : [];

    return (
        <div className="w-full">
            <h2 className="mb-4 text-lg font-semibold">Network Traffic</h2>

            <div className="mb-4 flex flex-col gap-3">
                <div className="flex flex-wrap items-center gap-3">
                    <button
                        type="button"
                        onClick={loadWiresharkItems}
                        disabled={status === "loading"}
                        className={[
                            "px-4 py-2 rounded-md text-sm font-medium border border-white/10",
                            status === "loading"
                                ? "bg-white/5 opacity-50 cursor-not-allowed"
                                : "bg-white/10 hover:bg-white/20",
                        ].join(" ")}
                    >
                        {status === "loading" ? "Loading..." : "Reload Wireshark Table"}
                    </button>

                    <div className="text-xs text-textMain/70">Total records: {wireData?.count ?? findings.length}</div>
                </div>

                {status === "error" && <div className="text-sm text-red-300">{error}</div>}
            </div>

            {findings.length > 0 ? (
                <WiresharkReportView findings={findings} />
            ) : (
                <div className="rounded-xl border border-white/10 bg-white/5 p-6 text-sm text-textMain/70">
                    {status === "loading" ? "Loading Wireshark table data..." : "No rows found in VulnWiresharks."}
                </div>
            )}
        </div>
    );
}
