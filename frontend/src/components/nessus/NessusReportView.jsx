import React from "react";
import NessusFindingsTable from "./NessusFindingsTable";

export default function NessusReportView({ findings }) {
    return (
        <div className="w-full">
            {/* Top row placeholders for graphs */}
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-4">
                    <div className="text-sm font-semibold text-slate-200">Bar Graph</div>
                    <div className="mt-3 h-40 rounded-lg border border-dashed border-slate-700" />
                </div>

                <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-4">
                    <div className="text-sm font-semibold text-slate-200">Another Graph</div>
                    <div className="mt-3 h-40 rounded-lg border border-dashed border-slate-700" />
                </div>
            </div>

            {/* Bottom row: AI summary placeholder + raw table */}
            <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-4">
                    <div className="text-sm font-semibold text-slate-200">AI Summary</div>
                    <div className="mt-2 text-sm text-slate-400">
                        (Later: generate a summary from top severities, hosts, common plugins, etc.)
                    </div>
                </div>

                <NessusFindingsTable findings={findings} />
            </div>
        </div>
    );
}