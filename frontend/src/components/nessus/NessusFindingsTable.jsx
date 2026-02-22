import React, { useMemo, useState } from "react";

function safeStr(v) {
    if (v === null || v === undefined) return "";
    return String(v);
}

function formatDate(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return safeStr(iso);
    return d.toLocaleString();
}

const COLUMNS = [
    { key: "severity", label: "Severity" },
    { key: "name", label: "Name" },
    { key: "host", label: "Host" },
    { key: "pluginId", label: "Plugin ID" },
    { key: "cvssV3", label: "CVSS v3" },
    { key: "vpr", label: "VPR" },
    { key: "epss", label: "EPSS" },
    { key: "createdAt", label: "Created" },
    { key: "updatedAt", label: "Updated" },
];

export default function NessusFindingsTable({ findings = [] }) {
    const [query, setQuery] = useState("");

    const filtered = useMemo(() => {
        const q = query.trim().toLowerCase();
        if (!q) return findings;

        return findings.filter((f) => {
            const hay = [
                f.severity,
                f.name,
                f.host,
                f.pluginId,
                f.reportId,
                f._id,
            ]
                .map(safeStr)
                .join(" ")
                .toLowerCase();
            return hay.includes(q);
        });
    }, [findings, query]);

    return (
        <div className="rounded-xl border border-white/10 bg-white/5">
            <div className="flex items-center justify-between gap-3 border-b border-white/10 px-4 py-3">
                <div className="text-sm font-semibold text-textMain">
                    Raw Data pulled from DB (scroll)
                </div>

                <div className="flex items-center gap-2">
                    <input
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="Search host, pluginId, name..."
                        className="w-64 max-w-full rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-textMain outline-none"
                    />
                    <div className="text-xs text-textMain/60">{filtered.length} rows</div>
                </div>
            </div>

            {/* Fixed height + scroll inside box */}
            <div className="max-h-[320px] overflow-auto">
                <table className="w-full border-collapse text-left text-sm">
                    <thead className="sticky top-0 bg-[#0b0f16]">
                        <tr>
                            {COLUMNS.map((c) => (
                                <th
                                    key={c.key}
                                    className="whitespace-nowrap border-b border-white/10 px-4 py-3 text-xs font-semibold uppercase tracking-wide text-textMain/70"
                                >
                                    {c.label}
                                </th>
                            ))}
                        </tr>
                    </thead>

                    <tbody>
                        {filtered.length === 0 ? (
                            <tr>
                                <td colSpan={COLUMNS.length} className="px-4 py-6 text-textMain/60">
                                    No findings found.
                                </td>
                            </tr>
                        ) : (
                            filtered.map((f) => (
                                <tr
                                    key={
                                        safeStr(f._id) ||
                                        `${safeStr(f.reportId)}-${safeStr(f.pluginId)}-${safeStr(f.host)}`
                                    }
                                    className="hover:bg-white/5"
                                >
                                    <td className="border-b border-white/5 px-4 py-3">
                                        {safeStr(f.severity)}
                                    </td>
                                    <td className="min-w-[420px] border-b border-white/5 px-4 py-3">
                                        {safeStr(f.name)}
                                    </td>
                                    <td className="border-b border-white/5 px-4 py-3">
                                        {safeStr(f.host)}
                                    </td>
                                    <td className="border-b border-white/5 px-4 py-3">
                                        {safeStr(f.pluginId)}
                                    </td>
                                    <td className="border-b border-white/5 px-4 py-3">
                                        {safeStr(f.cvssV3)}
                                    </td>
                                    <td className="border-b border-white/5 px-4 py-3">
                                        {safeStr(f.vpr)}
                                    </td>
                                    <td className="border-b border-white/5 px-4 py-3">
                                        {safeStr(f.epss)}
                                    </td>
                                    <td className="border-b border-white/5 px-4 py-3">
                                        {formatDate(f.createdAt)}
                                    </td>
                                    <td className="border-b border-white/5 px-4 py-3">
                                        {formatDate(f.updatedAt)}
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
}