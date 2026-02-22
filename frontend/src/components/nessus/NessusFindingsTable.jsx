import React, { useMemo, useState } from "react";
import { formatDateTime, formatScore, safeString } from "../../utils/formatters";
import { normalizeSeverity, severityColor, severityRank } from "../../utils/severity";

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
    const searched = !q
      ? findings
      : findings.filter((f) => {
          const hay = [f.severity, f.name, f.host, f.pluginId, f.reportId, f._id]
            .map(safeString)
            .join(" ")
            .toLowerCase();
          return hay.includes(q);
        });

    return [...searched].sort((a, b) => {
      const severityDiff = severityRank(a.severity) - severityRank(b.severity);
      if (severityDiff !== 0) return severityDiff;
      return String(a.name || "").localeCompare(String(b.name || ""));
    });
  }, [findings, query]);

  return (
    <div className="rounded-xl border border-white/10 bg-white/5">
      <div className="flex items-center justify-between gap-3 border-b border-white/10 px-4 py-3">
        <div className="text-sm font-semibold text-textMain">Findings Table</div>

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

      <div className="max-h-[420px] overflow-auto">
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
              filtered.map((f) => {
                const severityLabel = normalizeSeverity(f.severity);
                return (
                  <tr
                    key={safeString(f._id) || `${safeString(f.reportId)}-${safeString(f.pluginId)}-${safeString(f.host)}`}
                    className="hover:bg-white/5"
                  >
                    <td className="border-b border-white/5 px-4 py-3">
                      <span
                        className="inline-flex rounded-full px-2 py-1 text-xs font-semibold text-white"
                        style={{ backgroundColor: severityColor(f.severity) }}
                      >
                        {severityLabel}
                      </span>
                    </td>
                    <td className="min-w-[360px] border-b border-white/5 px-4 py-3">{safeString(f.name)}</td>
                    <td className="border-b border-white/5 px-4 py-3">{safeString(f.host)}</td>
                    <td className="border-b border-white/5 px-4 py-3">{safeString(f.pluginId)}</td>
                    <td className="border-b border-white/5 px-4 py-3">{formatScore(f.cvssV3)}</td>
                    <td className="border-b border-white/5 px-4 py-3">{formatScore(f.vpr)}</td>
                    <td className="border-b border-white/5 px-4 py-3">{formatScore(f.epss, 3)}</td>
                    <td className="border-b border-white/5 px-4 py-3">{formatDateTime(f.createdAt)}</td>
                    <td className="border-b border-white/5 px-4 py-3">{formatDateTime(f.updatedAt)}</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}