import React, { useMemo, useState } from "react";
import { formatDateTime, safeString } from "../../utils/formatters";

const COLUMNS = [
  { key: "timestamp", label: "Timestamp" },
  { key: "SrcIP", label: "Source IP" },
  { key: "DestIP", label: "Destination IP" },
  { key: "Protocol", label: "Protocol" },
  { key: "Info", label: "Info" },
];

export default function WiresharkFindingsTable({ findings = [] }) {
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const searched = !q
      ? findings
      : findings.filter((f) => {
          const haystack = [f.timestamp, f.SrcIP, f.DestIP, f.Protocol, f.Info, f.reportId, f._id]
            .map(safeString)
            .join(" ")
            .toLowerCase();
          return haystack.includes(q);
        });

    return [...searched].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [findings, query]);

  return (
    <div className="rounded-xl border border-white/10 bg-white/5">
      <div className="flex items-center justify-between gap-3 border-b border-white/10 px-4 py-3">
        <div className="text-sm font-semibold text-textMain">Table Data</div>

        <div className="flex items-center gap-2">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search IP, protocol, info..."
            className="w-64 max-w-full rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-textMain outline-none"
          />
          <div className="text-xs text-textMain/60">{filtered.length} rows</div>
        </div>
      </div>

      <div className="max-h-[420px] overflow-auto">
        <table className="w-full border-collapse text-left text-sm">
          <thead className="sticky top-0 bg-[#0b0f16]">
            <tr>
              {COLUMNS.map((column) => (
                <th
                  key={column.key}
                  className="whitespace-nowrap border-b border-white/10 px-4 py-3 text-xs font-semibold uppercase tracking-wide text-textMain/70"
                >
                  {column.label}
                </th>
              ))}
            </tr>
          </thead>

          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={COLUMNS.length} className="px-4 py-6 text-textMain/60">
                  No packets found.
                </td>
              </tr>
            ) : (
              filtered.map((finding) => (
                <tr
                  key={safeString(finding._id) || `${safeString(finding.reportId)}-${safeString(finding.timestamp)}-${safeString(finding.SrcIP)}`}
                  className="hover:bg-white/5"
                >
                  <td className="whitespace-nowrap border-b border-white/5 px-4 py-3">
                    {formatDateTime(finding.timestamp)}
                  </td>
                  <td className="whitespace-nowrap border-b border-white/5 px-4 py-3">{safeString(finding.SrcIP)}</td>
                  <td className="whitespace-nowrap border-b border-white/5 px-4 py-3">{safeString(finding.DestIP)}</td>
                  <td className="border-b border-white/5 px-4 py-3">
                    <span className="inline-flex rounded-full border border-white/20 bg-white/10 px-2 py-1 text-xs font-semibold text-textMain">
                      {safeString(finding.Protocol) || "Unknown"}
                    </span>
                  </td>
                  <td className="min-w-[420px] border-b border-white/5 px-4 py-3 text-textMain/85">{safeString(finding.Info)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
