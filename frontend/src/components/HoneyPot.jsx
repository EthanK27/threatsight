import { useEffect, useMemo, useRef, useState } from "react";
import * as echarts from "echarts";
import { fetchAllHoneypotItems, getHoneypotStreamUrl } from "../api/honeypot";
import { safeString } from "../utils/formatters";
import { normalizeSeverity, severityColor } from "../utils/severity";

const LEVELS = ["Critical", "High", "Medium", "Low"];
const QUICK = [
  "Summarize selected logs",
  "Why is this suspicious?",
  "Show likely MITRE technique",
  "Create investigation checklist",
];

const protoMap = { 22: "SSH", 53: "DNS", 80: "HTTP", 443: "TLS", 445: "SMB", 3389: "RDP" };
const rank = (s) => ({ Critical: 4, High: 3, Medium: 2, Low: 1 }[s] || 0);

const parseTimestamp = (value) => {
  if (value instanceof Date) return value;
  if (typeof value === "number") return new Date(value);

  const raw = safeString(value).trim();
  if (!raw) return new Date();

  const plain = raw.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/);
  if (plain) {
    const [, y, m, d, hh, mm, ss, frac = "0"] = plain;
    const ms = Number(frac.slice(0, 3).padEnd(3, "0"));
    return new Date(Number(y), Number(m) - 1, Number(d), Number(hh), Number(mm), Number(ss), ms);
  }

  const parsed = new Date(raw);
  return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
};

const formatLocal = (date) => {
  return date.toLocaleString([], {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
};

const deriveSeverity = (row = {}) => {
  if (safeString(row.severity)) return normalizeSeverity(row.severity);
  const logtype = Number(row.logtype ?? row.log_type);
  if (!Number.isNaN(logtype)) {
    if (logtype >= 5000) return "Critical";
    if (logtype >= 4000) return "High";
    if (logtype >= 3000) return "Medium";
  }
  const t = `${safeString(row.attack_type)} ${safeString(row.info)} ${safeString(row.name)}`.toLowerCase();
  if (/(malware|trojan|ransom|beacon|c2)/.test(t)) return "Critical";
  if (/(failed|brute|auth|ssh login)/.test(t)) return "High";
  if (/(scan|probe|recon)/.test(t)) return "Medium";
  return "Low";
};

const normalize = (row = {}) => {
  const tsRaw = row.timestamp || row.createdAt || row.updatedAt || new Date().toISOString();
  const timestamp = parseTimestamp(tsRaw);
  const src = row.src_ip || row.srcIP || row.source || row.source_ip || "-";
  const dst = row.dst_ip || row.dstIP || row.destination || row.dest_ip || "-";
  const srcPort = row.src_port ?? row.source_port ?? null;
  const dstPort = row.dst_port ?? row.dest_port ?? null;
  const protocol = row.protocol || row.proto || row.service || protoMap[Number(dstPort)] || protoMap[Number(srcPort)] || "Unknown";
  const alert = row.attack_type || row.name || protocol || "Suspicious activity";

  return {
    ...row,
    id: safeString(row._id) || safeString(row.event_id) || `${safeString(tsRaw)}-${safeString(src)}-${safeString(dst)}`,
    timestamp,
    timestampText: formatLocal(timestamp),
    src: safeString(src),
    dst: safeString(dst),
    protocol: safeString(protocol),
    info: safeString(row.info || row.name || row.attack_type || "honeypot event"),
    severity: deriveSeverity(row),
    alert: safeString(alert),
  };
};

const merge = (cur, incoming, max = 1600) => {
  const map = new Map();
  incoming.forEach((r) => r?.id && map.set(r.id, r));
  cur.forEach((r) => !map.has(r.id) && map.set(r.id, r));
  return Array.from(map.values()).sort((a, b) => b.timestamp - a.timestamp).slice(0, max);
};

const buildAttack = (rows) => {
  const now = Date.now();
  const recent10 = rows.filter((r) => now - r.timestamp.getTime() <= 10 * 60 * 1000);
  const recent2 = recent10.filter((r) => now - r.timestamp.getTime() <= 2 * 60 * 1000);
  const reasons = [];
  let score = 0;

  const srcCounts = new Map();
  recent10.forEach((r) => srcCounts.set(r.src, (srcCounts.get(r.src) || 0) + 1));
  const loudSrc = Array.from(srcCounts.entries()).find(([, count]) => count >= 8);
  if (loudSrc) {
    score += 3;
    reasons.push(`${loudSrc[1]} events from ${loudSrc[0]}`);
  }

  const failRows = recent10.filter((r) => /(failed|invalid|auth|ssh login)/i.test(r.info));
  if (failRows.length >= 3) {
    score += 3;
    reasons.push(`${failRows.length} authentication failures`);
  }

  const riskyRows = recent10.filter((r) => rank(r.severity) >= 3);
  if (riskyRows.length >= 3) {
    score += 4;
    reasons.push(`${riskyRows.length} High/Critical events`);
  }

  if (recent2.length >= 15) {
    score += 4;
    reasons.push(`Burst traffic: ${recent2.length} events in 2 minutes`);
  }

  const srcTargets = new Map();
  recent10.forEach((r) => {
    if (!srcTargets.has(r.src)) srcTargets.set(r.src, new Set());
    srcTargets.get(r.src).add(r.dst);
  });
  const spread = Array.from(srcTargets.entries()).find(([, set]) => set.size >= 4);
  if (spread) {
    score += 2;
    reasons.push(`Source ${spread[0]} touched ${spread[1].size} targets`);
  }

  const confidence = Math.min(100, score * 12 + Math.min(20, Math.floor(recent10.length / 2)));
  const status = confidence >= 65 ? "YES" : confidence >= 30 ? "POSSIBLE" : "NO";
  const suspiciousPool = riskyRows.length > 0 ? riskyRows : failRows.length > 0 ? failRows : recent10;
  const since = suspiciousPool.length > 0 ? suspiciousPool[suspiciousPool.length - 1].timestamp : null;

  return {
    status,
    confidence,
    reason: reasons[0] || "No high-risk pattern in last 10 minutes",
    since,
  };
};

export default function HoneypotTab() {
  const chartRef = useRef(null);
  const chartInstanceRef = useRef(null);
  const [rows, setRows] = useState([]);
  const [streamState, setStreamState] = useState("connecting");
  const [error, setError] = useState("");
  const [selectedAlertId, setSelectedAlertId] = useState("");
  const [triageFilter, setTriageFilter] = useState("All");
  const [triageSearch, setTriageSearch] = useState("");
  const [triageMeta, setTriageMeta] = useState({});
  const [prompt, setPrompt] = useState("");
  const [promptOut, setPromptOut] = useState("");

  useEffect(() => {
    fetchAllHoneypotItems()
      .then((data) => setRows((prev) => merge(prev, (data?.items || []).map(normalize))))
      .catch((err) => setError(err?.message || "Failed to load Honeypot rows"));
  }, []);

  useEffect(() => {
    const stream = new EventSource(getHoneypotStreamUrl(300));
    stream.onopen = () => {
      setStreamState("live");
      setError("");
    };
    stream.onerror = () => setStreamState("reconnecting");

    stream.addEventListener("snapshot", (event) => {
      try {
        setRows((prev) => merge(prev, (JSON.parse(event.data)?.items || []).map(normalize)));
      } catch {
        setError("Bad snapshot payload");
      }
    });

    stream.addEventListener("events", (event) => {
      try {
        setRows((prev) => merge(prev, (JSON.parse(event.data)?.items || []).map(normalize)));
      } catch {
        setError("Bad event payload");
      }
    });

    stream.addEventListener("stream_error", (event) => {
      try {
        setError(JSON.parse(event.data)?.message || "Stream error");
      } catch {
        setError("Stream error");
      }
    });

    return () => stream.close();
  }, []);

  const chartData = useMemo(() => {
    const map = new Map();
    const cutoff = Date.now() - 60 * 60 * 1000;

    rows.forEach((r) => {
      if (r.timestamp.getTime() < cutoff) return;
      const d = new Date(r.timestamp);
      d.setSeconds(0, 0);
      const k = d.getTime();
      if (!map.has(k)) {
        map.set(k, {
          label: d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          total: 0,
          Critical: 0,
          High: 0,
          Medium: 0,
          Low: 0,
        });
      }
      const b = map.get(k);
      b.total += 1;
      b[LEVELS.includes(r.severity) ? r.severity : "Low"] += 1;
    });

    const keys = Array.from(map.keys()).sort((a, b) => a - b);
    const total = keys.map((k) => map.get(k).total);
    const maxY = Math.max(5, ...total);

    return {
      labels: keys.map((k) => map.get(k).label),
      total,
      maxY,
      sev: Object.fromEntries(LEVELS.map((l) => [l, keys.map((k) => map.get(k)[l])])),
    };
  }, [rows]);

  useEffect(() => {
    if (!chartRef.current) return;
    if (!chartInstanceRef.current) chartInstanceRef.current = echarts.init(chartRef.current);
    const chart = chartInstanceRef.current;

    chart.setOption({
      tooltip: { trigger: "axis" },
      legend: {
        orient: "vertical",
        right: 6,
        top: "middle",
        textStyle: { color: "#d6ecf3" },
      },
      grid: { top: 20, right: 132, left: 6, bottom: 6, containLabel: true },
      xAxis: {
        type: "category",
        boundaryGap: false,
        data: chartData.labels,
        axisLabel: { color: "rgba(214,236,243,0.75)" },
      },
      yAxis: {
        type: "value",
        min: 0,
        max: Math.ceil(chartData.maxY * 1.2),
        minInterval: 1,
        axisLabel: { color: "rgba(214,236,243,0.75)" },
        splitLine: { lineStyle: { color: "rgba(214,236,243,0.12)" } },
      },
      series: [
        { name: "Events/min", type: "line", smooth: true, showSymbol: false, data: chartData.total, lineStyle: { color: "#cbd5e1" }, itemStyle: { color: "#cbd5e1" } },
        { name: "Critical", type: "line", stack: "sev", smooth: true, showSymbol: false, data: chartData.sev.Critical, areaStyle: { opacity: 0.24 }, lineStyle: { color: "#dc2626" }, itemStyle: { color: "#dc2626" } },
        { name: "High", type: "line", stack: "sev", smooth: true, showSymbol: false, data: chartData.sev.High, areaStyle: { opacity: 0.2 }, lineStyle: { color: "#ea580c" }, itemStyle: { color: "#ea580c" } },
        { name: "Medium", type: "line", stack: "sev", smooth: true, showSymbol: false, data: chartData.sev.Medium, areaStyle: { opacity: 0.18 }, lineStyle: { color: "#ca8a04" }, itemStyle: { color: "#ca8a04" } },
        { name: "Low", type: "line", stack: "sev", smooth: true, showSymbol: false, data: chartData.sev.Low, areaStyle: { opacity: 0.14 }, lineStyle: { color: "#0284c7" }, itemStyle: { color: "#0284c7" } },
      ],
    });

    const onResize = () => chart.resize();
    window.addEventListener("resize", onResize);
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(chartRef.current);

    return () => {
      window.removeEventListener("resize", onResize);
      observer.disconnect();
    };
  }, [chartData]);

  useEffect(() => () => chartInstanceRef.current?.dispose(), []);

  const attack = useMemo(() => buildAttack(rows), [rows]);
  const sevOpts = ["All", ...LEVELS];

  const triageRows = useMemo(() => {
    const q = triageSearch.trim().toLowerCase();
    return rows
      .filter((r) => triageFilter === "All" || r.severity === triageFilter)
      .filter((r) => !q || `${r.alert} ${r.src} ${r.dst} ${r.info}`.toLowerCase().includes(q))
      .map((r) => ({
        ...r,
        status: triageMeta[r.id]?.status || (rank(r.severity) >= 3 ? "Open" : "Investigating"),
        owner: triageMeta[r.id]?.owner || "Unassigned",
      }))
      .sort((a, b) => rank(b.severity) - rank(a.severity) || b.timestamp - a.timestamp)
      .slice(0, 120);
  }, [rows, triageFilter, triageSearch, triageMeta]);

  const selectedTriage = triageRows.find((r) => r.id === selectedAlertId) || null;
  const setTriage = (patch) =>
    selectedAlertId &&
    setTriageMeta((prev) => ({
      ...prev,
      [selectedAlertId]: { ...(prev[selectedAlertId] || {}), ...patch },
    }));

  const runPrompt = () => {
    const last15 = rows.filter((r) => Date.now() - r.timestamp.getTime() <= 15 * 60 * 1000);
    const top = Object.entries(last15.reduce((acc, r) => ((acc[r.src] = (acc[r.src] || 0) + 1), acc), {})).sort((a, b) => b[1] - a[1])[0];
    setPromptOut(
      [
        `Prompt: ${prompt || "Summarize last 15 minutes"}.`,
        `Events: ${last15.length}, high-risk: ${last15.filter((r) => rank(r.severity) >= 3).length}.`,
        top ? `Top source: ${top[0]} (${top[1]}).` : "Top source: n/a.",
        `Status: ${attack.status} (${attack.confidence}%).`,
        selectedTriage ? `Focus alert: ${selectedTriage.alert} from ${selectedTriage.src} to ${selectedTriage.dst}.` : "No selected triage alert.",
      ].join(" ")
    );
  };

  const statusClass =
    attack.status === "YES"
      ? "border-red-400/70 bg-red-500/10 text-red-200"
      : attack.status === "POSSIBLE"
        ? "border-yellow-400/70 bg-yellow-500/10 text-yellow-100"
        : "border-emerald-400/70 bg-emerald-500/10 text-emerald-100";

  return (
    <div className="w-full space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold">Internal Network - HoneyPot Monitor</h2>
        <div className="text-xs text-textMain/70">
          Stream: <span className="font-semibold text-textMain">{streamState}</span>
          {error ? <span className="ml-2 text-red-300">({error})</span> : null}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <section className="rounded-xl border border-white/15 bg-white/5 p-4 xl:col-span-7 flex min-h-[28rem] flex-col">
          <div className="text-sm font-semibold">Live Graph</div>
          <div className="text-xs text-textMain/70">Events/min + stacked severity (last 60 min)</div>
          {chartData.labels.length === 0 ? (
            <div className="mt-3 flex min-h-0 flex-1 items-center justify-center rounded-lg border border-dashed border-white/20 bg-black/20 text-sm text-textMain/70">
              Waiting for Honeypot events...
            </div>
          ) : (
            <div ref={chartRef} className="mt-3 min-h-0 flex-1 w-full" />
          )}
        </section>

        <section className={`rounded-xl border p-4 xl:col-span-5 ${statusClass}`}>
          <div className="text-sm font-semibold">Active Attack?</div>
          <div className="mt-2 text-2xl font-bold">{attack.status}</div>
          <div className="mt-1 text-sm">Confidence: {attack.confidence}%</div>
          <div className="mt-2 text-xs">Reason: {attack.reason}</div>
          <div className="mt-2 text-xs">Since: {attack.since ? formatLocal(attack.since) : "n/a"}</div>
        </section>

        <section className="rounded-xl border border-white/15 bg-white/5 p-4 xl:col-span-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="text-sm font-semibold">Actionable Alerts / Triage Queue</div>
            <div className="flex items-center gap-2">
              <select className="rounded-md border border-white/15 bg-black/25 px-2 py-1 text-xs" value={triageFilter} onChange={(e) => setTriageFilter(e.target.value)}>
                {sevOpts.map((o) => (
                  <option key={o}>{o}</option>
                ))}
              </select>
              <input value={triageSearch} onChange={(e) => setTriageSearch(e.target.value)} placeholder="Search" className="rounded-md border border-white/15 bg-black/25 px-2 py-1 text-xs" />
            </div>
          </div>

          <div className="mt-3 max-h-56 overflow-auto rounded-lg border border-white/10">
            <table className="w-full border-collapse text-left text-xs">
              <thead className="sticky top-0 bg-[#1a2430]">
                <tr>
                  {["Time", "Alert", "Src", "Dst", "Severity", "Status", "Owner"].map((h) => (
                    <th key={h} className="border-b border-white/10 px-2 py-2">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {triageRows.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-2 py-3 text-textMain/70">
                      No alerts for filters.
                    </td>
                  </tr>
                ) : (
                  triageRows.map((r) => (
                    <tr key={r.id} onClick={() => setSelectedAlertId(r.id)} className={`cursor-pointer hover:bg-white/10 ${selectedAlertId === r.id ? "bg-white/10" : ""}`}>
                      <td className="whitespace-nowrap border-b border-white/5 px-2 py-2">{r.timestampText}</td>
                      <td className="max-w-36 truncate border-b border-white/5 px-2 py-2">{r.alert}</td>
                      <td className="whitespace-nowrap border-b border-white/5 px-2 py-2">{r.src}</td>
                      <td className="whitespace-nowrap border-b border-white/5 px-2 py-2">{r.dst}</td>
                      <td className="border-b border-white/5 px-2 py-2">
                        <span className="rounded-full border px-2 py-0.5" style={{ borderColor: `${severityColor(r.severity)}99`, color: severityColor(r.severity) }}>
                          {r.severity}
                        </span>
                      </td>
                      <td className="whitespace-nowrap border-b border-white/5 px-2 py-2">{r.status}</td>
                      <td className="whitespace-nowrap border-b border-white/5 px-2 py-2">{r.owner}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="mt-3 flex flex-wrap gap-2 text-xs">
            <button type="button" onClick={() => setTriage({ status: "Acknowledged" })} className="rounded-md border border-white/15 bg-white/10 px-2 py-1 disabled:opacity-40" disabled={!selectedAlertId}>Acknowledge</button>
            <button type="button" onClick={() => setTriage({ status: "Assigned", owner: "SOC-1" })} className="rounded-md border border-white/15 bg-white/10 px-2 py-1 disabled:opacity-40" disabled={!selectedAlertId}>Assign</button>
            <button type="button" onClick={() => setTriage({ status: "Suppressed" })} className="rounded-md border border-white/15 bg-white/10 px-2 py-1 disabled:opacity-40" disabled={!selectedAlertId}>Suppress</button>
            <button type="button" onClick={() => setTriage({ status: "Case Open" })} className="rounded-md border border-white/15 bg-white/10 px-2 py-1 disabled:opacity-40" disabled={!selectedAlertId}>Open Case</button>
          </div>
        </section>

        <section className="rounded-xl border border-white/15 bg-white/5 p-4 xl:col-span-7">
          <div className="text-sm font-semibold">Gemini Box for input</div>
          <div className="mt-2 grid gap-2 md:grid-cols-[minmax(0,1fr)_auto]">
            <textarea value={prompt} onChange={(e) => setPrompt(e.target.value)} placeholder="Explain this alert in plain English" className="h-24 rounded-md border border-white/15 bg-black/25 p-2 text-sm outline-none" />
            <button type="button" onClick={runPrompt} className="rounded-md border border-white/15 bg-white/10 px-3 py-2 text-xs font-semibold">Run Prompt</button>
          </div>
          <div className="mt-2 flex flex-wrap gap-2 text-xs">
            {QUICK.map((q) => (
              <button key={q} type="button" onClick={() => setPrompt(q)} className="rounded-full border border-white/15 bg-white/10 px-3 py-1">
                {q}
              </button>
            ))}
          </div>
          <div className="mt-2 min-h-12 rounded-md border border-dashed border-white/20 bg-black/20 p-2 text-xs text-textMain/80">{promptOut || "Output preview appears here."}</div>
        </section>
      </div>
    </div>
  );
}
