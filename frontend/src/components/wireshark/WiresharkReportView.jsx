import React, { useEffect, useMemo, useRef, useState } from "react";
import * as echarts from "echarts";
import WiresharkFindingsTable from "./WiresharkFindingsTable";

const PROTOCOL_COLORS = ["#22c55e", "#3b82f6", "#f97316", "#eab308", "#a855f7", "#14b8a6"];
const QUICK_PROMPTS = [
  "Summarize selected logs",
  "Why is this suspicious?",
  "Show likely MITRE technique",
  "Create investigation checklist",
];

function normalizeProtocol(value) {
  const raw = String(value || "").trim();
  return raw || "Unknown";
}

function countTop(items, key) {
  const counts = new Map();
  for (const item of items) {
    const value = String(item?.[key] || "Unknown").trim() || "Unknown";
    counts.set(value, (counts.get(value) || 0) + 1);
  }

  const [label, count] = Array.from(counts.entries()).sort((a, b) => b[1] - a[1])[0] || ["-", 0];
  return { label, count };
}

export default function WiresharkReportView({ findings = [] }) {
  const chartRef = useRef(null);
  const [prompt, setPrompt] = useState("");
  const [promptOut, setPromptOut] = useState("");

  const chartData = useMemo(() => {
    const protocolTotals = new Map();
    const bucketCounts = new Map();

    for (const finding of findings) {
      const protocol = normalizeProtocol(finding.Protocol);
      protocolTotals.set(protocol, (protocolTotals.get(protocol) || 0) + 1);

      const timestamp = new Date(finding.timestamp);
      if (Number.isNaN(timestamp.getTime())) continue;

      timestamp.setSeconds(0, 0);
      const bucketKey = timestamp.getTime();

      if (!bucketCounts.has(bucketKey)) {
        bucketCounts.set(bucketKey, new Map());
      }

      const bucket = bucketCounts.get(bucketKey);
      bucket.set(protocol, (bucket.get(protocol) || 0) + 1);
    }

    const topProtocols = Array.from(protocolTotals.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([protocol]) => protocol);

    const sortedBuckets = Array.from(bucketCounts.keys()).sort((a, b) => a - b);

    const labels = sortedBuckets.map((bucketKey) =>
      new Date(bucketKey).toLocaleString([], {
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      })
    );

    const series = topProtocols.map((protocol, index) => ({
      name: protocol,
      type: "line",
      stack: "traffic",
      smooth: true,
      showSymbol: false,
      areaStyle: { opacity: 0.18 },
      lineStyle: { width: 2, color: PROTOCOL_COLORS[index % PROTOCOL_COLORS.length] },
      itemStyle: { color: PROTOCOL_COLORS[index % PROTOCOL_COLORS.length] },
      data: sortedBuckets.map((bucketKey) => bucketCounts.get(bucketKey)?.get(protocol) || 0),
    }));

    const legend = topProtocols.map((protocol, index) => ({
      protocol,
      color: PROTOCOL_COLORS[index % PROTOCOL_COLORS.length],
      total: protocolTotals.get(protocol) || 0,
    }));

    return { labels, series, legend };
  }, [findings]);

  const summary = useMemo(() => {
    const totalPackets = findings.length;
    const topDestination = countTop(findings, "DestIP");
    const topSender = countTop(findings, "SrcIP");
    return { totalPackets, topDestination, topSender };
  }, [findings]);

  const promptContext = useMemo(() => {
    const now = Date.now();
    const recent = findings.filter((f) => {
      const ts = new Date(f?.timestamp).getTime();
      return Number.isFinite(ts) && now - ts <= 15 * 60 * 1000;
    });
    const sample = recent.length > 0 ? recent : findings;
    const suspicious = sample.filter((f) => /(scan|exploit|malware|failed|brute|c2|flood|suspicious|beacon|dos)/i.test(`${f?.Info || ""} ${f?.Protocol || ""}`));
    const topProtocol = countTop(sample, "Protocol");
    const topSource = countTop(sample, "SrcIP");

    return {
      windowLabel: recent.length > 0 ? "last 15 minutes" : "all loaded packets",
      packetCount: sample.length,
      suspiciousCount: suspicious.length,
      topProtocol,
      topSource,
    };
  }, [findings]);

  const runPrompt = () => {
    setPromptOut(
      [
        `Prompt: ${prompt || "Summarize last 15 minutes"}.`,
        `Window: ${promptContext.windowLabel}.`,
        `Packets: ${promptContext.packetCount}, suspicious-pattern hits: ${promptContext.suspiciousCount}.`,
        `Top protocol: ${promptContext.topProtocol.label} (${promptContext.topProtocol.count}).`,
        `Top source: ${promptContext.topSource.label} (${promptContext.topSource.count}).`,
        `Top destination: ${summary.topDestination.label} (${summary.topDestination.count}).`,
      ].join(" ")
    );
  };

  useEffect(() => {
    if (!chartRef.current || chartData.series.length === 0 || chartData.labels.length === 0) return;

    const chart = echarts.init(chartRef.current);

    chart.setOption({
      backgroundColor: "transparent",
      tooltip: {
        trigger: "axis",
        axisPointer: { type: "line" },
      },
      grid: { left: "4%", right: "4%", top: "8%", bottom: "8%", containLabel: true },
      xAxis: {
        type: "category",
        boundaryGap: false,
        data: chartData.labels,
        axisLine: { lineStyle: { color: "#475569" } },
        axisLabel: { color: "#cbd5e1", hideOverlap: true },
      },
      yAxis: {
        type: "value",
        minInterval: 1,
        axisLine: { lineStyle: { color: "#475569" } },
        splitLine: { lineStyle: { color: "rgba(148, 163, 184, 0.2)" } },
        axisLabel: { color: "#cbd5e1" },
      },
      series: chartData.series,
    });

    const onResize = () => chart.resize();
    window.addEventListener("resize", onResize);

    return () => {
      window.removeEventListener("resize", onResize);
      chart.dispose();
    };
  }, [chartData]);

  return (
    <div className="w-full space-y-4">
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-3">
          <div className="text-xs text-slate-400">Packet Count</div>
          <div className="mt-1 text-xl font-semibold text-slate-100">{summary.totalPackets}</div>
        </div>
        <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-3">
          <div className="text-xs text-slate-400">Top Destination IP</div>
          <div className="mt-1 text-base font-semibold text-slate-100">{summary.topDestination.label}</div>
          <div className="text-xs text-slate-400">{summary.topDestination.count} packets</div>
        </div>
        <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-3">
          <div className="text-xs text-slate-400">Top Sender</div>
          <div className="mt-1 text-base font-semibold text-slate-100">{summary.topSender.label}</div>
          <div className="text-xs text-slate-400">{summary.topSender.count} packets</div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(240px,1fr)]">
        <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-4">
          <div className="text-sm font-semibold text-slate-200">Network Traffic</div>
          <div className="mt-1 text-xs text-slate-400">Stacked line chart by protocol over time</div>

          {chartData.series.length === 0 || chartData.labels.length === 0 ? (
            <div className="mt-4 flex h-64 items-center justify-center rounded-lg border border-dashed border-slate-600/80 bg-slate-900/40 text-sm text-slate-400">
              Not enough timestamp data to render chart.
            </div>
          ) : (
            <div ref={chartRef} className="mt-3 h-64 w-full" />
          )}
        </div>

        <div className="rounded-xl border border-emerald-500/60 bg-emerald-950/15 p-4">
          <div className="text-lg font-semibold text-emerald-300">Legend</div>
          <div className="mt-3 space-y-2">
            {chartData.legend.length === 0 ? (
              <div className="rounded-md border border-dashed border-emerald-600/60 p-3 text-sm text-emerald-200/80">
                No protocol data available.
              </div>
            ) : (
              chartData.legend.map((item) => (
                <div
                  key={item.protocol}
                  className="flex items-center justify-between rounded-md border border-emerald-600/40 bg-emerald-900/20 px-3 py-2"
                >
                  <div className="flex items-center gap-2">
                    <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                    <span className="text-sm font-medium text-emerald-100">{item.protocol}</span>
                  </div>
                  <span className="text-xs text-emerald-200/80">{item.total}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-white/15 bg-white/5 p-4">
        <div className="text-sm font-semibold">Gemini Box for input</div>
        <div className="mt-2 grid gap-2 md:grid-cols-[minmax(0,1fr)_auto]">
          <textarea
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
            placeholder="Explain this Wireshark traffic in plain English"
            className="h-24 rounded-md border border-white/15 bg-black/25 p-2 text-sm outline-none"
          />
          <button type="button" onClick={runPrompt} className="rounded-md border border-white/15 bg-white/10 px-3 py-2 text-xs font-semibold">
            Run Prompt
          </button>
        </div>
        <div className="mt-2 flex flex-wrap gap-2 text-xs">
          {QUICK_PROMPTS.map((quick) => (
            <button key={quick} type="button" onClick={() => setPrompt(quick)} className="rounded-full border border-white/15 bg-white/10 px-3 py-1">
              {quick}
            </button>
          ))}
        </div>
        <div className="mt-2 min-h-12 rounded-md border border-dashed border-white/20 bg-black/20 p-2 text-xs text-textMain/80">
          {promptOut || "Output preview appears here."}
        </div>
      </div>

      <WiresharkFindingsTable findings={findings} />
    </div>
  );
}
