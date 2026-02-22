import React, { useEffect, useMemo, useRef, useState } from "react";
import * as echarts from "echarts";
import NessusFindingsTable from "./NessusFindingsTable";
import { normalizeSeverity, SEVERITY_COLORS, SEVERITY_ORDER } from "../../utils/severity";

const CHART_SEVERITIES = ["Critical", "High", "Medium", "Low"];
const CATEGORY_ORDER = [
  "Patching",
  "Hardening",
  "Cryptography",
  "Authentication",
  "Exposure",
  "Application",
  "Disclosure",
  "Malware",
  "Compliance",
  "Other",
];
const QUICK_PROMPTS = [
    "Prioritize the top 5 Critical/High findings by exploit risk and business impact.",
    "Give a remediation plan for the most affected host, ordered by fastest risk reduction.",
    "Identify findings with high CVSS/VPR/EPSS and explain why they should be patched first.",
    "List likely false positives to validate before remediation with quick verification steps.",
];

const normalizeCategory = (value) => {
  if (value === null || value === undefined) return "Other";
  const raw = String(value).trim();
  if (!raw) return "Other";
  const match = CATEGORY_ORDER.find(
    (category) => category.toLowerCase() === raw.toLowerCase()
  );
  return match || "Other";
};

export default function NessusReportView({ findings = [] }) {
  const severityChartRef = useRef(null);
  const hostChartRef = useRef(null);
  const matrixChartRef = useRef(null);
  const [prompt, setPrompt] = useState("");
  const [promptOut, setPromptOut] = useState("");

  const severityData = useMemo(() => {
    const counts = new Map(CHART_SEVERITIES.map((label) => [label, 0]));

    for (const finding of findings) {
      const label = normalizeSeverity(finding?.severity);
      if (!counts.has(label)) continue;
      counts.set(label, (counts.get(label) || 0) + 1);
    }

    return {
      categories: CHART_SEVERITIES,
      values: CHART_SEVERITIES.map((label) => counts.get(label) || 0),
    };
  }, [findings]);

  const topHosts = useMemo(() => {
    const counts = new Map();
    for (const finding of findings) {
      const host = String(finding?.host || "Unknown").trim() || "Unknown";
      counts.set(host, (counts.get(host) || 0) + 1);
    }

    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
  }, [findings]);

  const severityCategoryMatrix = useMemo(() => {
    const severities = [...SEVERITY_ORDER];
    const categories = [...CATEGORY_ORDER];
    const matrix = severities.map(() => categories.map(() => 0));
    const unknownSeverityIndex = severities.indexOf("Unknown");

    for (const finding of findings) {
      const severity = normalizeSeverity(finding?.severity);
      const category = normalizeCategory(finding?.category);
      const yIndex = severities.indexOf(severity);
      const xIndex = categories.indexOf(category);
      const targetY = yIndex === -1 ? unknownSeverityIndex : yIndex;

      if (targetY === -1 || xIndex === -1) continue;
      matrix[targetY][xIndex] += 1;
    }

    const heatmapData = [];
    let maxValue = 0;
    for (let y = 0; y < severities.length; y += 1) {
      for (let x = 0; x < categories.length; x += 1) {
        const value = matrix[y][x];
        if (value > maxValue) maxValue = value;
        heatmapData.push([x, y, value]);
      }
    }

    return {
      severities,
      categories,
      heatmapData,
      maxValue: Math.max(1, maxValue),
    };
  }, [findings]);

  const summary = useMemo(() => {
    const total = findings.length;
    const critical = findings.filter((f) => normalizeSeverity(f.severity) === "Critical").length;
    const high = findings.filter((f) => normalizeSeverity(f.severity) === "High").length;
    const uniqueHosts = new Set(findings.map((f) => String(f?.host || "Unknown"))).size;

    return { total, critical, high, uniqueHosts };
  }, [findings]);

  const promptContext = useMemo(() => {
    const topHost = topHosts[0] || ["-", 0];
    const bySeverity = CHART_SEVERITIES.map((label, index) => `${label}:${severityData.values[index]}`).join(", ");
    const highRisk = findings.filter((f) => {
      const sev = normalizeSeverity(f?.severity);
      return sev === "Critical" || sev === "High";
    }).length;
    return {
      topHost,
      bySeverity,
      highRisk,
    };
  }, [findings, severityData, topHosts]);

  const runPrompt = () => {
    setPromptOut(
      [
        `Prompt: ${prompt || "Summarize Nessus findings"}.`,
        `Findings: ${summary.total}, high-risk (Critical/High): ${promptContext.highRisk}.`,
        `Severity mix: ${promptContext.bySeverity}.`,
        `Top affected host: ${promptContext.topHost[0]} (${promptContext.topHost[1]} findings).`,
        `Unique hosts: ${summary.uniqueHosts}.`,
      ].join(" ")
    );
  };

  useEffect(() => {
    if (!severityChartRef.current) return;

    const chart = echarts.init(severityChartRef.current);

    chart.setOption({
      backgroundColor: "transparent",
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
      grid: { left: "3%", right: "4%", bottom: "3%", containLabel: true },
      xAxis: [
        {
          type: "category",
          data: severityData.categories,
          axisTick: { alignWithLabel: true },
          axisLine: { lineStyle: { color: "#475569" } },
          axisLabel: { color: "#cbd5e1" },
        },
      ],
      yAxis: [
        {
          type: "value",
          minInterval: 1,
          axisLine: { lineStyle: { color: "#475569" } },
          splitLine: { lineStyle: { color: "rgba(148, 163, 184, 0.2)" } },
          axisLabel: { color: "#cbd5e1" },
        },
      ],
      series: [
        {
          name: "Findings",
          type: "bar",
          barWidth: "60%",
          data: severityData.values,
          label: { show: true, position: "top", color: "#e2e8f0", fontWeight: 600 },
          itemStyle: {
            color: (params) => SEVERITY_COLORS[severityData.categories[params.dataIndex]] || "#38bdf8",
            borderRadius: [4, 4, 0, 0],
          },
        },
      ],
    });

    const onResize = () => chart.resize();
    window.addEventListener("resize", onResize);

    return () => {
      window.removeEventListener("resize", onResize);
      chart.dispose();
    };
  }, [severityData]);

  useEffect(() => {
    if (!hostChartRef.current) return;

    const chart = echarts.init(hostChartRef.current);

    chart.setOption({
      backgroundColor: "transparent",
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
      grid: { left: "4%", right: "3%", bottom: "3%", containLabel: true },
      xAxis: {
        type: "value",
        minInterval: 1,
        axisLine: { lineStyle: { color: "#475569" } },
        splitLine: { lineStyle: { color: "rgba(148, 163, 184, 0.2)" } },
        axisLabel: { color: "#cbd5e1" },
      },
      yAxis: {
        type: "category",
        data: topHosts.map(([host]) => host),
        axisLine: { lineStyle: { color: "#475569" } },
        axisLabel: { color: "#cbd5e1", width: 140, overflow: "truncate" },
      },
      series: [
        {
          name: "Findings",
          type: "bar",
          data: topHosts.map(([, count]) => count),
          label: { show: true, position: "right", color: "#e2e8f0" },
          itemStyle: { color: "#0ea5e9", borderRadius: [0, 4, 4, 0] },
        },
      ],
    });

    const onResize = () => chart.resize();
    window.addEventListener("resize", onResize);

    return () => {
      window.removeEventListener("resize", onResize);
      chart.dispose();
    };
  }, [topHosts]);

  useEffect(() => {
    if (!matrixChartRef.current) return;

    const chart = echarts.init(matrixChartRef.current);

    chart.setOption({
      backgroundColor: "transparent",
      tooltip: {
        position: "top",
        formatter: (params) => {
          const [x, y, value] = params.data;
          const category = severityCategoryMatrix.categories[x];
          const severity = severityCategoryMatrix.severities[y];
          return `${severity} / ${category}: ${value}`;
        },
      },
      grid: { left: "12%", right: "3%", top: "5%", bottom: "20%", containLabel: true },
      xAxis: {
        type: "category",
        data: severityCategoryMatrix.categories,
        splitArea: { show: true },
        axisLine: { lineStyle: { color: "#475569" } },
        axisLabel: { color: "#cbd5e1", rotate: 20, fontSize: 11 },
      },
      yAxis: {
        type: "category",
        data: severityCategoryMatrix.severities,
        inverse: true,
        splitArea: { show: true },
        axisLine: { lineStyle: { color: "#475569" } },
        axisLabel: { color: "#cbd5e1" },
      },
      visualMap: {
        min: 0,
        max: severityCategoryMatrix.maxValue,
        calculable: false,
        orient: "horizontal",
        left: "center",
        bottom: 0,
        text: ["More", "Less"],
        textStyle: { color: "#cbd5e1" },
        inRange: {
          color: ["#0f172a", "#1d4ed8", "#22d3ee", "#f59e0b", "#ef4444"],
        },
      },
      series: [
        {
          type: "heatmap",
          data: severityCategoryMatrix.heatmapData,
          label: {
            show: true,
            color: "#e2e8f0",
            fontSize: 11,
            formatter: (params) => (params.data[2] > 0 ? params.data[2] : ""),
          },
          emphasis: {
            itemStyle: {
              shadowBlur: 12,
              shadowColor: "rgba(0, 0, 0, 0.45)",
            },
          },
        },
      ],
    });

    const onResize = () => chart.resize();
    window.addEventListener("resize", onResize);

    return () => {
      window.removeEventListener("resize", onResize);
      chart.dispose();
    };
  }, [severityCategoryMatrix]);

  return (
    <div className="w-full">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-4">
          <div className="text-sm font-semibold text-slate-200">Severity Counts</div>
          <div ref={severityChartRef} className="mt-3 h-64 w-full" />
        </div>

        <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-4">
          <div className="text-sm font-semibold text-slate-200">Top Affected Hosts</div>
          <div ref={hostChartRef} className="mt-3 h-64 w-full" />
        </div>
      </div>

      <div className="mt-4 rounded-xl border border-slate-700 bg-slate-950/40 p-4">
        <div className="text-sm font-semibold text-slate-200">Severity x Category Matrix</div>
        <div className="mt-1 text-xs text-slate-400">
          Latest loaded report findings, with severity on Y-axis and category on X-axis.
        </div>
        <div ref={matrixChartRef} className="mt-3 h-80 w-full" />
      </div>

      <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-3">
          <div className="text-xs text-slate-400">Total Findings</div>
          <div className="mt-1 text-xl font-semibold text-slate-100">{summary.total}</div>
        </div>
        <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-3">
          <div className="text-xs text-slate-400">Critical</div>
          <div className="mt-1 text-xl font-semibold text-red-400">{summary.critical}</div>
        </div>
        <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-3">
          <div className="text-xs text-slate-400">High</div>
          <div className="mt-1 text-xl font-semibold text-orange-400">{summary.high}</div>
        </div>
        <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-3">
          <div className="text-xs text-slate-400">Hosts</div>
          <div className="mt-1 text-xl font-semibold text-slate-100">{summary.uniqueHosts}</div>
        </div>
      </div>

      <div className="mt-4 rounded-xl border border-white/15 bg-white/5 p-4">
        <div className="text-sm font-semibold">Gemini Box for input</div>
        <div className="mt-2 grid gap-2 md:grid-cols-[minmax(0,1fr)_auto]">
          <textarea
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
            placeholder="Explain these Nessus findings in plain English"
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

      <div className="mt-4">
        <NessusFindingsTable findings={findings} severityOrder={SEVERITY_ORDER} />
      </div>
    </div>
  );
}
