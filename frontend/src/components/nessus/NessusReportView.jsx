import React, { useEffect, useMemo, useRef } from "react";
import * as echarts from "echarts";
import NessusFindingsTable from "./NessusFindingsTable";
import { normalizeSeverity, SEVERITY_COLORS, SEVERITY_ORDER } from "../../utils/severity";

const CHART_SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];

export default function NessusReportView({ findings = [] }) {
  const severityChartRef = useRef(null);
  const hostChartRef = useRef(null);

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

  const summary = useMemo(() => {
    const total = findings.length;
    const critical = findings.filter((f) => normalizeSeverity(f.severity) === "Critical").length;
    const high = findings.filter((f) => normalizeSeverity(f.severity) === "High").length;
    const uniqueHosts = new Set(findings.map((f) => String(f?.host || "Unknown"))).size;

    return { total, critical, high, uniqueHosts };
  }, [findings]);

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

  return (
    <div className="w-full">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
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

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-4">
          <div className="text-sm font-semibold text-slate-200">Severity Counts</div>
          <div ref={severityChartRef} className="mt-3 h-64 w-full" />
        </div>

        <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-4">
          <div className="text-sm font-semibold text-slate-200">Top Affected Hosts</div>
          <div ref={hostChartRef} className="mt-3 h-64 w-full" />
        </div>
      </div>

      <div className="mt-4">
        <NessusFindingsTable findings={findings} severityOrder={SEVERITY_ORDER} />
      </div>
    </div>
  );
}