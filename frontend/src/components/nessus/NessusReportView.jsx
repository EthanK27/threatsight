import React, { useEffect, useMemo, useRef } from "react";
import * as echarts from "echarts";
import NessusFindingsTable from "./NessusFindingsTable";

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"];

const SEVERITY_LABEL_MAP = {
    "4": "Critical",
    "3": "High",
    "2": "Medium",
    "1": "Low",
    "0": "Info",
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    info: "Info",
    informational: "Info",
    none: "None",
    unknown: "Unknown",
};

const SEVERITY_COLORS = {
    Critical: "#dc2626",
    High: "#ea580c",
    Medium: "#ca8a04",
    Low: "#0284c7",
    Info: "#22c55e",
    None: "#94a3b8",
    Unknown: "#64748b",
};

function normalizeSeverity(value) {
    if (value === null || value === undefined) return "Unknown";
    const raw = String(value).trim();
    if (!raw) return "Unknown";

    const mapped = SEVERITY_LABEL_MAP[raw.toLowerCase()];
    if (mapped) return mapped;

    return raw.charAt(0).toUpperCase() + raw.slice(1);
}

export default function NessusReportView({ findings }) {
    const chartRef = useRef(null);

    const { categories, data } = useMemo(() => {
        const counts = new Map(SEVERITY_ORDER.map((label) => [label, 0]));

        for (const finding of findings || []) {
            const label = normalizeSeverity(finding?.severity);
            if (!counts.has(label)) continue;
            counts.set(label, (counts.get(label) || 0) + 1);
        }

        const orderedCategories = SEVERITY_ORDER;

        return {
            categories: orderedCategories,
            data: orderedCategories.map((label) => counts.get(label) || 0),
        };
    }, [findings]);

    useEffect(() => {
        if (!chartRef.current) return;

        const chart = echarts.init(chartRef.current);

        chart.setOption({
            backgroundColor: "transparent",
            tooltip: {
                trigger: "axis",
                axisPointer: {
                    type: "shadow",
                },
            },
            grid: {
                left: "3%",
                right: "4%",
                bottom: "3%",
                containLabel: true,
            },
            xAxis: [
                {
                    type: "category",
                    data: categories,
                    axisTick: {
                        alignWithLabel: true,
                    },
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
                    data,
                    label: {
                        show: true,
                        position: "top",
                        color: "#e2e8f0",
                        fontWeight: 600,
                    },
                    itemStyle: {
                        color: (params) => SEVERITY_COLORS[categories[params.dataIndex]] || "#38bdf8",
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
    }, [categories, data]);

    return (
        <div className="w-full">
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-4">
                    <div className="text-sm font-semibold text-slate-200">Severity Counts</div>
                    <div ref={chartRef} className="mt-3 h-64 w-full" />
                </div>

                <div className="rounded-xl border border-slate-700 bg-slate-950/40 p-4">
                    <div className="text-sm font-semibold text-slate-200">Another Graph</div>
                    <div className="mt-3 h-40 rounded-lg border border-dashed border-slate-700" />
                </div>
            </div>

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
