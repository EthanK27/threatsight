import { useState } from "react";
import NessusTab from "../components/NessusTab";
import WiresharkTab from "../components/WiresharkTab";
import HoneypotTab from "../components/HoneyPot";

const TABS = [
    { key: "nessus", label: "Nessus (PDF)" },
    { key: "wireshark", label: "Wireshark" },
    { key: "honeypot", label: "Honeypot" },
];

export default function Dashboard() {
    const [activeTab, setActiveTab] = useState("nessus");

    return (
        <div className="min-h-screen bg-primary text-textMain flex flex-col">
            {/* Top bar */}
            <header className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-accent/20">
                <div className="flex items-center gap-3">
                    <div className="w-3 h-3 rounded-sm bg-textMain/80" />
                    <div>
                        <div className="text-lg font-semibold tracking-wide">ThreatSite</div>
                        <div className="text-xs text-textMain/70">Security Dashboard</div>
                    </div>
                </div>

                <div className="text-xs px-3 py-1 rounded-full bg-white/5 border border-white/10">
                    {TABS.find((t) => t.key === activeTab)?.label}
                </div>
            </header>

            {/* Tabs */}
            <nav className="px-6 pt-4">
                <div className="flex gap-2 border-b border-white/10">
                    {TABS.map((tab) => {
                        const isActive = tab.key === activeTab;
                        return (
                            <button
                                key={tab.key}
                                onClick={() => setActiveTab(tab.key)}
                                className={[
                                    "px-4 py-2 text-sm font-medium transition",
                                    isActive
                                        ? "border-b-2 border-textMain text-textMain"
                                        : "text-textMain/60 hover:text-textMain",
                                ].join(" ")}
                                type="button"
                            >
                                {tab.label}
                            </button>
                        );
                    })}
                </div>
            </nav>

            {/* Content area */}
            <main className="flex-1 px-6 py-6">
                <section className="rounded-lg bg-white/5 border border-white/10 p-6">
                    {/* Keep all mounted; just hide */}
                    <div className={activeTab === "nessus" ? "block" : "hidden"}>
                        <NessusTab />
                    </div>

                    <div className={activeTab === "wireshark" ? "block" : "hidden"}>
                        <WiresharkTab />
                    </div>

                    <div className={activeTab === "honeypot" ? "block" : "hidden"}>
                        <HoneypotTab />
                    </div>
                </section>
            </main>
        </div>
    );
}