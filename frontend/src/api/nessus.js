import { apiFetch } from "./client";

export const uploadAndProcessNessusPdf = async ({ file, reportName }) => {
    const formData = new FormData();
    formData.append("nessusPdf", file);
    if (reportName) formData.append("reportName", reportName);

    return apiFetch("/api/analysis/nessus/upload", {
        method: "POST",
        body: formData,
    });
};

export const fetchLatestNessusReport = async () => {
    return apiFetch("/api/reports/latest?mode=Nessus");
};
