// src/api/nessus.js
import { apiGet, apiPostForm } from "./client";

export async function uploadNessusPdf(file) {
    const formData = new FormData();
    formData.append("nessusPdf", file); // must match multer field name
    return apiPostForm("/api/analysis/nessus/upload", formData);
}

export async function fetchNessusFindings(reportId) {
    const data = await apiGet(`/api/analysis/nessus/reports/${reportId}/findings`);
    return Array.isArray(data) ? data : (data?.findings ?? []);
}

export async function fetchLatestNessusReport() {
    const data = await apiGet("/api/analysis/nessus/reports/latest");
    return data ?? null;
}
