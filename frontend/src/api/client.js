// src/api/client.js
export async function apiGet(path) {
    const res = await fetch(path, { method: "GET" });
    const text = await res.text();
    const data = text ? safeJson(text) : null;

    if (!res.ok) {
        throw new Error(data?.error || `GET ${path} failed (${res.status})`);
    }
    return data;
}

export async function apiPostForm(path, formData) {
    const res = await fetch(path, { method: "POST", body: formData });
    const text = await res.text();
    const data = text ? safeJson(text) : null;

    if (!res.ok) {
        throw new Error(data?.error || `POST ${path} failed (${res.status})`);
    }
    if (!data) {
        throw new Error("Request succeeded but response was not JSON.");
    }
    return data;
}

function safeJson(text) {
    try {
        return JSON.parse(text);
    } catch {
        return null;
    }
}