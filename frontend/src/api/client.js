const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/+$/, "");

const buildUrl = (path) => {
    if (/^https?:\/\//i.test(path)) return path;
    if (!API_BASE_URL) return path;
    return `${API_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`;
};

export const apiFetch = async (path, options = {}) => {
    const res = await fetch(buildUrl(path), options);
    const rawBody = await res.text();

    let data = null;
    if (rawBody) {
        try {
            data = JSON.parse(rawBody);
        } catch {
            data = rawBody;
        }
    }

    if (!res.ok) {
        const message =
            (data && typeof data === "object" && (data.error || data.message)) ||
            `Request failed (${res.status})`;
        throw new Error(message);
    }

    return data;
};

export default apiFetch;
