export function chunkText(text, maxChars = 900, overlap = 120) {
    const clean = (text || "").replace(/\s+/g, " ").trim();
    if (!clean)
        return [];
    const out = [];
    let i = 0;
    while (i < clean.length) {
        const end = Math.min(clean.length, i + maxChars);
        out.push(clean.slice(i, end));
        if (end >= clean.length)
            break;
        i = Math.max(0, end - overlap);
    }
    return out.filter(Boolean);
}
