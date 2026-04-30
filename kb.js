import crypto from "crypto";
import { chunkText } from "./chunk.js";
function uid() {
    return typeof crypto.randomUUID === "function" ? crypto.randomUUID() : String(Date.now() + Math.random());
}
const KB = [];
export function kbCount() {
    return KB.length;
}
export function kbList(params = {}) {
    const limit = Math.max(1, Math.min(200, params.limit ?? 50));
    const offset = Math.max(0, params.offset ?? 0);
    const items = [...KB].sort((a, b) => b.createdAt - a.createdAt).slice(offset, offset + limit);
    return { total: KB.length, limit, offset, items };
}
export function ingestKB(params) {
    const { title = null, source = null, content } = params;
    const chunks = chunkText(content, 900, 120);
    const now = Date.now();
    for (const c of chunks) {
        KB.push({
            id: uid(),
            docTitle: title,
            source,
            text: c,
            createdAt: now,
        });
    }
    return { ok: true, added: chunks.length, total: KB.length };
}
export function searchKB(query, limit = 6) {
    const q = (query || "").toLowerCase().trim();
    if (!q || KB.length === 0)
        return [];
    const tokens = q.split(/\s+/).filter(Boolean).slice(0, 12);
    const scored = KB.map((x) => {
        const t = x.text.toLowerCase();
        let score = 0;
        for (const tok of tokens) {
            if (tok.length < 3)
                continue;
            if (t.includes(tok))
                score += 2;
        }
        if (t.includes(q))
            score += 5;
        return { x, score };
    });
    scored.sort((a, b) => b.score - a.score);
    return scored
        .filter((s) => s.score > 0)
        .slice(0, limit)
        .map((s) => s.x);
}
