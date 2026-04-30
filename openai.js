const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
async function postJSON(url, body) {
    if (!OPENAI_API_KEY)
        throw new Error("OPENAI_API_KEY yoxdur (backend env-də ver).");
    const r = await fetch(url, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${OPENAI_API_KEY}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
    });
    if (!r.ok) {
        const t = await r.text().catch(() => "");
        throw new Error(`OpenAI error ${r.status}: ${t}`);
    }
    return r.json();
}
export async function aiAnswer(params) {
    const { userMessage, context } = params;
    const system = "You are a customer support assistant. " +
        "Answer ONLY using the provided CONTEXT. " +
        "If the answer is not in the context, say you don't have enough info and suggest contacting a human. " +
        "Respond in Azerbaijani. Keep it concise.";
    const data = await postJSON("https://api.openai.com/v1/chat/completions", {
        model: "gpt-4.1-mini",
        temperature: 0.2,
        messages: [
            { role: "system", content: system },
            { role: "user", content: `CONTEXT:\n${context || "(empty)"}\n\nQUESTION:\n${userMessage}` },
        ],
    });
    return String(data.choices?.[0]?.message?.content ?? "").trim();
}
