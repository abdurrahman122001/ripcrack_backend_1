import { Router } from "express";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { prisma } from "./prisma.js";
import { signJwt } from "./utils.js";
import { requireAdmin, requireAuth, requireOptionalAuth } from "./auth.js";
import multer from "multer";
import path from "path";
import crypto from "crypto";
import { sendMail } from "./mailer.js";
import { ingestKB, kbCount, kbList, searchKB } from "./kb.js";
import { aiAnswer } from "./openai.js";
import { getEmailVerificationTemplate, getWelcomeEmailTemplate, getPasswordResetTemplate, getOrderConfirmationTemplate, getOrderCancellationTemplate, getOrderConfirmedByAdminTemplate } from "./emailTemplates.js";
export const router = Router();
router.get("/health", async (_req, res) => {
    try {
        const dbRow = await prisma.$queryRaw `SELECT DATABASE() as db`;
        const db = dbRow?.[0]?.db ?? null;
        const [productCount, userCount, subscriptionCount] = await Promise.all([
            prisma.product.count(),
            prisma.user.count(),
            prisma.newsletterSubscription.count(),
        ]);
        return res.json({ ok: true, kbChunks: kbCount(), db, productCount, userCount, subscriptionCount });
    }
    catch (e) {
        return res.json({ ok: true, kbChunks: kbCount(), db: null, productCount: null, userCount: null, subscriptionCount: null, dbError: e?.message || "db check failed" });
    }
});
const optionalUrl = z.preprocess((v) => (v == null || (typeof v === "string" && v.trim() === "") ? undefined : (typeof v === "string" ? v.trim() : v)), z.string().url().optional());
function make6DigitCode() {
    return String(Math.floor(100000 + Math.random() * 900000));
}
function hashEmailVerifyCode(userId, code) {
    return crypto.createHash("sha256").update(`${userId}:${code}`).digest("hex");
}
function hashFraudSubmissionCode(submissionId, code) {
    return crypto.createHash("sha256").update(`fraud:${submissionId}:${code}`).digest("hex");
}
// Generate a unique frontendRoute for a product
async function generateUniqueFrontendRoute(db, providedRoute, productTitle, excludeProductId) {
    let route = providedRoute.trim();
    // If empty, generate from title
    if (!route) {
        route = productTitle
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '')
            .substring(0, 200);
        if (!route) {
            // Fallback if title doesn't generate a valid route
            route = `product-${Date.now()}`;
        }
    }
    // Ensure route is unique
    let uniqueRoute = route;
    let counter = 1;
    while (true) {
        const existing = await db.product.findFirst({
            where: {
                frontendRoute: uniqueRoute,
                ...(excludeProductId ? { id: { not: excludeProductId } } : {})
            }
        });
        if (!existing) {
            return uniqueRoute;
        }
        // Append counter to make it unique
        const baseRoute = route.substring(0, 200 - String(counter).length - 1);
        uniqueRoute = `${baseRoute}-${counter}`;
        counter++;
        // Safety check to prevent infinite loop
        if (counter > 10000) {
            uniqueRoute = `${route}-${Date.now()}`;
            break;
        }
    }
    return uniqueRoute;
}
async function createAndSendEmailVerifyCode(opts) {
    const code = make6DigitCode();
    const codeHash = hashEmailVerifyCode(opts.userId, code);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    await prisma.emailVerificationCode.create({
        data: { userId: opts.userId, codeHash, expiresAt },
    });
    const emailHtml = getEmailVerificationTemplate({
        verificationCode: code,
    });
    await sendMail({
        to: opts.email,
        subject: "Verify your email - RipCrack",
        html: emailHtml,
    });
}
async function createAndSendFraudSubmissionCode(opts) {
    const code = make6DigitCode();
    const codeHash = hashFraudSubmissionCode(opts.submissionId, code);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    await prisma.fraudSubmissionCode.create({
        data: { submissionId: opts.submissionId, codeHash, expiresAt },
    });
    const emailHtml = getEmailVerificationTemplate({ verificationCode: String(code) });
    await sendMail({
        to: opts.email,
        subject: "Verify your email - RipCrack",
        html: emailHtml,
    });
}
const upload = multer({
    storage: multer.diskStorage({
        destination: (_req, _file, cb) => cb(null, path.resolve(process.cwd(), "uploads")),
        filename: (_req, file, cb) => {
            const ext = path.extname(file.originalname || "").toLowerCase();
            cb(null, `${Date.now()}-${crypto.randomBytes(6).toString("hex")}${ext || ".bin"}`);
        }
    }),
    limits: { files: 5, fileSize: 5 * 1024 * 1024 }
});
const uploadSingle = multer({
    storage: multer.diskStorage({
        destination: (_req, _file, cb) => cb(null, path.resolve(process.cwd(), "uploads")),
        filename: (_req, file, cb) => {
            const ext = path.extname(file.originalname || "").toLowerCase();
            cb(null, `${Date.now()}-${crypto.randomBytes(6).toString("hex")}${ext || ".bin"}`);
        }
    }),
    fileFilter: (_req, file, cb) => {
        const allowed = [".svg", ".png", ".jpg", ".jpeg", ".webp"];
        const ext = path.extname(file.originalname || "").toLowerCase();
        if (allowed.includes(ext))
            cb(null, true);
        else
            cb(new Error("Only SVG, PNG, JPG, WEBP allowed"));
    },
    limits: { files: 1, fileSize: 2 * 1024 * 1024 }
});
async function verifyTurnstile(token, ip) {
    const secret = process.env.TURNSTILE_SECRET_KEY;
    const env = String(process.env.NODE_ENV || "").toLowerCase();
    const bypass = String(process.env.TURNSTILE_DEV_BYPASS || "").trim().toLowerCase();
    if (env !== "production" || bypass === "true" || bypass === "1" || bypass === "yes") {
        return { ok: true, skipped: true };
    }
    if (!secret)
        return { ok: true, skipped: true };
    if (!token)
        return { ok: false, error: "Missing captcha token" };
    const body = new URLSearchParams();
    body.set("secret", secret);
    body.set("response", token);
    if (ip)
        body.set("remoteip", ip);
    if (typeof fetch !== "function")
        return { ok: false, error: "Server missing fetch()" };
    const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
    });
    const json = await resp.json().catch(() => null);
    if (!resp.ok)
        return { ok: false, error: "Captcha verify failed" };
    if (!json?.success)
        return { ok: false, error: "Captcha failed" };
    return { ok: true };
}
function getClientIp(req) {
    const xf = req?.headers?.["x-forwarded-for"];
    if (typeof xf === "string" && xf.trim())
        return xf.split(",")[0].trim();
    return req?.ip || req?.socket?.remoteAddress || "unknown";
}
function normalizeSeoKeyword(input) {
    return String(input || "")
        .trim()
        .toLowerCase()
        .replace(/\s+/g, " ");
}
function jsonStringArray(value) {
    if (Array.isArray(value))
        return value.filter((x) => typeof x === "string");
    if (typeof value === "string") {
        try {
            const parsed = JSON.parse(value);
            return Array.isArray(parsed) ? parsed.filter((x) => typeof x === "string") : [];
        }
        catch {
            return [];
        }
    }
    if (value && typeof value === "object") {
        const v = value;
        if (Array.isArray(v))
            return v.filter((x) => typeof x === "string");
    }
    return [];
}
function jsonNumberArray(value) {
    if (Array.isArray(value))
        return value.map((x) => Number(x)).filter((n) => Number.isFinite(n));
    if (typeof value === "string") {
        try {
            const parsed = JSON.parse(value);
            return Array.isArray(parsed) ? parsed.map((x) => Number(x)).filter((n) => Number.isFinite(n)) : [];
        }
        catch {
            return [];
        }
    }
    if (value && typeof value === "object") {
        const v = value;
        if (Array.isArray(v))
            return v.map((x) => Number(x)).filter((n) => Number.isFinite(n));
    }
    return [];
}
function normalizeSeoKeywordList(primary, secondary) {
    const normalized = [normalizeSeoKeyword(primary), ...(secondary || []).map(normalizeSeoKeyword)].filter(Boolean);
    return Array.from(new Set(normalized));
}
async function ensureSeoKeyword(db, keywordNormalized) {
    const keyword = keywordNormalized;
    const existing = await db.seoKeyword.findUnique({ where: { normalized: keywordNormalized } });
    if (existing) {
        if (existing.keyword !== keyword) {
            return db.seoKeyword.update({ where: { id: existing.id }, data: { keyword } });
        }
        return existing;
    }
    try {
        return await db.seoKeyword.create({ data: { keyword, normalized: keywordNormalized } });
    }
    catch (e) {
        if (e?.code === "P2002") {
            return await db.seoKeyword.findUnique({ where: { normalized: keywordNormalized } });
        }
        throw e;
    }
}
async function checkSeoKeywordConflict(opts) {
    const usage = await opts.db.seoKeywordUsage.findFirst({
        where: {
            entityType: opts.entityType,
            keyword: { normalized: opts.keywordNormalized },
        },
        include: { keyword: true },
    });
    if (!usage)
        return null;
    if (opts.excludeEntityId !== undefined && usage.entityId === opts.excludeEntityId)
        return null;
    return usage;
}
async function syncSeoKeywordUsage(opts) {
    const desired = normalizeSeoKeywordList(opts.primaryKeyword, opts.secondaryKeywords);
    const existing = await opts.db.seoKeywordUsage.findMany({
        where: { entityType: opts.entityType, entityId: opts.entityId },
        include: { keyword: true },
    });
    const desiredSet = new Set(desired);
    const existingSet = new Set(existing.map((x) => x.keyword.normalized));
    const toRemove = existing.filter((x) => !desiredSet.has(x.keyword.normalized)).map((x) => x.id);
    if (toRemove.length) {
        await opts.db.seoKeywordUsage.deleteMany({ where: { id: { in: toRemove } } });
    }
    for (const keywordNormalized of desired) {
        if (existingSet.has(keywordNormalized))
            continue;
        const conflict = await checkSeoKeywordConflict({
            db: opts.db,
            entityType: opts.entityType,
            keywordNormalized,
            excludeEntityId: opts.entityId,
        });
        if (conflict) {
            const kw = conflict.keyword?.keyword || keywordNormalized;
            throw new Error(`Keyword already used for ${opts.entityType}: ${kw}`);
        }
        const kw = await ensureSeoKeyword(opts.db, keywordNormalized);
        if (!kw)
            throw new Error(`Failed to ensure keyword: ${keywordNormalized}`);
        await opts.db.seoKeywordUsage.create({
            data: { keywordId: kw.id, entityType: opts.entityType, entityId: opts.entityId },
        });
    }
}
function rateLimit(opts) {
    const hits = new Map();
    const windowMs = Math.max(1_000, opts.windowMs);
    const max = Math.max(1, opts.max);
    return (req, res, next) => {
        const ip = getClientIp(req);
        const now = Date.now();
        const key = `${opts.keyPrefix}:${ip}`;
        const entry = hits.get(key);
        if (!entry || entry.resetAt <= now) {
            hits.set(key, { count: 1, resetAt: now + windowMs });
            return next();
        }
        entry.count += 1;
        if (entry.count > max) {
            const retryAfterSec = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
            res.setHeader("Retry-After", String(retryAfterSec));
            return res.status(429).json({ error: "Too many attempts. Please try again later." });
        }
        return next();
    };
}
router.get("/auth/me", requireOptionalAuth, async (req, res) => {
    try {
        if (!req.user)
            return res.json({ user: null });
        const user = await prisma.user.findUnique({ where: { id: req.user.id }, select: { id: true, email: true, role: true, firstName: true, lastName: true } });
        res.json({ user });
    }
    catch (err) {
        console.error("[/auth/me] error:", err);
        res.status(500).json({ error: err?.message || "Failed to get user" });
    }
});
router.get("/footer-links", async (_req, res) => {
    try {
        const items = await prisma.footerLink.findMany({ where: { enabled: true }, orderBy: [{ group: "asc" }, { sortOrder: "asc" }, { id: "asc" }] });
        res.json({ items });
    }
    catch (err) {
        console.error("[/footer-links] error:", err);
        res.status(500).json({ error: err?.message || "Failed to load footer links" });
    }
});
// Public: Subscribe (newsletter) – save email to database
router.post("/subscribe", async (req, res) => {
    try {
        const raw = req.body;
        if (raw == null || typeof raw !== "object") {
            console.warn("[/subscribe] missing or invalid body", { body: raw });
            return res.status(400).json({ error: "Invalid request body." });
        }
        const body = z.object({ email: z.string().email().min(1).max(255) }).parse(raw);
        const email = body.email.trim().toLowerCase();
        const dbRow = await prisma.$queryRaw `SELECT DATABASE() as db`;
        const dbName = dbRow?.[0]?.db ?? "unknown";
        console.log("[/subscribe] saving to database:", dbName, "email:", email);
        try {
            const created = await prisma.newsletterSubscription.create({
                data: { email },
            });
            console.log("[/subscribe] created id=%s email=%s in db=%s", created.id, created.email, dbName);
        }
        catch (createErr) {
            if (createErr?.code === "P2002") {
                console.log("[/subscribe] already subscribed:", email, "in db=", dbName);
                return res.json({ ok: true, message: "Subscribed successfully." });
            }
            console.error("[/subscribe] DB create error:", createErr?.code, createErr?.message);
            throw createErr;
        }
        res.json({ ok: true, message: "Subscribed successfully." });
    }
    catch (err) {
        if (err instanceof z.ZodError) {
            return res.status(400).json({ error: "Please enter a valid email address." });
        }
        console.error("[/subscribe] error:", err);
        res.status(500).json({ error: err?.message || "Failed to subscribe." });
    }
});
// Admin: List newsletter subscriptions (NewsletterSubscription table)
router.get("/admin/subscriptions", requireAuth, requireAdmin, async (_req, res) => {
    try {
        const items = await prisma.newsletterSubscription.findMany({
            orderBy: { createdAt: "desc" },
        });
        res.json({ items });
    }
    catch (err) {
        console.error("[/admin/subscriptions] error:", err);
        res.status(500).json({ error: err?.message || "Failed to load subscriptions." });
    }
});
// Admin: Clear all newsletter subscriptions (must be before :id so "clear" is not matched as id)
router.delete("/admin/subscriptions/clear", requireAuth, requireAdmin, async (_req, res) => {
    try {
        await prisma.newsletterSubscription.deleteMany({});
        res.json({ ok: true });
    }
    catch (err) {
        console.error("[/admin/subscriptions/clear DELETE] error:", err);
        res.status(500).json({ error: err?.message || "Failed to clear subscriptions." });
    }
});
// Admin: Delete a newsletter subscription
router.delete("/admin/subscriptions/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!Number.isInteger(id) || id < 1) {
            return res.status(400).json({ error: "Invalid subscription id." });
        }
        await prisma.newsletterSubscription.delete({
            where: { id },
        });
        res.json({ ok: true });
    }
    catch (err) {
        if (err?.code === "P2025") {
            return res.status(404).json({ error: "Subscription not found." });
        }
        console.error("[/admin/subscriptions/:id DELETE] error:", err);
        res.status(500).json({ error: err?.message || "Failed to delete subscription." });
    }
});
// ===================== BANNERS =====================
// Public: Get active banners
router.get("/banners", async (_req, res) => {
    try {
        const items = await prisma.banner.findMany({ where: { active: true }, orderBy: [{ sortOrder: "asc" }, { id: "asc" }] });
        res.json({ items });
    }
    catch (err) {
        console.error("[/banners] error:", err);
        res.status(500).json({ error: err?.message || "Failed to load banners" });
    }
});
// Admin: Get all banners
router.get("/admin/banners", requireAuth, requireAdmin, async (_req, res) => {
    const items = await prisma.banner.findMany({ orderBy: [{ sortOrder: "asc" }, { id: "asc" }] });
    res.json({ items });
});
// Admin: Create banner
router.post("/admin/banners", requireAuth, requireAdmin, async (req, res) => {
    try {
        const body = z
            .object({
            title: z.string().min(1).max(200),
            subtitle: z.string().max(300).optional().default(""),
            cta: z.string().max(80).optional().default(""),
            targetPage: z.string().max(80).optional().default(""),
            targetUrl: z.string().max(500).optional().default(""),
            sortOrder: z.coerce.number().int().optional().default(0),
            active: z.boolean().optional().default(true),
        })
            .parse(req.body);
        const created = await prisma.banner.create({
            data: {
                title: body.title.trim(),
                subtitle: body.subtitle.trim(),
                cta: body.cta.trim(),
                targetPage: body.targetPage.trim(),
                targetUrl: body.targetUrl.trim(),
                sortOrder: body.sortOrder,
                active: body.active,
            },
        });
        res.json({ item: created });
    }
    catch (err) {
        console.error("Banner create error:", err);
        if (err instanceof z.ZodError) {
            return res.status(400).json({ error: "Invalid request: " + err.errors.map((e) => e.message).join(", ") });
        }
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Admin: Update banner
router.put("/admin/banners/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!Number.isFinite(id))
            return res.status(400).json({ error: "Invalid id" });
        const existing = await prisma.banner.findUnique({ where: { id } });
        if (!existing)
            return res.status(404).json({ error: "Not found" });
        const body = z
            .object({
            title: z.string().min(1).max(200).optional(),
            subtitle: z.string().max(300).optional(),
            cta: z.string().max(80).optional(),
            targetPage: z.string().max(80).optional(),
            targetUrl: z.string().max(500).optional(),
            sortOrder: z.coerce.number().int().optional(),
            active: z.boolean().optional(),
        })
            .parse(req.body);
        const data = {};
        if (body.title !== undefined)
            data.title = body.title.trim();
        if (body.subtitle !== undefined)
            data.subtitle = body.subtitle.trim();
        if (body.cta !== undefined)
            data.cta = body.cta.trim();
        if (body.targetPage !== undefined)
            data.targetPage = body.targetPage.trim();
        if (body.targetUrl !== undefined)
            data.targetUrl = body.targetUrl.trim();
        if (body.sortOrder !== undefined)
            data.sortOrder = body.sortOrder;
        if (body.active !== undefined)
            data.active = body.active;
        const updated = await prisma.banner.update({ where: { id }, data });
        res.json({ item: updated });
    }
    catch (err) {
        console.error("Banner update error:", err);
        if (err instanceof z.ZodError) {
            return res.status(400).json({ error: "Invalid request: " + err.errors.map((e) => e.message).join(", ") });
        }
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Admin: Delete banner
router.delete("/admin/banners/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const existing = await prisma.banner.findUnique({ where: { id } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    await prisma.banner.delete({ where: { id } });
    res.json({ ok: true });
});
// ========== KB (Admin) ==========
router.get("/kb/list", requireAuth, requireAdmin, async (req, res) => {
    try {
        const q = z
            .object({
            limit: z.coerce.number().optional().default(50),
            offset: z.coerce.number().optional().default(0),
        })
            .parse(req.query);
        res.json(kbList({ limit: q.limit, offset: q.offset }));
    }
    catch (err) {
        console.error("[/kb/list] error:", err);
        if (err instanceof z.ZodError) {
            return res.status(400).json({ error: "Invalid request: " + err.errors.map((e) => e.message).join(", ") });
        }
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
router.post("/kb/ingest", requireAuth, requireAdmin, async (req, res) => {
    try {
        const body = z
            .object({
            title: z.string().max(300).optional().nullable().default(null),
            source: z.string().max(500).optional().nullable().default(null),
            content: z.string().min(1).max(200_000),
        })
            .parse(req.body);
        const out = ingestKB({ title: body.title, source: body.source, content: body.content });
        res.json(out);
    }
    catch (err) {
        console.error("[/kb/ingest] error:", err);
        if (err instanceof z.ZodError) {
            return res.status(400).json({ error: "Invalid request: " + err.errors.map((e) => e.message).join(", ") });
        }
        res.status(500).json({ error: err?.message || "kb ingest error" });
    }
});
// ========== AI CHAT (Public) ==========
router.post("/ai/chat", rateLimit({ windowMs: 60 * 1000, max: 30, keyPrefix: "ai:chat" }), async (req, res) => {
    try {
        const body = z
            .object({
            message: z.string().min(1).max(2000),
        })
            .parse(req.body);
        const hits = searchKB(body.message, 6);
        const context = hits.map((h, i) => `[#${i + 1}] ${h.text}`).join("\n\n");
        const safeContext = context ||
            "No knowledge base provided yet. Tell the user you don't have enough information and suggest contacting a human.";
        const answer = await aiAnswer({ userMessage: body.message, context: safeContext });
        res.json({
            answer,
            sources: hits.map((h) => ({ title: h.docTitle ?? null, source: h.source ?? null })),
        });
    }
    catch (err) {
        console.error("[/ai/chat] error:", err);
        if (err instanceof z.ZodError) {
            return res.status(400).json({ error: "Invalid request: " + err.errors.map((e) => e.message).join(", ") });
        }
        res.status(500).json({ error: err?.message || "ai error" });
    }
});
router.post("/auth/logout", (_req, res) => {
    res.json({ ok: true });
});
router.post("/auth/register", rateLimit({ windowMs: 10 * 60 * 1000, max: 12, keyPrefix: "auth:register" }), async (req, res) => {
    const body = z
        .object({ email: z.string().email(), password: z.string().min(6), captchaToken: z.string().optional().default("") })
        .parse(req.body);
    const captcha = await verifyTurnstile(body.captchaToken, req.ip);
    if (!captcha.ok)
        return res.status(400).json({ error: captcha.error });
    const email = body.email.toLowerCase();
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing)
        return res.status(400).json({ error: "Email already in use" });
    const password = await bcrypt.hash(body.password, 10);
    const user = await prisma.user.create({ data: { email, password, emailVerified: false } });
    // Send welcome email
    const welcomeEmailHtml = getWelcomeEmailTemplate();
    await sendMail({
        to: user.email,
        subject: "Welcome to RipCrack!",
        html: welcomeEmailHtml,
    });
    await createAndSendEmailVerifyCode({ userId: user.id, email: user.email });
    res.json({ ok: true, needsVerification: true, email: user.email });
});
router.post("/auth/login", rateLimit({ windowMs: 10 * 60 * 1000, max: 20, keyPrefix: "auth:login" }), async (req, res) => {
    const body = z
        .object({ email: z.string().email(), password: z.string().min(1), captchaToken: z.string().optional().default("") })
        .parse(req.body);
    const captcha = await verifyTurnstile(body.captchaToken, req.ip);
    if (!captcha.ok)
        return res.status(400).json({ error: captcha.error });
    const user = await prisma.user.findUnique({ where: { email: body.email.toLowerCase() } });
    if (!user)
        return res.status(401).json({ error: "Invalid credentials" });
    // Email verification check removed - users can login without verification
    // if (!user.emailVerified) return res.status(403).json({ error: "Email not verified", needsVerification: true });
    // Trim password for consistency with reset password
    const ok = await bcrypt.compare(body.password.trim(), user.password);
    if (!ok)
        return res.status(401).json({ error: "Invalid credentials" });
    const token = signJwt({ sub: user.id });
    res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
});
router.post("/auth/resend-verification", rateLimit({ windowMs: 10 * 60 * 1000, max: 10, keyPrefix: "auth:resend_verify" }), async (req, res) => {
    const body = z
        .object({ email: z.string().email(), captchaToken: z.string().optional().default("") })
        .parse(req.body);
    const captcha = await verifyTurnstile(body.captchaToken, req.ip);
    if (!captcha.ok)
        return res.status(400).json({ error: captcha.error });
    const email = body.email.toLowerCase();
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user)
        return res.json({ ok: true });
    if (user.emailVerified)
        return res.json({ ok: true });
    await createAndSendEmailVerifyCode({ userId: user.id, email: user.email });
    res.json({ ok: true });
});
router.post("/fraud/resend", rateLimit({ windowMs: 10 * 60 * 1000, max: 20, keyPrefix: "fraud:resend" }), async (req, res) => {
    const body = z
        .object({ submissionId: z.string().min(5), email: z.string().email(), captchaToken: z.string().optional().default("") })
        .parse(req.body);
    const captcha = await verifyTurnstile(body.captchaToken, req.ip);
    if (!captcha.ok)
        return res.status(400).json({ error: captcha.error });
    const submission = await prisma.fraudSubmission.findUnique({ where: { id: body.submissionId } });
    if (!submission)
        return res.json({ ok: true });
    if (submission.email.toLowerCase() !== body.email.toLowerCase())
        return res.json({ ok: true });
    if (submission.verifiedAt)
        return res.json({ ok: true });
    await createAndSendFraudSubmissionCode({ submissionId: submission.id, email: submission.email });
    res.json({ ok: true });
});
// --- Fraud (Public) ---
router.get("/fraud/entries", rateLimit({ windowMs: 60 * 1000, max: 600, keyPrefix: "fraud:list" }), async (_req, res) => {
    const items = await prisma.fraudEntry.findMany({
        where: { active: true },
        orderBy: [{ reports: "desc" }, { updatedAt: "desc" }, { id: "desc" }],
    });
    res.json({ items });
});
router.post("/fraud/submit", rateLimit({ windowMs: 10 * 60 * 1000, max: 20, keyPrefix: "fraud:submit" }), async (req, res) => {
    const body = z
        .object({
        email: z.string().email().max(320),
        name: z.string().min(1).max(200),
        platform: z.string().min(1).max(60),
        handle: z.string().min(1).max(200),
        details: z.string().min(3).max(10_000),
        evidenceUrl: z.preprocess((v) => (v == null || v === "" ? "" : String(v).trim()), z.string().max(2000)).optional().default(""),
        captchaToken: z.string().optional().default(""),
    })
        .parse(req.body);
    const captcha = await verifyTurnstile(body.captchaToken, req.ip);
    if (!captcha.ok)
        return res.status(400).json({ error: captcha.error });
    const email = body.email.toLowerCase();
    const submission = await prisma.fraudSubmission.create({
        data: {
            email,
            name: body.name.trim(),
            platform: body.platform.trim(),
            handle: body.handle.trim(),
            details: body.details.trim(),
            evidenceUrl: (body.evidenceUrl ?? "").trim(),
        },
    });
    await createAndSendFraudSubmissionCode({ submissionId: submission.id, email });
    res.json({ ok: true, needsVerification: true, submissionId: submission.id, email });
});
router.post("/fraud/verify", rateLimit({ windowMs: 10 * 60 * 1000, max: 30, keyPrefix: "fraud:verify" }), async (req, res) => {
    const body = z
        .object({ submissionId: z.string().min(5), email: z.string().email(), code: z.string().min(6).max(6) })
        .parse(req.body);
    const submission = await prisma.fraudSubmission.findUnique({ where: { id: body.submissionId } });
    if (!submission)
        return res.status(400).json({ error: "Invalid code" });
    if (submission.email.toLowerCase() !== body.email.toLowerCase())
        return res.status(400).json({ error: "Invalid code" });
    if (submission.verifiedAt)
        return res.json({ ok: true });
    const codeHash = hashFraudSubmissionCode(submission.id, body.code);
    const record = await prisma.fraudSubmissionCode.findUnique({ where: { codeHash } });
    if (!record || record.submissionId !== submission.id)
        return res.status(400).json({ error: "Invalid code" });
    if (record.usedAt)
        return res.status(400).json({ error: "Code already used" });
    if (record.expiresAt.getTime() < Date.now())
        return res.status(400).json({ error: "Code expired" });
    await prisma.$transaction([
        prisma.fraudSubmission.update({ where: { id: submission.id }, data: { verifiedAt: new Date() } }),
        prisma.fraudSubmissionCode.update({ where: { codeHash }, data: { usedAt: new Date() } }),
    ]);
    const adminEmail = process.env.ADMIN_EMAIL || "admin@example.com";
    await sendMail({
        to: adminEmail,
        subject: `New verified fraud submission (${submission.id})`,
        html: `<h2>New verified fraud submission</h2><p><b>Email:</b> ${escapeHtml(submission.email)}</p><p><b>Name:</b> ${escapeHtml(submission.name)}</p><p><b>Platform:</b> ${escapeHtml(submission.platform)}</p><p><b>Handle:</b> ${escapeHtml(submission.handle)}</p><p><b>Evidence:</b> ${escapeHtml(submission.evidenceUrl || "")}</p><p><b>Details:</b></p><pre style="white-space:pre-wrap">${escapeHtml(submission.details)}</pre>`,
    });
    res.json({ ok: true });
});
router.post("/fraud/entries/:id/report", rateLimit({ windowMs: 60 * 1000, max: 120, keyPrefix: "fraud:report" }), async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!Number.isFinite(id))
            return res.status(400).json({ error: "Invalid id" });
        const body = z.object({ deviceId: z.string().min(3).max(200) }).parse(req.body);
        const entry = await prisma.fraudEntry.findUnique({ where: { id } });
        if (!entry || !entry.active)
            return res.status(404).json({ error: "Not found" });
        try {
            await prisma.fraudEntryReport.create({ data: { fraudId: id, deviceId: body.deviceId } });
        }
        catch {
            return res.status(409).json({ error: "Already reported" });
        }
        const updated = await prisma.fraudEntry.update({ where: { id }, data: { reports: { increment: 1 } } });
        res.json({ ok: true, item: updated });
    }
    catch (err) {
        console.error("Fraud report error:", err);
        res.status(500).json({ error: err?.message || "Failed to report fraud" });
    }
});
// --- Fraud (Admin) ---
router.get("/admin/fraud/entries", requireAuth, requireAdmin, async (_req, res) => {
    try {
        const items = await prisma.fraudEntry.findMany({ orderBy: [{ updatedAt: "desc" }, { id: "desc" }] });
        res.json({ items });
    }
    catch (err) {
        console.error("Fraud entries list error:", err);
        res.status(500).json({ error: err?.message || "Failed to load fraud entries" });
    }
});
router.post("/admin/fraud/entries", requireAuth, requireAdmin, async (req, res) => {
    try {
        const body = z
            .object({
            name: z.string().min(1).max(200),
            platform: z.string().min(1).max(60),
            handle: z.string().min(1).max(200),
            note: z.string().optional().default(""),
            details: z.string().optional().default(""),
            evidenceUrl: z.preprocess((v) => (v == null || v === "" ? "" : String(v).trim()), z.string().max(2000)),
            active: z.boolean().optional().default(true),
        })
            .parse(req.body);
        const item = await prisma.fraudEntry.create({
            data: {
                name: body.name.trim(),
                platform: body.platform.trim(),
                handle: body.handle.trim(),
                note: body.note.trim(),
                details: body.details.trim(),
                evidenceUrl: body.evidenceUrl ?? "",
                active: body.active,
            },
        });
        res.json({ item });
    }
    catch (err) {
        console.error("Fraud entry create error:", err);
        res.status(500).json({ error: err?.message || "Failed to create fraud entry" });
    }
});
router.post("/admin/fraud/entries/import-defaults", requireAuth, requireAdmin, async (_req, res) => {
    try {
        const defaults = [
            {
                name: "Example Scam Account",
                platform: "Telegram",
                handle: "@example_scammer",
                note: "Default entry (sample)",
                details: "This is a default/sample fraud entry imported for initial setup. Replace with real data as needed.",
                evidenceUrl: "https://example.com",
                active: true,
            },
            {
                name: "Fake Support",
                platform: "WhatsApp",
                handle: "+0000000000",
                note: "Default entry (sample)",
                details: "Impersonates support and asks for payments/credentials. Replace with real data as needed.",
                evidenceUrl: "https://example.com",
                active: true,
            },
            {
                name: "Phishing Website",
                platform: "Website",
                handle: "fake-ripcrack.example",
                note: "Default entry (sample)",
                details: "A sample phishing website entry. Replace with real data as needed.",
                evidenceUrl: "https://example.com",
                active: true,
            },
        ];
        let createdCount = 0;
        let skippedCount = 0;
        for (const d of defaults) {
            const existing = await prisma.fraudEntry.findFirst({
                where: {
                    name: d.name,
                    platform: d.platform,
                    handle: d.handle,
                },
            });
            if (existing) {
                skippedCount += 1;
                continue;
            }
            await prisma.fraudEntry.create({
                data: {
                    name: d.name,
                    platform: d.platform,
                    handle: d.handle,
                    note: d.note,
                    details: d.details,
                    evidenceUrl: d.evidenceUrl,
                    active: d.active,
                    reports: 0,
                },
            });
            createdCount += 1;
        }
        res.json({ ok: true, createdCount, skippedCount, total: defaults.length });
    }
    catch (err) {
        console.error("Fraud import-defaults error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
router.put("/admin/fraud/entries/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!Number.isFinite(id))
            return res.status(400).json({ error: "Invalid id" });
        const body = z
            .object({
            name: z.string().min(1).max(200).optional(),
            platform: z.string().min(1).max(60).optional(),
            handle: z.string().min(1).max(200).optional(),
            note: z.string().optional(),
            details: z.string().optional(),
            evidenceUrl: z.preprocess((v) => (v == null || v === "" ? "" : String(v).trim()), z.string().max(2000)).optional(),
            active: z.boolean().optional(),
        })
            .parse(req.body);
        const data = {};
        if (body.name !== undefined)
            data.name = body.name.trim();
        if (body.platform !== undefined)
            data.platform = body.platform.trim();
        if (body.handle !== undefined)
            data.handle = body.handle.trim();
        if (body.note !== undefined)
            data.note = String(body.note || "").trim();
        if (body.details !== undefined)
            data.details = String(body.details || "").trim();
        if (body.evidenceUrl !== undefined)
            data.evidenceUrl = String(body.evidenceUrl || "").trim();
        if (body.active !== undefined)
            data.active = body.active;
        const item = await prisma.fraudEntry.update({ where: { id }, data });
        res.json({ item });
    }
    catch (err) {
        console.error("Fraud entry update error:", err);
        res.status(500).json({ error: err?.message || "Failed to update fraud entry" });
    }
});
router.delete("/admin/fraud/entries/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!Number.isFinite(id))
            return res.status(400).json({ error: "Invalid id" });
        const existing = await prisma.fraudEntry.findUnique({ where: { id } });
        if (!existing)
            return res.status(404).json({ error: "Fraud entry not found or already deleted" });
        await prisma.fraudEntry.delete({ where: { id } });
        res.json({ ok: true });
    }
    catch (err) {
        console.error("Fraud entry delete error:", err);
        res.status(500).json({ error: err?.message || "Failed to delete fraud entry" });
    }
});
router.get("/admin/fraud/submissions", requireAuth, requireAdmin, async (_req, res) => {
    const items = await prisma.fraudSubmission.findMany({
        where: { approvedAt: null, rejectedAt: null },
        orderBy: { createdAt: "desc" },
    });
    res.json({ items });
});
router.post("/admin/fraud/submissions/:id/approve", requireAuth, requireAdmin, async (req, res) => {
    const id = String(req.params.id || "");
    const submission = await prisma.fraudSubmission.findUnique({ where: { id } });
    if (!submission)
        return res.status(404).json({ error: "Not found" });
    if (!submission.verifiedAt)
        return res.status(400).json({ error: "Submission not verified" });
    if (submission.rejectedAt)
        return res.status(400).json({ error: "Submission rejected" });
    const created = await prisma.fraudEntry.create({
        data: {
            name: submission.name,
            platform: submission.platform,
            handle: submission.handle,
            details: submission.details,
            evidenceUrl: submission.evidenceUrl,
            note: "",
            active: true,
            reports: 0,
        },
    });
    await prisma.fraudSubmission.update({ where: { id }, data: { approvedAt: new Date() } });
    try {
        await sendMail({
            to: submission.email,
            subject: "Your fraud report was approved",
            html: `<h2>Thank you for your report</h2><p>Your fraud report has been reviewed and approved. It is now published on the website.</p><p><b>Platform:</b> ${escapeHtml(submission.platform)}</p><p><b>Handle:</b> ${escapeHtml(submission.handle)}</p>`,
        });
    }
    catch (err) {
        console.error("Fraud approval email failed:", err);
    }
    res.json({ ok: true, item: created });
});
router.get("/admin/special", requireAuth, requireAdmin, async (_req, res) => {
    try {
        const items = await prisma.specialCrackSubmission.findMany({
            orderBy: { createdAt: "desc" },
        });
        res.json({ items });
    }
    catch (err) {
        console.error("[/admin/special] error:", err);
        res.status(500).json({ error: err?.message || "Failed to fetch special crack submissions" });
    }
});
router.post("/admin/fraud/submissions/:id/reject", requireAuth, requireAdmin, async (req, res) => {
    const id = String(req.params.id || "");
    const submission = await prisma.fraudSubmission.findUnique({ where: { id } });
    if (!submission)
        return res.status(404).json({ error: "Not found" });
    if (submission.approvedAt)
        return res.status(400).json({ error: "Submission already approved" });
    await prisma.fraudSubmission.update({ where: { id }, data: { rejectedAt: new Date() } });
    res.json({ ok: true });
});
router.post("/auth/verify-email", rateLimit({ windowMs: 10 * 60 * 1000, max: 30, keyPrefix: "auth:verify_email" }), async (req, res) => {
    const body = z
        .object({ email: z.string().email(), code: z.string().min(6).max(6) })
        .parse(req.body);
    const email = body.email.toLowerCase();
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user)
        return res.status(400).json({ error: "Invalid code" });
    if (user.emailVerified) {
        const token = signJwt({ sub: user.id });
        return res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
    }
    const codeHash = hashEmailVerifyCode(user.id, body.code);
    const record = await prisma.emailVerificationCode.findUnique({ where: { codeHash } });
    if (!record || record.userId !== user.id)
        return res.status(400).json({ error: "Invalid code" });
    if (record.usedAt)
        return res.status(400).json({ error: "Code already used" });
    if (record.expiresAt.getTime() < Date.now())
        return res.status(400).json({ error: "Code expired" });
    await prisma.$transaction([
        prisma.user.update({ where: { id: user.id }, data: { emailVerified: true } }),
        prisma.emailVerificationCode.update({ where: { codeHash }, data: { usedAt: new Date() } }),
    ]);
    const token = signJwt({ sub: user.id });
    res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
});
router.put("/auth/password", rateLimit({ windowMs: 10 * 60 * 1000, max: 20, keyPrefix: "auth:password" }), requireAuth, async (req, res) => {
    const body = z
        .object({ oldPassword: z.string().min(1), newPassword: z.string().min(6) })
        .parse(req.body);
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user)
        return res.status(401).json({ error: "User not found" });
    const ok = await bcrypt.compare(body.oldPassword, user.password);
    if (!ok)
        return res.status(401).json({ error: "Invalid current password" });
    const password = await bcrypt.hash(body.newPassword, 10);
    await prisma.user.update({ where: { id: user.id }, data: { password } });
    res.json({ ok: true });
});
router.put("/auth/profile", rateLimit({ windowMs: 10 * 60 * 1000, max: 20, keyPrefix: "auth:profile" }), requireAuth, async (req, res) => {
    const body = z
        .object({
        email: z.string().email().optional(),
        firstName: z.string().min(1).max(100).optional(),
        lastName: z.string().min(1).max(100).optional()
    })
        .parse(req.body);
    const updateData = {};
    if (body.email !== undefined) {
        const emailLower = body.email.toLowerCase();
        const existing = await prisma.user.findUnique({ where: { email: emailLower } });
        if (existing && existing.id !== req.user.id) {
            return res.status(400).json({ error: "Email already in use" });
        }
        updateData.email = emailLower;
    }
    if (body.firstName !== undefined)
        updateData.firstName = body.firstName.trim() || null;
    if (body.lastName !== undefined)
        updateData.lastName = body.lastName.trim() || null;
    if (Object.keys(updateData).length === 0) {
        return res.status(400).json({ error: "No fields to update" });
    }
    const updated = await prisma.user.update({
        where: { id: req.user.id },
        data: updateData,
        select: { id: true, email: true, role: true, firstName: true, lastName: true }
    });
    res.json({ user: updated });
});
router.post("/auth/forgot-password", rateLimit({ windowMs: 10 * 60 * 1000, max: 10, keyPrefix: "auth:forgot" }), async (req, res) => {
    const body = z.object({ email: z.string().email() }).parse(req.body);
    const email = body.email.toLowerCase();
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user)
        return res.json({ ok: true });
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
    await prisma.passwordResetToken.create({
        data: { userId: user.id, tokenHash, expiresAt },
    });
    // Send password reset email with reset code using template
    const resetEmailHtml = getPasswordResetTemplate({ resetCode: rawToken });
    await sendMail({
        to: user.email,
        subject: "Password reset - RipCrack",
        html: resetEmailHtml,
    });
    res.json({ ok: true });
});
router.put("/auth/reset-password", rateLimit({ windowMs: 10 * 60 * 1000, max: 20, keyPrefix: "auth:reset" }), async (req, res) => {
    const body = z
        .object({ token: z.string().min(10), newPassword: z.string().min(6) })
        .parse(req.body);
    const tokenHash = crypto.createHash("sha256").update(body.token.trim()).digest("hex");
    const record = await prisma.passwordResetToken.findUnique({ where: { tokenHash } });
    if (!record || record.usedAt)
        return res.status(400).json({ error: "Invalid token" });
    if (record.expiresAt.getTime() < Date.now())
        return res.status(400).json({ error: "Token expired" });
    // Trim password to avoid whitespace issues
    const trimmedPassword = body.newPassword.trim();
    if (trimmedPassword.length < 6)
        return res.status(400).json({ error: "Password must be at least 6 characters" });
    const password = await bcrypt.hash(trimmedPassword, 10);
    // Use transaction to ensure both updates happen atomically
    await prisma.$transaction([
        prisma.user.update({ where: { id: record.userId }, data: { password } }),
        prisma.passwordResetToken.update({ where: { tokenHash }, data: { usedAt: new Date() } }),
    ]);
    res.json({ ok: true });
});
router.post("/contact", rateLimit({ windowMs: 10 * 60 * 1000, max: 10, keyPrefix: "contact" }), async (req, res) => {
    try {
        const body = z
            .object({
            name: z.string().trim().min(1).max(200),
            email: z.string().trim().email().max(320),
            message: z.string().trim().min(1).max(10_000),
            captchaToken: z.string().optional().default(""),
        })
            .parse(req.body);
        const captcha = await verifyTurnstile(body.captchaToken, req.ip);
        if (!captcha.ok)
            return res.status(400).json({ error: captcha.error });
        // Get admin email from database, fallback to environment variable
        const adminUser = await prisma.user.findFirst({
            where: { role: "ADMIN" },
            select: { email: true },
        });
        const adminEmail = adminUser?.email || process.env.ADMIN_EMAIL || "admin@example.com";
        console.log(`[CONTACT] Sending contact message email to: ${adminEmail}`);
        try {
            await sendMail({
                to: adminEmail,
                subject: `New contact message from ${body.name}`,
                html: `<h2>New Contact Message</h2><p><b>Name:</b> ${escapeHtml(body.name)}</p><p><b>Email:</b> ${escapeHtml(body.email)}</p><p><b>IP:</b> ${escapeHtml(String(getClientIp(req)))}</p><p><b>Message:</b></p><pre style="white-space:pre-wrap">${escapeHtml(body.message)}</pre>`,
            });
            console.log(`[CONTACT] Contact message email sent successfully to: ${adminEmail}`);
        }
        catch (error) {
            console.error(`[CONTACT] Failed to send contact message email to ${adminEmail}:`, error.message);
            // Don't fail the request - email sending is not critical
            // But log the error for debugging
        }
        res.json({ ok: true });
    }
    catch (err) {
        console.error("[/contact] error:", err);
        if (err instanceof z.ZodError) {
            return res.status(400).json({ error: "Invalid request: " + err.errors.map((e) => e.message).join(", ") });
        }
        res.status(500).json({ error: err?.message || "Contact submission failed" });
    }
});
router.post("/special-crack", rateLimit({ windowMs: 10 * 60 * 1000, max: 10, keyPrefix: "special-crack" }), uploadSingle.single("attachment"), async (req, res) => {
    try {
        const body = z
            .object({
            name: z.string().trim().min(1).max(200),
            email: z.string().trim().email().max(320),
            whatsapp: z.string().trim().min(1).max(50),
            website: z.string().trim().min(1).max(500),
            service: z.string().trim().min(1).max(100),
            budget: z.string().trim().min(1).max(100),
            message: z.string().trim().min(1).max(10_000),
            smileyRating: z.coerce.number().int().min(0).max(4).default(3),
            captchaToken: z.string().optional().default(""),
        })
            .parse(req.body);
        const captcha = await verifyTurnstile(body.captchaToken, req.ip);
        if (!captcha.ok)
            return res.status(400).json({ error: captcha.error });
        const file = req.file;
        const attachmentUrl = file ? `/api/uploads/${file.filename}` : "";
        const ip = getClientIp(req);
        const userAgent = String(req.headers["user-agent"] || "").slice(0, 500);
        const submission = await prisma.specialCrackSubmission.create({
            data: {
                name: body.name,
                email: body.email.toLowerCase(),
                whatsapp: body.whatsapp,
                website: body.website,
                service: body.service,
                budget: body.budget,
                message: body.message,
                attachmentUrl,
                smileyRating: body.smileyRating,
                ip,
                userAgent,
            },
        });
        // Get admin email from database, fallback to environment variable
        const adminUser = await prisma.user.findFirst({
            where: { role: "ADMIN" },
            select: { email: true },
        });
        const adminEmail = adminUser?.email || process.env.ADMIN_EMAIL || "admin@example.com";
        console.log(`[SPECIAL-CRACK] Sending email to: ${adminEmail}`);
        try {
            const smileyEmojis = ["😞", "🙁", "😐", "🙂", "😃"];
            const smileyEmoji = smileyEmojis[body.smileyRating] || "😐";
            await sendMail({
                to: adminEmail,
                subject: `New Special Crack Request: ${body.service}`,
                html: `<h2>New Special Crack Request</h2>
            <p><b>Name:</b> ${escapeHtml(body.name)}</p>
            <p><b>Email:</b> ${escapeHtml(body.email)}</p>
            <p><b>WhatsApp:</b> ${escapeHtml(body.whatsapp)}</p>
            <p><b>Website:</b> ${escapeHtml(body.website)}</p>
            <p><b>Service:</b> ${escapeHtml(body.service)}</p>
            <p><b>Budget:</b> ${escapeHtml(body.budget)}</p>
            <p><b>Smiley Rating:</b> ${smileyEmoji} (${body.smileyRating + 1}/5)</p>
            <p><b>IP:</b> ${escapeHtml(ip)}</p>
            <p><b>Message:</b></p>
            <pre style="white-space:pre-wrap">${escapeHtml(body.message)}</pre>
            ${attachmentUrl ? `<p><b>Attachment:</b> <a href="${escapeHtml(attachmentUrl)}">${escapeHtml(attachmentUrl)}</a></p>` : ""}
            <p><b>Submission ID:</b> ${submission.id}</p>`,
            });
            console.log(`[SPECIAL-CRACK] Email sent successfully to: ${adminEmail}`);
        }
        catch (error) {
            console.error(`[SPECIAL-CRACK] Failed to send email to ${adminEmail}:`, error.message);
            // Don't fail the request - email sending is not critical
        }
        res.json({ ok: true, submissionId: submission.id });
    }
    catch (err) {
        console.error("[/special-crack] error:", err);
        if (err instanceof z.ZodError) {
            return res.status(400).json({ error: "Invalid request: " + err.errors.map((e) => e.message).join(", ") });
        }
        res.status(500).json({ error: err?.message || "Special crack submission failed" });
    }
});
function escapeHtml(s) {
    return String(s || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
function csvEscape(v) {
    const s = String(v ?? "");
    if (/[",\n\r]/.test(s))
        return `"${s.replace(/"/g, '""')}"`;
    return s;
}
function getPublicApiUrl() {
    const envUrl = String(process.env.PUBLIC_API_URL || "").trim();
    if (envUrl)
        return envUrl.replace(/\/$/, "");
    const origin = String(process.env.CORS_ORIGIN || "").trim();
    if (origin)
        return `${origin.replace(/\/$/, "")}/api`;
    return "http://localhost:8080/api";
}
function buildOrderTrackingApiLink(orderId, token) {
    // Use APP_URL if set, otherwise fall back to getPublicApiUrl()
    const appUrl = String(process.env.APP_URL || "").trim();
    const base = appUrl ? `${appUrl.replace(/\/$/, "")}/api` : getPublicApiUrl();
    const qs = new URLSearchParams({ orderId: String(orderId), token });
    return `${base}/orders/track?${qs.toString()}`;
}
router.post("/track/page", rateLimit({ windowMs: 60 * 1000, max: 240, keyPrefix: "track:page" }), async (req, res) => {
    try {
        const body = z
            .object({
            deviceId: z.string().min(3).max(200),
            page: z.string().min(1).max(80),
            path: z.string().optional().default(""),
            productId: z.coerce.number().int().positive().optional(),
        })
            .parse(req.body);
        const ip = getClientIp(req);
        const ua = String(req.headers["user-agent"] || "").slice(0, 500);
        const path = String(body.path || "").slice(0, 500);
        prisma.siteVisit
            .upsert({
            where: { deviceId: body.deviceId },
            update: {
                ip,
                userAgent: ua,
                visitCount: { increment: 1 },
                lastSeenAt: new Date(),
            },
            create: {
                deviceId: body.deviceId,
                ip,
                userAgent: ua,
                visitCount: 1,
            },
        })
            .catch(() => null);
        const pvPromise = prisma.pageView
            .create({
            data: {
                deviceId: body.deviceId,
                ip,
                page: body.page,
                path,
                productId: body.productId ?? null,
                country: "",
                city: "",
            },
        })
            .catch(() => null);
        res.json({ ok: true });
        (async () => {
            const geo = await getGeoForIp(ip);
            if (!geo.country && !geo.city)
                return;
            await prisma.siteVisit
                .update({ where: { deviceId: body.deviceId }, data: { country: geo.country, city: geo.city } })
                .catch(() => null);
            const pv = await pvPromise;
            if (!pv)
                return;
            await prisma.pageView
                .update({ where: { id: pv.id }, data: { country: geo.country, city: geo.city } })
                .catch(() => null);
        })().catch(() => null);
    }
    catch (err) {
        console.error("[/track/page] error:", err);
        if (err instanceof z.ZodError) {
            return res.status(400).json({ error: "Invalid request: " + err.errors.map(e => e.message).join(", ") });
        }
        res.status(500).json({ error: err?.message || "Failed to track page" });
    }
});
router.get("/admin/analytics/summary", requireAuth, requireAdmin, async (_req, res) => {
    try {
        const [totalPageViews, uniqueDevices, uniqueIps, topPages, topCountries, topProductsViewed, topProductsSold,] = await Promise.all([
            prisma.pageView.count(),
            prisma.siteVisit.count(),
            prisma.siteVisit
                .groupBy({ by: ["ip"], _count: { ip: true } })
                .then((rows) => rows.length)
                .catch(() => 0),
            prisma.pageView.groupBy({ by: ["page"], _count: { page: true }, orderBy: { _count: { page: "desc" } }, take: 20 }),
            prisma.pageView.groupBy({
                by: ["country", "city"],
                _count: { country: true },
                orderBy: { _count: { country: "desc" } },
                take: 30,
                where: { country: { not: "" } },
            }),
            prisma.pageView.groupBy({
                by: ["productId"],
                _count: { productId: true },
                orderBy: { _count: { productId: "desc" } },
                take: 20,
                where: { productId: { not: null } },
            }),
            prisma.product.findMany({ orderBy: { sold: "desc" }, take: 20, select: { id: true, title: true, sold: true, views: true } }),
        ]);
        const productIds = topProductsViewed
            .map((x) => Number(x.productId))
            .filter((x) => Number.isFinite(x));
        const products = productIds.length
            ? await prisma.product.findMany({ where: { id: { in: productIds } }, select: { id: true, title: true, sold: true, views: true } })
            : [];
        const productById = new Map(products.map((p) => [p.id, p]));
        res.json({
            totals: {
                totalVisits: totalPageViews,
                uniqueDevices,
                uniqueIps,
            },
            topPages: topPages.map((x) => ({ page: x.page, views: x._count.page })),
            topCountries: topCountries.map((x) => ({ country: x.country, city: x.city, views: x._count.country })),
            topProductsViewed: topProductsViewed.map((x) => ({
                productId: x.productId,
                title: x.productId ? productById.get(Number(x.productId))?.title || "" : "",
                views: x._count.productId,
            })),
            topProductsSold: topProductsSold.map((p) => ({ productId: p.id, title: p.title, sold: p.sold, views: p.views })),
        });
    }
    catch (e) {
        const code = String(e?.code || "");
        console.error("[analytics/summary] failed", e);
        if (code === "P2021" || code === "P2022") {
            return res.status(503).json({
                message: "Analytics tables are missing. Run prisma migrate dev + prisma generate, then restart backend.",
                code,
            });
        }
        return res.status(500).json({ message: e?.message || "Failed to load analytics" });
    }
});
router.get("/products", async (req, res) => {
    try {
        const q = String(req.query.q || "");
        const category = String(req.query.category || "");
        const where = {};
        // MySQL does not support Prisma's mode: "insensitive"; use contains only (case-sensitive at DB). Frontend filters case-insensitively.
        if (q)
            where.title = { contains: q };
        if (category && category !== "All")
            where.category = category;
        const items = await prisma.product.findMany({
            where,
            orderBy: [{ sortOrder: "asc" }, { createdAt: "desc" }]
        });
        res.json({ items });
    }
    catch (err) {
        console.error("[/products] error:", err);
        res.status(500).json({ error: err?.message || "Failed to load products" });
    }
});
// Get product by route (custom frontend route)
router.get("/products/route/:route", async (req, res) => {
    const route = String(req.params.route || "").trim();
    if (!route)
        return res.status(400).json({ error: "Invalid route" });
    const item = await prisma.product.findUnique({ where: { frontendRoute: route } });
    if (!item)
        return res.status(404).json({ error: "Not found" });
    const deviceId = String(req.query.deviceId || "").trim();
    if (!deviceId) {
        await prisma.product.update({ where: { id: item.id }, data: { views: { increment: 1 } } });
        const updated = await prisma.product.findUnique({ where: { id: item.id } });
        return res.json({ item: updated });
    }
    // Use createMany with skipDuplicates to handle race conditions gracefully
    try {
        const result = await prisma.productView.createMany({
            data: [{ productId: item.id, deviceId }],
            skipDuplicates: true
        });
        // Only increment view count if we actually created a new view
        if (result.count > 0) {
            await prisma.product.update({ where: { id: item.id }, data: { views: { increment: 1 } } });
        }
    }
    catch (err) {
        // Silently handle any errors in view tracking
        // This can happen in race conditions, but we don't want to fail the request
    }
    const updated = await prisma.product.findUnique({ where: { id: item.id } });
    res.json({ item: updated });
});
router.get("/products/:id", async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const item = await prisma.product.findUnique({ where: { id } });
    if (!item)
        return res.status(404).json({ error: "Not found" });
    const deviceId = String(req.query.deviceId || "").trim();
    if (!deviceId) {
        await prisma.product.update({ where: { id }, data: { views: { increment: 1 } } });
        const updated = await prisma.product.findUnique({ where: { id } });
        return res.json({ item: updated });
    }
    // Use createMany with skipDuplicates to handle race conditions gracefully
    try {
        const result = await prisma.productView.createMany({
            data: [{ productId: id, deviceId }],
            skipDuplicates: true
        });
        // Only increment view count if we actually created a new view
        if (result.count > 0) {
            await prisma.product.update({ where: { id }, data: { views: { increment: 1 } } });
        }
    }
    catch (err) {
        // Silently handle any errors in view tracking
        // This can happen in race conditions, but we don't want to fail the request
    }
    const updated = await prisma.product.findUnique({ where: { id } });
    res.json({ item: updated });
});
router.get("/admin/users", requireAuth, requireAdmin, async (_req, res) => {
    const items = await prisma.user.findMany({ orderBy: { createdAt: "desc" } });
    res.json({ items });
});
router.get("/admin/footer-links", requireAuth, requireAdmin, async (_req, res) => {
    const items = await prisma.footerLink.findMany({ orderBy: [{ group: "asc" }, { sortOrder: "asc" }, { id: "asc" }] });
    res.json({ items });
});
router.post("/admin/footer-links", requireAuth, requireAdmin, async (req, res) => {
    const body = z
        .object({
        group: z.enum(["RESOURCES", "INFORMATION"]),
        labels: z.record(z.string().min(1), z.string().min(1)),
        targetType: z.enum(["PAGE", "URL"]),
        targetPage: z.string().optional().default(""),
        targetUrl: z.string().optional().default(""),
        sortOrder: z.coerce.number().int().optional().default(0),
        enabled: z.coerce.boolean().optional().default(true)
    })
        .parse(req.body);
    const targetPage = String(body.targetPage || "").trim();
    const targetUrl = String(body.targetUrl || "").trim();
    if (body.targetType === "PAGE" && !targetPage)
        return res.status(400).json({ error: "Missing targetPage" });
    if (body.targetType === "URL") {
        if (!targetUrl)
            return res.status(400).json({ error: "Missing targetUrl" });
        try {
            new URL(targetUrl);
        }
        catch {
            return res.status(400).json({ error: "Invalid targetUrl" });
        }
    }
    const created = await prisma.footerLink.create({
        data: {
            group: body.group,
            labels: body.labels,
            targetType: body.targetType,
            targetPage: body.targetType === "PAGE" ? targetPage : "",
            targetUrl: body.targetType === "URL" ? targetUrl : "",
            sortOrder: body.sortOrder,
            enabled: body.enabled
        }
    });
    res.json({ item: created });
});
router.put("/admin/footer-links/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const body = z
        .object({
        group: z.enum(["RESOURCES", "INFORMATION"]).optional(),
        labels: z.record(z.string().min(1), z.string().min(1)).optional(),
        targetType: z.enum(["PAGE", "URL"]).optional(),
        targetPage: z.string().optional(),
        targetUrl: z.string().optional(),
        sortOrder: z.coerce.number().int().optional(),
        enabled: z.coerce.boolean().optional()
    })
        .parse(req.body);
    const existing = await prisma.footerLink.findUnique({ where: { id } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    const nextTargetType = body.targetType || existing.targetType;
    const nextTargetPage = String(body.targetPage ?? existing.targetPage ?? "").trim();
    const nextTargetUrl = String(body.targetUrl ?? existing.targetUrl ?? "").trim();
    if (nextTargetType === "PAGE" && !nextTargetPage)
        return res.status(400).json({ error: "Missing targetPage" });
    if (nextTargetType === "URL") {
        if (!nextTargetUrl)
            return res.status(400).json({ error: "Missing targetUrl" });
        try {
            new URL(nextTargetUrl);
        }
        catch {
            return res.status(400).json({ error: "Invalid targetUrl" });
        }
    }
    const updated = await prisma.footerLink.update({
        where: { id },
        data: {
            group: body.group,
            labels: body.labels ?? undefined,
            targetType: nextTargetType,
            targetPage: nextTargetType === "PAGE" ? nextTargetPage : "",
            targetUrl: nextTargetType === "URL" ? nextTargetUrl : "",
            sortOrder: body.sortOrder,
            enabled: body.enabled
        }
    });
    res.json({ item: updated });
});
router.delete("/admin/footer-links/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    await prisma.footerLink.delete({ where: { id } });
    res.json({ ok: true });
});
router.get("/admin/users/export.csv", requireAuth, requireAdmin, async (_req, res) => {
    const items = await prisma.user.findMany({ orderBy: { createdAt: "desc" } });
    const header = ["id", "email", "role", "createdAt"];
    const rows = items.map((u) => [u.id, u.email, u.role, u.createdAt?.toISOString?.() || String(u.createdAt || "")]);
    const csv = [header.map(csvEscape).join(","), ...rows.map((r) => r.map(csvEscape).join(","))].join("\n");
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename=users_${Date.now()}.csv`);
    res.send(csv);
});
router.post("/orders", requireAuth, async (req, res) => {
    const orderStart = Date.now();
    console.log("[ORDER] POST /orders received", { userId: req.user?.id, at: new Date().toISOString() });
    const orderSummarySchema = z.object({
        subtotal: z.coerce.number().min(0),
        discount: z.coerce.number().min(0).optional().default(0),
        total: z.coerce.number().min(0),
    }).optional();
    const baseSchema = z.object({
        purchaseTerm: z.enum(["ANNUAL", "LIFETIME"]),
        selectedType: z.string().min(1).default("Personal"),
        customerName: z.string().min(2).max(200),
        customerEmail: z.string().email().max(320),
        customerPhone: z.string().min(6).max(40),
        country: z.string().min(2).max(100),
        city: z.string().min(2).max(120),
        street: z.string().min(3).max(200),
        zip: z.string().min(3).max(20),
        notes: z.string().optional().default(""),
        orderSummary: orderSummarySchema,
    });
    const singleSchema = baseSchema.extend({
        productId: z.coerce.number().int().positive(),
    });
    const multiSchema = baseSchema.extend({
        items: z.array(z.object({
            productId: z.coerce.number().int().positive(),
            qty: z.coerce.number().int().min(1).max(10_000).default(1),
            productType: z.enum(["Personal", "Business"]).optional(),
        })).min(1)
    });
    const bodyAny = z.union([multiSchema, singleSchema]).parse(req.body);
    const items = ("items" in bodyAny)
        ? bodyAny.items.map((x) => ({ productId: x.productId, qty: x.qty, productType: x.productType }))
        : [{ productId: bodyAny.productId, qty: 1, productType: undefined }];
    const itemsForDb = items.map((x) => ({
        productId: x.productId,
        qty: x.qty,
        productType: x.productType ?? bodyAny.selectedType,
    }));
    const orderSummary = bodyAny.orderSummary;
    const uniqueIds = Array.from(new Set(items.map((x) => x.productId)));
    const products = await prisma.product.findMany({ where: { id: { in: uniqueIds } } });
    if (products.length !== uniqueIds.length)
        return res.status(400).json({ error: "Invalid product" });
    const productById = new Map(products.map((p) => [p.id, p]));
    const primaryProductId = items[0].productId;
    const primaryProduct = productById.get(primaryProductId);
    const rawTrackToken = crypto.randomBytes(24).toString("hex");
    const trackingTokenHash = crypto.createHash("sha256").update(rawTrackToken).digest("hex");
    const order = await prisma.$transaction(async (tx) => {
        const created = await tx.order.create({
            data: {
                userId: req.user.id,
                productId: primaryProduct.id,
                trackingTokenHash,
                purchaseTerm: bodyAny.purchaseTerm,
                selectedType: bodyAny.selectedType,
                customerName: bodyAny.customerName,
                customerEmail: bodyAny.customerEmail,
                customerPhone: bodyAny.customerPhone,
                country: bodyAny.country,
                city: bodyAny.city,
                street: bodyAny.street,
                zip: bodyAny.zip,
                notes: bodyAny.notes ?? "",
                subtotal: orderSummary != null ? orderSummary.subtotal : undefined,
                discountAmount: orderSummary != null ? (orderSummary.discount ?? 0) : undefined,
                total: orderSummary != null ? orderSummary.total : undefined,
                orderItems: {
                    create: itemsForDb.map((it) => ({
                        productId: it.productId,
                        qty: it.qty,
                        productType: it.productType ?? null,
                    }))
                }
            },
            include: { user: true, product: true, orderItems: { include: { product: true } } }
        });
        for (const it of itemsForDb) {
            await tx.product.update({ where: { id: it.productId }, data: { sold: { increment: it.qty } } });
        }
        return created;
    });
    const itemsHtml = order.orderItems
        .map((it) => `<li>${escapeHtml(it.product?.title || String(it.productId))} × <b>${it.qty}</b></li>`)
        .join("");
    const orderDuration = Date.now() - orderStart;
    console.log("[ORDER] POST /orders completed", { orderId: order.id, durationMs: orderDuration, at: new Date().toISOString() });
    // Respond to client immediately so order placement never blocks on email
    res.json({ order });
    // Send emails in background (don't block or fail the request)
    (async () => {
        const adminUser = await prisma.user.findFirst({
            where: { role: "ADMIN" },
            select: { email: true },
        });
        const adminEmail = adminUser?.email || process.env.ADMIN_EMAIL || "admin@example.com";
        console.log(`[ORDER] Sending new order email to admin: ${adminEmail}`);
        try {
            await sendMail({
                to: adminEmail,
                subject: `New order request: ${primaryProduct.title}${order.orderItems.length > 1 ? ` (+${order.orderItems.length - 1} more)` : ""}`,
                html: `<h2>New Order Request</h2><p><b>User:</b> ${order.user.email}</p><p><b>Customer:</b> ${escapeHtml(order.customerName || "-")}</p><p><b>Customer email:</b> ${escapeHtml(order.customerEmail || "-")}</p><p><b>Customer phone:</b> ${escapeHtml(order.customerPhone || "-")}</p><p><b>Address:</b> ${escapeHtml([order.street, order.city, order.zip, order.country].filter(Boolean).join(", ") || "-")}</p><p><b>Items:</b></p><ul>${itemsHtml || ""}</ul><p><b>Term:</b> ${order.purchaseTerm}</p><p><b>Plan:</b> ${order.selectedType}</p><p><b>Note:</b></p><pre style="white-space:pre-wrap">${escapeHtml(order.notes || "-")}</pre><p><b>Order ID:</b> ${order.id}</p>`
            });
            console.log(`[ORDER] New order email sent successfully to admin: ${adminEmail}`);
        }
        catch (error) {
            console.error(`[ORDER] Failed to send new order email to admin ${adminEmail}:`, error.message);
        }
        const trackingLink = buildOrderTrackingApiLink(order.id, rawTrackToken);
        const customerEmail = order.customerEmail || order.user.email;
        if (!customerEmail)
            return;
        try {
            const orderItemsWithType = order.orderItems.map((oi) => {
                const reqItem = items.find((i) => i.productId === oi.productId);
                const productType = (oi.productType != null && String(oi.productType).trim() !== "")
                    ? String(oi.productType).trim()
                    : (reqItem && "productType" in reqItem && reqItem.productType)
                        ? reqItem.productType
                        : order.selectedType;
                const images = Array.isArray(oi.product?.images) ? oi.product.images : (typeof oi.product?.images === "string" ? (() => { try {
                    return JSON.parse(oi.product.images);
                }
                catch {
                    return [];
                } })() : []);
                const firstImage = Array.isArray(images) && images[0] ? images[0] : (oi.product?.cover ?? null);
                return {
                    product: {
                        title: oi.product?.title || "Product",
                        description: oi.product?.description || null,
                        price: oi.product?.price || null,
                        personalPrice: oi.product?.personalPrice || null,
                        businessPrice: oi.product?.businessPrice || null,
                        cover: firstImage,
                    },
                    qty: oi.qty,
                    productType: productType,
                };
            });
            const orderConfirmationHtml = getOrderConfirmationTemplate({
                orderId: order.id,
                customerName: order.customerName || order.user.email,
                customerEmail: customerEmail,
                street: order.street || "",
                city: order.city || "",
                zip: order.zip || "",
                country: order.country || "",
                purchaseTerm: order.purchaseTerm,
                selectedType: order.selectedType,
                orderItems: orderItemsWithType,
                trackingLink: trackingLink,
                orderSummary: orderSummary ? { subtotal: orderSummary.subtotal, discount: orderSummary.discount ?? 0, total: orderSummary.total } : undefined,
            });
            await sendMail({
                to: customerEmail,
                subject: `Order received: ${primaryProduct.title}${order.orderItems.length > 1 ? ` (+${order.orderItems.length - 1} more)` : ""}`,
                html: orderConfirmationHtml,
            });
            console.log(`[ORDER] Order confirmation email sent to customer: ${customerEmail}`);
        }
        catch (error) {
            console.error(`[ORDER] Failed to send order confirmation to ${customerEmail}:`, error.message);
        }
    })();
});
router.get("/me/orders", requireAuth, async (req, res) => {
    const items = await prisma.order.findMany({
        where: { userId: req.user.id },
        orderBy: { createdAt: "desc" },
        include: { product: true, orderItems: { include: { product: true } } }
    });
    res.json({ items });
});
router.put("/me/orders/:id/cancel", requireAuth, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const existing = await prisma.order.findUnique({ where: { id }, include: { user: true, product: true } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    // Only allow canceling own orders
    if (existing.userId !== req.user.id)
        return res.status(403).json({ error: "Forbidden" });
    // Only allow canceling REQUESTED orders
    if (existing.status !== "REQUESTED") {
        return res.status(400).json({ error: `Cannot cancel order with status: ${existing.status}` });
    }
    const updated = await prisma.order.update({
        where: { id },
        data: { status: "CANCELED" },
        include: { user: true, product: true, orderItems: { include: { product: true } } }
    });
    // Send order cancellation email to customer
    const customerEmail = updated.customerEmail || updated.user.email;
    if (customerEmail) {
        const orderWithTotals = updated;
        const hasStoredTotals = typeof orderWithTotals.subtotal === "number" && Number.isFinite(orderWithTotals.subtotal) && typeof orderWithTotals.total === "number" && Number.isFinite(orderWithTotals.total);
        const cancellationHtml = getOrderCancellationTemplate({
            orderId: updated.id,
            cancellationDate: new Date(),
            purchaseTerm: updated.purchaseTerm,
            selectedType: updated.selectedType,
            orderItems: updated.orderItems.map((it) => {
                const images = Array.isArray(it.product?.images) ? it.product.images : (typeof it.product?.images === "string" ? (() => { try {
                    return JSON.parse(it.product.images);
                }
                catch {
                    return [];
                } })() : []);
                const firstImage = Array.isArray(images) && images[0] ? images[0] : (it.product?.cover ?? null);
                return {
                    product: {
                        title: it.product?.title || "Product",
                        description: it.product?.description || null,
                        price: it.product?.price || null,
                        personalPrice: it.product?.personalPrice || null,
                        businessPrice: it.product?.businessPrice || null,
                        cover: firstImage,
                    },
                    qty: it.qty,
                };
            }),
            orderSummary: hasStoredTotals
                ? {
                    subtotal: orderWithTotals.subtotal,
                    discount: orderWithTotals.discountAmount ?? 0,
                    refundTotal: orderWithTotals.total,
                }
                : undefined,
        });
        try {
            await sendMail({
                to: customerEmail,
                subject: `Order cancelled: ${updated.product?.title || "Order"}`,
                html: cancellationHtml,
            });
            console.log(`[ORDER] Cancellation email sent successfully to customer: ${customerEmail}`);
        }
        catch (error) {
            console.error(`[ORDER] Failed to send cancellation email to customer ${customerEmail}:`, error.message);
            // Don't fail the request - email sending is not critical
        }
    }
    // Send order cancellation notification to admin
    const adminUser = await prisma.user.findFirst({
        where: { role: "ADMIN" },
        select: { email: true },
    });
    const adminEmail = adminUser?.email || process.env.ADMIN_EMAIL || "admin@example.com";
    const itemsHtml = updated.orderItems
        .map((it) => `<li>${escapeHtml(it.product?.title || String(it.productId))} × <b>${it.qty}</b></li>`)
        .join("");
    console.log(`[ORDER] Sending cancellation notification to admin: ${adminEmail}`);
    try {
        await sendMail({
            to: adminEmail,
            subject: `Order cancelled: ${updated.product?.title || "Order"} (ID: ${updated.id})`,
            html: `<h2>Order Cancelled</h2>
        <p><b>Order ID:</b> ${updated.id}</p>
        <p><b>User:</b> ${updated.user.email}</p>
        <p><b>Customer:</b> ${escapeHtml(updated.customerName || "-")}</p>
        <p><b>Customer email:</b> ${escapeHtml(updated.customerEmail || "-")}</p>
        <p><b>Items:</b></p>
        <ul>${itemsHtml || ""}</ul>
        <p><b>Term:</b> ${updated.purchaseTerm}</p>
        <p><b>Plan:</b> ${updated.selectedType}</p>
        <p><b>Cancelled at:</b> ${new Date().toLocaleString()}</p>`
        });
        console.log(`[ORDER] Cancellation notification sent successfully to admin: ${adminEmail}`);
    }
    catch (error) {
        console.error(`[ORDER] Failed to send cancellation notification to admin ${adminEmail}:`, error.message);
        // Don't fail the request - email sending is not critical
    }
    res.json({ item: updated });
});
router.get("/orders/track", rateLimit({ windowMs: 5 * 60 * 1000, max: 60, keyPrefix: "orders:track" }), async (req, res) => {
    const q = z.object({ orderId: z.coerce.number().int().positive(), token: z.string().min(10) }).parse(req.query);
    const tokenHash = crypto.createHash("sha256").update(q.token).digest("hex");
    const order = await prisma.order.findUnique({ where: { id: q.orderId }, include: { product: true } });
    if (!order)
        return res.status(404).json({ error: "Not found" });
    if (!order.trackingTokenHash)
        return res.status(400).json({ error: "Tracking not available for this order" });
    if (order.trackingTokenHash !== tokenHash)
        return res.status(401).json({ error: "Invalid token" });
    res.json({
        item: {
            id: order.id,
            status: order.status,
            createdAt: order.createdAt,
            product: { id: order.productId, title: order.product?.title || "" },
            purchaseTerm: order.purchaseTerm,
            selectedType: order.selectedType
        }
    });
});
router.get("/fraud", async (_req, res) => {
    const items = await prisma.fraudReport.findMany({ orderBy: { reports: "desc" } });
    res.json({ items });
});
router.post("/fraud/report", async (req, res) => {
    const body = z.object({
        name: z.string().min(2),
        platform: z.string().min(2),
        handle: z.string().min(2),
        details: z.string().min(10),
    }).parse(req.body);
    const existing = await prisma.fraudReport.findFirst({ where: { platform: body.platform, handle: body.handle } });
    if (existing) {
        const updated = await prisma.fraudReport.update({ where: { id: existing.id }, data: { reports: { increment: 1 } } });
        return res.json({ item: updated, merged: true });
    }
    const created = await prisma.fraudReport.create({ data: body });
    res.json({ item: created, merged: false });
});
router.get("/admin/orders", requireAuth, requireAdmin, async (_req, res) => {
    const items = await prisma.order.findMany({
        orderBy: { createdAt: "desc" },
        include: { user: true, product: true, orderItems: { include: { product: true } } }
    });
    res.json({ items });
});
router.get("/admin/orders/export.csv", requireAuth, requireAdmin, async (req, res) => {
    const q = z
        .object({
        status: z.enum(["ALL", "REQUESTED", "CONFIRMED", "REJECTED"]).optional().default("ALL"),
        from: z.string().optional().default(""),
        to: z.string().optional().default("")
    })
        .parse(req.query);
    const where = {};
    if (q.status && q.status !== "ALL")
        where.status = q.status;
    if (q.from && q.from.trim()) {
        const fromDate = new Date(q.from.trim() + "T00:00:00.000Z");
        if (!Number.isNaN(fromDate.getTime())) {
            where.createdAt = { ...(where.createdAt || {}), gte: fromDate };
        }
    }
    if (q.to && q.to.trim()) {
        const toDate = new Date(q.to.trim() + "T23:59:59.999Z");
        if (!Number.isNaN(toDate.getTime())) {
            where.createdAt = { ...(where.createdAt || {}), lte: toDate };
        }
    }
    const items = await prisma.order.findMany({
        where,
        orderBy: { createdAt: "desc" },
        include: { user: true, product: true }
    });
    const header = [
        "id",
        "createdAt",
        "status",
        "userId",
        "userEmail",
        "productId",
        "productTitle",
        "purchaseTerm",
        "selectedType",
        "customerName",
        "customerEmail",
        "customerPhone",
        "country",
        "city",
        "street",
        "zip",
        "notes"
    ];
    const rows = items.map((o) => [
        o.id,
        o.createdAt?.toISOString?.() || String(o.createdAt || ""),
        o.status,
        o.userId,
        o.user?.email || "",
        o.productId,
        o.product?.title || "",
        o.purchaseTerm,
        o.selectedType,
        o.customerName,
        o.customerEmail,
        o.customerPhone,
        o.country,
        o.city,
        o.street,
        o.zip,
        o.notes
    ]);
    const csv = [header.map(csvEscape).join(","), ...rows.map((r) => r.map(csvEscape).join(","))].join("\n");
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename=orders_${Date.now()}.csv`);
    res.send(csv);
});
router.put("/admin/orders/:id/status", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const body = z
        .object({
        status: z.enum(["REQUESTED", "CONFIRMED", "REJECTED", "CANCELED"])
    })
        .parse(req.body);
    const existing = await prisma.order.findUnique({ where: { id }, include: { user: true, product: true, orderItems: { include: { product: true } } } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    const rawTrackToken = crypto.randomBytes(24).toString("hex");
    const trackingTokenHash = crypto.createHash("sha256").update(rawTrackToken).digest("hex");
    const updated = await prisma.order.update({
        where: { id },
        data: { status: body.status, trackingTokenHash },
        include: { user: true, product: true, orderItems: { include: { product: true } } }
    });
    const to = (updated.customerEmail || updated.user?.email || "").trim();
    if (to) {
        if (body.status === "REJECTED") {
            // Send same cancellation-style email to customer as when user cancels
            const orderWithTotals = updated;
            const hasStoredTotals = typeof orderWithTotals.subtotal === "number" && Number.isFinite(orderWithTotals.subtotal) && typeof orderWithTotals.total === "number" && Number.isFinite(orderWithTotals.total);
            const cancellationHtml = getOrderCancellationTemplate({
                orderId: updated.id,
                cancellationDate: new Date(),
                purchaseTerm: updated.purchaseTerm,
                selectedType: updated.selectedType,
                orderItems: updated.orderItems.map((it) => {
                    const images = Array.isArray(it.product?.images) ? it.product.images : (typeof it.product?.images === "string" ? (() => { try {
                        return JSON.parse(it.product.images);
                    }
                    catch {
                        return [];
                    } })() : []);
                    const firstImage = Array.isArray(images) && images[0] ? images[0] : (it.product?.cover ?? null);
                    return {
                        product: {
                            title: it.product?.title || "Product",
                            description: it.product?.description || null,
                            price: it.product?.price || null,
                            personalPrice: it.product?.personalPrice || null,
                            businessPrice: it.product?.businessPrice || null,
                            cover: firstImage,
                        },
                        qty: it.qty,
                    };
                }),
                orderSummary: hasStoredTotals
                    ? {
                        subtotal: orderWithTotals.subtotal,
                        discount: orderWithTotals.discountAmount ?? 0,
                        refundTotal: orderWithTotals.total,
                    }
                    : undefined,
                isRejection: true,
            });
            try {
                await sendMail({
                    to,
                    subject: `Order Rejected: ${updated.product?.title || "Order"}`,
                    html: cancellationHtml,
                });
                console.log(`[ORDER] Rejection (cancellation) email sent to customer: ${to}`);
            }
            catch (error) {
                console.error(`[ORDER] Failed to send rejection email to customer ${to}:`, error.message);
            }
        }
        else if (body.status === "CONFIRMED") {
            const appUrl = (process.env.APP_URL || "https://ripcrack.net").trim().replace(/\/$/, "");
            const accountLink = `${appUrl}/account`;
            const confirmationHtml = getOrderConfirmedByAdminTemplate({
                orderId: updated.id,
                trackingLink: accountLink,
            });
            try {
                await sendMail({
                    to,
                    subject: `Order Confirmed: ${updated.product?.title || "Order"}`,
                    html: confirmationHtml,
                });
                console.log(`[ORDER] Confirmation email sent to customer: ${to}`);
            }
            catch (error) {
                console.error(`[ORDER] Failed to send confirmation email to customer ${to}:`, error.message);
            }
        }
        else {
            const link = buildOrderTrackingApiLink(updated.id, rawTrackToken);
            await sendMail({
                to,
                subject: `Order status updated: ${updated.product?.title || "Order"}`,
                html: `<h2>Order status updated</h2><p><b>Order ID:</b> ${updated.id}</p><p><b>Product:</b> ${escapeHtml(updated.product?.title || "-")}</p><p><b>New status:</b> ${escapeHtml(updated.status)}</p><p><b>Track your order status:</b><br/><a href="${escapeHtml(link)}">${escapeHtml(link)}</a></p><p>We will contact you if we need more information.</p>`
            });
        }
    }
    res.json({ item: updated });
});
router.post("/admin/products", requireAuth, requireAdmin, async (req, res) => {
    const body = z
        .object({
        title: z.string().min(2),
        category: z.string().min(1),
        description: z.string().optional().default(""),
        badge: z.string().optional().default(""),
        price: z.string().optional().default("Price on request"),
        personalPrice: z.string().optional().default(""),
        businessPrice: z.string().optional().default(""),
        seoTitle: z.string().optional().default(""),
        seoDescription: z.string().optional().default(""),
        seoSlug: z.string().optional().default(""),
        seoOgImage: z.string().optional().default(""),
        primaryKeyword: z.string().optional().default(""),
        secondaryKeywords: z.array(z.string()).optional().default([]),
        frontendRoute: z.string().optional().default("")
    })
        .parse(req.body);
    try {
        const created = await prisma.$transaction(async (db) => {
            // Generate unique frontendRoute
            const uniqueRoute = await generateUniqueFrontendRoute(db, body.frontendRoute || "", body.title);
            const item = await db.product.create({
                data: {
                    ...body,
                    images: [],
                    title: body.title || "",
                    description: body.description || "",
                    seoTitle: body.seoTitle || "",
                    seoDescription: body.seoDescription || "",
                    seoSlug: body.seoSlug || "",
                    seoOgImage: body.seoOgImage || "",
                    primaryKeyword: body.primaryKeyword || "",
                    frontendRoute: uniqueRoute,
                }
            });
            await syncSeoKeywordUsage({
                db,
                entityType: "PRODUCT",
                entityId: item.id,
                primaryKeyword: item.primaryKeyword,
                secondaryKeywords: jsonStringArray(item.secondaryKeywords),
            });
            return item;
        });
        res.json({ item: created });
    }
    catch (err) {
        res.status(400).json({ error: err?.message || "Failed" });
    }
});
router.post("/admin/products-multipart", requireAuth, requireAdmin, upload.array("images", 5), async (req, res) => {
    const body = z
        .object({
        title: z.string().min(2),
        category: z.string().min(1),
        description: z.string().optional().default(""),
        badge: z.string().optional().default(""),
        price: z.string().optional().default("Price on request"),
        personalPrice: z.string().optional().default(""),
        businessPrice: z.string().optional().default(""),
        seoTitle: z.string().optional().default(""),
        seoDescription: z.string().optional().default(""),
        seoSlug: z.string().optional().default(""),
        seoOgImage: z.string().optional().default(""),
        primaryKeyword: z.string().optional().default(""),
        secondaryKeywords: z
            .preprocess((val) => {
            if (Array.isArray(val))
                return val;
            if (typeof val === "string") {
                const s = val.trim();
                if (!s)
                    return [];
                try {
                    const parsed = JSON.parse(s);
                    if (Array.isArray(parsed))
                        return parsed;
                }
                catch {
                    // ignore
                }
                return s.split(",").map((x) => x.trim()).filter(Boolean);
            }
            return [];
        }, z.array(z.string()))
            .optional()
            .default([]),
        frontendRoute: z.string().optional().default("")
    })
        .parse(req.body);
    const files = (req.files || []);
    const images = files.map((f) => `/api/uploads/${f.filename}`);
    try {
        const created = await prisma.$transaction(async (db) => {
            // Generate unique frontendRoute
            const uniqueRoute = await generateUniqueFrontendRoute(db, body.frontendRoute || "", body.title);
            const item = await db.product.create({
                data: {
                    ...body,
                    images,
                    title: body.title || "",
                    description: body.description || "",
                    seoTitle: body.seoTitle || "",
                    seoDescription: body.seoDescription || "",
                    seoSlug: body.seoSlug || "",
                    seoOgImage: body.seoOgImage || "",
                    primaryKeyword: body.primaryKeyword || "",
                    frontendRoute: uniqueRoute,
                }
            });
            await syncSeoKeywordUsage({
                db,
                entityType: "PRODUCT",
                entityId: item.id,
                primaryKeyword: item.primaryKeyword,
                secondaryKeywords: jsonStringArray(item.secondaryKeywords),
            });
            return item;
        });
        res.json({ item: created });
    }
    catch (err) {
        res.status(400).json({ error: err?.message || "Failed" });
    }
});
// Admin: Get all products
router.get("/admin/products", requireAuth, requireAdmin, async (_req, res) => {
    const items = await prisma.product.findMany({
        orderBy: [{ sortOrder: "asc" }, { createdAt: "desc" }]
    });
    res.json({ items });
});
// Admin: Reorder products
router.post("/admin/products/reorder", requireAuth, requireAdmin, async (req, res) => {
    try {
        const body = z.object({
            ids: z.array(z.number().int())
        }).parse(req.body);
        await prisma.$transaction(body.ids.map((id, index) => prisma.product.update({
            where: { id },
            data: { sortOrder: index }
        })));
        res.json({ ok: true });
    }
    catch (err) {
        console.error("Product reorder error:", err);
        res.status(500).json({ error: err?.message || "Failed to reorder products" });
    }
});
// Admin: Update product (JSON)
router.put("/admin/products/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const existing = await prisma.product.findUnique({ where: { id } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    const body = z
        .object({
        title: z.string().min(2).optional(),
        category: z.string().min(1).optional(),
        description: z.string().optional(),
        badge: z.string().optional(),
        price: z.string().optional(),
        personalPrice: z.string().optional(),
        businessPrice: z.string().optional(),
        seoTitle: z.string().optional(),
        seoDescription: z.string().optional(),
        seoSlug: z.string().optional(),
        seoOgImage: z.string().optional(),
        primaryKeyword: z.string().optional(),
        secondaryKeywords: z.array(z.string()).optional(),
        images: z.array(z.string()).optional(),
        frontendRoute: z.string().optional()
    })
        .parse(req.body);
    try {
        const updated = await prisma.$transaction(async (db) => {
            // If frontendRoute is being updated, ensure it's unique
            if (body.frontendRoute !== undefined) {
                const currentProduct = await db.product.findUnique({ where: { id }, select: { title: true } });
                if (currentProduct) {
                    body.frontendRoute = await generateUniqueFrontendRoute(db, body.frontendRoute || "", currentProduct.title, id // Exclude current product from uniqueness check
                    );
                }
            }
            const item = await db.product.update({ where: { id }, data: body });
            await syncSeoKeywordUsage({
                db,
                entityType: "PRODUCT",
                entityId: item.id,
                primaryKeyword: item.primaryKeyword,
                secondaryKeywords: jsonStringArray(item.secondaryKeywords),
            });
            return item;
        });
        res.json({ item: updated });
    }
    catch (err) {
        res.status(400).json({ error: err?.message || "Failed" });
    }
});
// Admin: Update product (multipart with images)
router.put("/admin/products/:id/multipart", requireAuth, requireAdmin, upload.array("images", 5), async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const existing = await prisma.product.findUnique({ where: { id } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    const body = z
        .object({
        title: z.string().min(2).optional(),
        category: z.string().min(1).optional(),
        description: z.string().optional(),
        badge: z.string().optional(),
        price: z.string().optional(),
        personalPrice: z.string().optional(),
        businessPrice: z.string().optional(),
        seoTitle: z.string().optional(),
        seoDescription: z.string().optional(),
        seoSlug: z.string().optional(),
        seoOgImage: z.string().optional(),
        primaryKeyword: z.string().optional(),
        secondaryKeywords: z
            .preprocess((val) => {
            if (Array.isArray(val))
                return val;
            if (typeof val === "string") {
                const s = val.trim();
                if (!s)
                    return [];
                try {
                    const parsed = JSON.parse(s);
                    if (Array.isArray(parsed))
                        return parsed;
                }
                catch {
                    // ignore
                }
                return s.split(",").map((x) => x.trim()).filter(Boolean);
            }
            return [];
        }, z.array(z.string()))
            .optional(),
        frontendRoute: z.string().optional(),
    })
        .parse(req.body);
    const files = (req.files || []);
    const images = files.map((f) => `/api/uploads/${f.filename}`);
    try {
        const updated = await prisma.$transaction(async (db) => {
            // If frontendRoute is being updated, ensure it's unique
            if (body.frontendRoute !== undefined) {
                const currentProduct = await db.product.findUnique({ where: { id }, select: { title: true } });
                if (currentProduct) {
                    body.frontendRoute = await generateUniqueFrontendRoute(db, body.frontendRoute || "", currentProduct.title, id // Exclude current product from uniqueness check
                    );
                }
            }
            const updateData = { ...body };
            if (images.length > 0) {
                updateData.images = images;
            }
            const item = await db.product.update({ where: { id }, data: updateData });
            await syncSeoKeywordUsage({
                db,
                entityType: "PRODUCT",
                entityId: item.id,
                primaryKeyword: item.primaryKeyword,
                secondaryKeywords: jsonStringArray(item.secondaryKeywords),
            });
            return item;
        });
        res.json({ item: updated });
    }
    catch (err) {
        res.status(400).json({ error: err?.message || "Failed" });
    }
});
// Admin: Delete product
router.delete("/admin/products/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const existing = await prisma.product.findUnique({ where: { id } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    await prisma.$transaction(async (db) => {
        // Delete all related records first (in correct order to respect foreign keys)
        await db.seoKeywordUsage.deleteMany({ where: { entityType: "PRODUCT", entityId: id } });
        await db.productView.deleteMany({ where: { productId: id } });
        await db.pageView.deleteMany({ where: { productId: id } });
        // Delete order items first (they reference both order and product)
        await db.orderItem.deleteMany({ where: { productId: id } });
        // Delete orders that reference this product
        await db.order.deleteMany({ where: { productId: id } });
        // Now delete the product
        await db.product.delete({ where: { id } });
    });
    res.json({ ok: true });
});
// ===================== BRANDS =====================
// Public: Get header brands (Brands we sell)
router.get("/brands/header", async (_req, res) => {
    try {
        const items = await prisma.brand.findMany({
            where: { type: "HEADER" },
            orderBy: { sortOrder: "asc" }
        });
        res.json({ items });
    }
    catch (err) {
        console.error("[/brands/header] error:", err);
        res.status(500).json({ error: err?.message || "Failed to load brands" });
    }
});
// Public: Get trusted brands (Trusted by teams)
router.get("/brands/trusted", async (_req, res) => {
    try {
        const items = await prisma.brand.findMany({
            where: { type: "TRUSTED" },
            orderBy: { sortOrder: "asc" }
        });
        res.json({ items });
    }
    catch (err) {
        console.error("[/brands/trusted] error:", err);
        res.status(500).json({ error: err?.message || "Failed to load brands" });
    }
});
// Public: Get all brands (backwards compatible)
router.get("/brands", async (_req, res) => {
    const items = await prisma.brand.findMany({ orderBy: { sortOrder: "asc" } });
    res.json({ items });
});
// Admin: Create brand with logo upload
router.post("/admin/brands", requireAuth, requireAdmin, uploadSingle.single("logo"), async (req, res) => {
    const body = z.object({
        name: z.string().min(1),
        sortOrder: z.coerce.number().int().optional().default(0),
        type: z.enum(["HEADER", "TRUSTED"]).optional().default("HEADER")
    }).parse(req.body);
    const file = req.file;
    const logo = file ? `/api/uploads/${file.filename}` : "";
    const created = await prisma.brand.create({ data: { ...body, logo } });
    res.json({ item: created });
});
// Admin: Update brand
router.put("/admin/brands/:id", requireAuth, requireAdmin, uploadSingle.single("logo"), async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const existing = await prisma.brand.findUnique({ where: { id } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    const body = z.object({
        name: z.string().min(1).optional(),
        sortOrder: z.coerce.number().int().optional(),
        type: z.enum(["HEADER", "TRUSTED"]).optional()
    }).parse(req.body);
    const file = req.file;
    const logo = file ? `/api/uploads/${file.filename}` : undefined;
    const updated = await prisma.brand.update({
        where: { id },
        data: {
            ...(body.name !== undefined && { name: body.name }),
            ...(body.sortOrder !== undefined && { sortOrder: body.sortOrder }),
            ...(body.type !== undefined && { type: body.type }),
            ...(logo !== undefined && { logo })
        }
    });
    res.json({ item: updated });
});
// Admin: Delete brand
router.delete("/admin/brands/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const existing = await prisma.brand.findUnique({ where: { id } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    await prisma.brand.delete({ where: { id } });
    res.json({ ok: true });
});
// ===================== CATEGORIES =====================
// Public: Get all categories
router.get("/categories", async (_req, res) => {
    try {
        const items = await prisma.category.findMany({ orderBy: { sortOrder: "asc" } });
        res.json({ items });
    }
    catch (err) {
        console.error("[/categories] error:", err);
        res.status(500).json({ error: err?.message || "Failed to load categories" });
    }
});
// Admin: Create category
router.post("/admin/categories", requireAuth, requireAdmin, async (req, res) => {
    const body = z.object({
        name: z.string().min(1),
        sortOrder: z.coerce.number().int().optional().default(0),
        seoTitle: z.string().optional().default(""),
        seoDescription: z.string().optional().default(""),
        seoSlug: z.string().optional().default(""),
        seoOgImage: z.string().optional().default(""),
        primaryKeyword: z.string().optional().default(""),
        secondaryKeywords: z.array(z.string()).optional().default([])
    }).parse(req.body);
    const existing = await prisma.category.findUnique({ where: { name: body.name } });
    if (existing)
        return res.status(400).json({ error: "Category already exists" });
    try {
        const created = await prisma.$transaction(async (db) => {
            const item = await db.category.create({
                data: {
                    ...body,
                    seoTitle: body.seoTitle || "",
                    seoDescription: body.seoDescription || "",
                    seoSlug: body.seoSlug || "",
                    seoOgImage: body.seoOgImage || "",
                    primaryKeyword: body.primaryKeyword || "",
                }
            });
            await syncSeoKeywordUsage({
                db,
                entityType: "CATEGORY",
                entityId: item.id,
                primaryKeyword: item.primaryKeyword,
                secondaryKeywords: jsonStringArray(item.secondaryKeywords),
            });
            return item;
        });
        res.json({ item: created });
    }
    catch (err) {
        res.status(400).json({ error: err?.message || "Failed" });
    }
});
// Admin: Get all categories
router.get("/admin/categories", requireAuth, requireAdmin, async (_req, res) => {
    const items = await prisma.category.findMany({ orderBy: [{ sortOrder: "asc" }, { id: "asc" }] });
    res.json({ items });
});
// Admin: Update category
router.put("/admin/categories/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const existing = await prisma.category.findUnique({ where: { id } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    const body = z.object({
        name: z.string().min(1).optional(),
        sortOrder: z.coerce.number().int().optional(),
        seoTitle: z.string().optional(),
        seoDescription: z.string().optional(),
        seoSlug: z.string().optional(),
        seoOgImage: z.string().optional(),
        primaryKeyword: z.string().optional(),
        secondaryKeywords: z.array(z.string()).optional()
    }).parse(req.body);
    try {
        const updated = await prisma.$transaction(async (db) => {
            const item = await db.category.update({
                where: { id },
                data: {
                    ...(body.name !== undefined && { name: body.name }),
                    ...(body.sortOrder !== undefined && { sortOrder: body.sortOrder }),
                    ...(body.seoTitle !== undefined && { seoTitle: body.seoTitle }),
                    ...(body.seoDescription !== undefined && { seoDescription: body.seoDescription }),
                    ...(body.seoSlug !== undefined && { seoSlug: body.seoSlug }),
                    ...(body.seoOgImage !== undefined && { seoOgImage: body.seoOgImage }),
                    ...(body.primaryKeyword !== undefined && { primaryKeyword: body.primaryKeyword }),
                    ...(body.secondaryKeywords !== undefined && { secondaryKeywords: body.secondaryKeywords }),
                }
            });
            await syncSeoKeywordUsage({
                db,
                entityType: "CATEGORY",
                entityId: item.id,
                primaryKeyword: item.primaryKeyword,
                secondaryKeywords: jsonStringArray(item.secondaryKeywords),
            });
            return item;
        });
        res.json({ item: updated });
    }
    catch (err) {
        res.status(400).json({ error: err?.message || "Failed" });
    }
});
// Admin: Delete category
router.delete("/admin/categories/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const existing = await prisma.category.findUnique({ where: { id } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    await prisma.$transaction(async (db) => {
        await db.seoKeywordUsage.deleteMany({ where: { entityType: "CATEGORY", entityId: id } });
        await db.category.delete({ where: { id } });
    });
    res.json({ ok: true });
});
router.get("/admin/seo/keywords/autocomplete", requireAuth, requireAdmin, async (req, res) => {
    const q = typeof req.query?.q === "string" ? req.query.q : "";
    const query = normalizeSeoKeyword(q);
    if (!query)
        return res.json({ items: [] });
    const items = await prisma.seoKeyword.findMany({
        where: { normalized: { contains: query } },
        orderBy: { updatedAt: "desc" },
        take: 10,
    });
    res.json({ items });
});
router.get("/admin/seo/keywords/duplicate-check", requireAuth, requireAdmin, async (req, res) => {
    const entityType = typeof req.query?.entityType === "string" ? req.query.entityType : "";
    const keyword = typeof req.query?.keyword === "string" ? req.query.keyword : "";
    const excludeEntityIdRaw = typeof req.query?.excludeEntityId === "string" ? req.query.excludeEntityId : undefined;
    const excludeEntityId = excludeEntityIdRaw ? Number(excludeEntityIdRaw) : undefined;
    if (entityType !== "PRODUCT" && entityType !== "CATEGORY" && entityType !== "FAQ") {
        return res.status(400).json({ error: "Invalid entityType" });
    }
    const normalized = normalizeSeoKeyword(keyword);
    if (!normalized)
        return res.json({ ok: true, conflict: null });
    const conflict = await checkSeoKeywordConflict({
        db: prisma,
        entityType,
        keywordNormalized: normalized,
        excludeEntityId: Number.isFinite(excludeEntityId) ? excludeEntityId : undefined,
    });
    if (!conflict)
        return res.json({ ok: true, conflict: null });
    res.json({
        ok: false,
        conflict: {
            entityType: conflict.entityType,
            entityId: conflict.entityId,
            keyword: conflict.keyword?.keyword || normalized,
        },
    });
});
// ===================== PRICING PLANS =====================
// Public: Get all pricing plans
router.get("/pricing", async (_req, res) => {
    try {
        const items = await prisma.pricingPlan.findMany({ orderBy: { sortOrder: "asc" } });
        res.json({ items });
    }
    catch (err) {
        console.error("[/pricing] error:", err);
        res.status(500).json({ error: err?.message || "Failed to load pricing plans" });
    }
});
// ===================== FAQS =====================
router.get("/faqs", async (_req, res) => {
    try {
        const itemsNew = await prisma.fAQItem
            .findMany({ where: { active: true }, orderBy: { sortOrder: "asc" } })
            .catch(() => []);
        const itemsOld = await prisma.chatFAQ
            .findMany({ where: { active: true }, orderBy: { sortOrder: "asc" } })
            .catch(() => []);
        const mergedRaw = [
            ...itemsNew.map((x) => ({ ...x, source: "new" })),
            ...itemsOld.map((x) => ({ ...x, source: "old" })),
        ].sort((a, b) => (Number(a.sortOrder || 0) - Number(b.sortOrder || 0)) ||
            (String(a.source).localeCompare(String(b.source))) ||
            (Number(a.id || 0) - Number(b.id || 0)));
        const byQuestion = new Map();
        for (const item of mergedRaw) {
            const key = String(item?.question ?? "")
                .trim()
                .toLowerCase()
                .replace(/\s+/g, " ");
            if (!key)
                continue;
            const existing = byQuestion.get(key);
            if (!existing) {
                byQuestion.set(key, item);
                continue;
            }
            if (existing.source !== "new" && item.source === "new") {
                byQuestion.set(key, item);
            }
        }
        const merged = Array.from(byQuestion.values()).sort((a, b) => (Number(a.sortOrder || 0) - Number(b.sortOrder || 0)) ||
            (String(a.source).localeCompare(String(b.source))) ||
            (Number(a.id || 0) - Number(b.id || 0)));
        return res.json({ items: merged });
    }
    catch (err) {
        console.error("[/faqs] error:", err);
        res.status(500).json({ error: err?.message || "Failed to load faqs" });
    }
});
// Admin: Create pricing plan
router.post("/admin/pricing", requireAuth, requireAdmin, async (req, res) => {
    const body = z.object({
        name: z.string().min(1),
        tagline: z.string().optional().default(""),
        lifetimePrice: z.string().optional().default(""),
        annualPrice: z.string().optional().default(""),
        popular: z.boolean().optional().default(false),
        features: z.array(z.string()).optional().default([]),
        sortOrder: z.coerce.number().int().optional().default(0)
    }).parse(req.body);
    const created = await prisma.pricingPlan.create({ data: body });
    res.json({ item: created });
});
// Admin: Update pricing plan
router.put("/admin/pricing/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const existing = await prisma.pricingPlan.findUnique({ where: { id } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    const body = z.object({
        name: z.string().min(1).optional(),
        tagline: z.string().optional(),
        lifetimePrice: z.string().optional(),
        annualPrice: z.string().optional(),
        popular: z.boolean().optional(),
        features: z.array(z.string()).optional(),
        sortOrder: z.coerce.number().int().optional()
    }).parse(req.body);
    const updated = await prisma.pricingPlan.update({
        where: { id },
        data: body
    });
    res.json({ item: updated });
});
// Admin: Delete pricing plan
router.delete("/admin/pricing/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const existing = await prisma.pricingPlan.findUnique({ where: { id } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    await prisma.pricingPlan.delete({ where: { id } });
    res.json({ ok: true });
});
// ===================== NAV ITEMS =====================
// Public: Get all nav items
router.get("/nav", async (_req, res) => {
    const items = await prisma.navItem.findMany({
        where: { visible: true },
        orderBy: { sortOrder: "asc" }
    });
    res.json({ items });
});
// Admin: Get all nav items (including hidden)
router.get("/admin/nav", requireAuth, requireAdmin, async (_req, res) => {
    const items = await prisma.navItem.findMany({ orderBy: { sortOrder: "asc" } });
    res.json({ items });
});
// Admin: Create nav item
router.post("/admin/nav", requireAuth, requireAdmin, async (req, res) => {
    const body = z.object({
        label: z.string().min(1),
        page: z.string().min(1),
        sortOrder: z.coerce.number().int().optional().default(0),
        visible: z.boolean().optional().default(true)
    }).parse(req.body);
    const created = await prisma.navItem.create({ data: body });
    res.json({ item: created });
});
// Admin: Update nav item
router.put("/admin/nav/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const existing = await prisma.navItem.findUnique({ where: { id } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    const body = z.object({
        label: z.string().min(1).optional(),
        page: z.string().min(1).optional(),
        sortOrder: z.coerce.number().int().optional(),
        visible: z.boolean().optional()
    }).parse(req.body);
    const updated = await prisma.navItem.update({ where: { id }, data: body });
    res.json({ item: updated });
});
// Admin: Delete nav item
router.delete("/admin/nav/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    await prisma.navItem.delete({ where: { id } });
    res.json({ ok: true });
});
// ===================== SITE SETTINGS =====================
// Public: Get site settings
router.get("/settings", async (_req, res) => {
    try {
        let settings = await prisma.siteSettings.findUnique({ where: { id: 1 } });
        if (!settings) {
            settings = await prisma.siteSettings.create({ data: { id: 1 } });
        }
        res.json({ settings });
    }
    catch (err) {
        console.error("[/settings] error:", err);
        res.status(500).json({ error: err?.message || "Failed to load settings" });
    }
});
// Admin: Update site settings with logo upload
router.put("/admin/settings", requireAuth, requireAdmin, upload.fields([
    { name: "headerLogo", maxCount: 1 },
    { name: "footerLogo", maxCount: 1 },
    { name: "supportImage", maxCount: 1 }
]), async (req, res) => {
    try {
        // Allow empty siteName - check if it's explicitly provided in the request
        const siteNameProvided = req.body?.siteName !== undefined;
        const siteName = siteNameProvided ? String(req.body.siteName || "").trim() : undefined;
        const heroKickerProvided = req.body?.heroKicker !== undefined;
        const heroTitleProvided = req.body?.heroTitle !== undefined;
        const heroTitleAccentProvided = req.body?.heroTitleAccent !== undefined;
        const heroSubtitleProvided = req.body?.heroSubtitle !== undefined;
        const heroCtaBrowseProvided = req.body?.heroCtaBrowse !== undefined;
        const heroCtaPricingProvided = req.body?.heroCtaPricing !== undefined;
        const heroFeature1Provided = req.body?.heroFeature1 !== undefined;
        const heroFeature2Provided = req.body?.heroFeature2 !== undefined;
        const heroFeature3Provided = req.body?.heroFeature3 !== undefined;
        const heroKicker = heroKickerProvided ? String(req.body.heroKicker || "").trim() : undefined;
        const heroTitle = heroTitleProvided ? String(req.body.heroTitle || "").trim() : undefined;
        const heroTitleAccent = heroTitleAccentProvided ? String(req.body.heroTitleAccent || "").trim() : undefined;
        const heroSubtitle = heroSubtitleProvided ? String(req.body.heroSubtitle || "").trim() : undefined;
        const heroCtaBrowse = heroCtaBrowseProvided ? String(req.body.heroCtaBrowse || "").trim() : undefined;
        const heroCtaPricing = heroCtaPricingProvided ? String(req.body.heroCtaPricing || "").trim() : undefined;
        const heroFeature1 = heroFeature1Provided ? String(req.body.heroFeature1 || "").trim() : undefined;
        const heroFeature2 = heroFeature2Provided ? String(req.body.heroFeature2 || "").trim() : undefined;
        const heroFeature3 = heroFeature3Provided ? String(req.body.heroFeature3 || "").trim() : undefined;
        const files = req.files;
        const headerLogoFile = files?.headerLogo?.[0];
        const footerLogoFile = files?.footerLogo?.[0];
        const supportImageFile = files?.supportImage?.[0];
        let settings = await prisma.siteSettings.findUnique({ where: { id: 1 } });
        if (!settings) {
            settings = await prisma.siteSettings.create({ data: { id: 1 } });
        }
        const updateData = {};
        // Update siteName if it was provided (even if empty)
        if (siteNameProvided) {
            updateData.siteName = siteName || "";
        }
        if (heroKickerProvided)
            updateData.heroKicker = heroKicker || "";
        if (heroTitleProvided)
            updateData.heroTitle = heroTitle || "";
        if (heroTitleAccentProvided)
            updateData.heroTitleAccent = heroTitleAccent || "";
        if (heroSubtitleProvided)
            updateData.heroSubtitle = heroSubtitle || "";
        if (heroCtaBrowseProvided)
            updateData.heroCtaBrowse = heroCtaBrowse || "";
        if (heroCtaPricingProvided)
            updateData.heroCtaPricing = heroCtaPricing || "";
        if (heroFeature1Provided)
            updateData.heroFeature1 = heroFeature1 || "";
        if (heroFeature2Provided)
            updateData.heroFeature2 = heroFeature2 || "";
        if (heroFeature3Provided)
            updateData.heroFeature3 = heroFeature3 || "";
        if (headerLogoFile)
            updateData.headerLogo = `/api/uploads/${headerLogoFile.filename}`;
        if (footerLogoFile)
            updateData.footerLogo = `/api/uploads/${footerLogoFile.filename}`;
        if (supportImageFile) {
            const allowed = ["image/svg+xml", "image/png", "image/jpeg", "image/webp"];
            if (!allowed.includes(String(supportImageFile.mimetype || "").toLowerCase())) {
                return res.status(400).json({ error: "Only SVG, PNG, JPG/JPEG, WEBP images are allowed." });
            }
            updateData.supportImage = `/api/uploads/${supportImageFile.filename}`;
        }
        const updated = await prisma.siteSettings.update({
            where: { id: 1 },
            data: updateData
        });
        res.json({ settings: updated });
    }
    catch (err) {
        console.error("Settings update error:", err);
        res.status(500).json({ error: err?.message || "Failed to update settings" });
    }
});
// ===================== HOME FEATURED PRODUCTS =====================
// Public: get featured products list for homepage
router.get("/featured-products", async (_req, res) => {
    try {
        const items = await prisma.homeFeaturedProduct.findMany({
            where: { active: true },
            orderBy: [{ sortOrder: "asc" }, { id: "asc" }],
            include: { product: true },
        });
        res.json({ items });
    }
    catch (err) {
        console.error("[/featured-products] error:", err);
        res.status(500).json({ error: err?.message || "Failed to load featured products" });
    }
});
// Admin: get all featured products (including inactive)
router.get("/admin/featured-products", requireAuth, requireAdmin, async (_req, res) => {
    const items = await prisma.homeFeaturedProduct.findMany({
        orderBy: [{ sortOrder: "asc" }, { id: "asc" }],
        include: { product: true },
    });
    res.json({ items });
});
// Admin: add featured product
router.post("/admin/featured-products", requireAuth, requireAdmin, async (req, res) => {
    const body = z
        .object({
        productId: z.coerce.number().int().positive(),
        sortOrder: z.coerce.number().int().optional().default(0),
        active: z.boolean().optional().default(true),
    })
        .parse(req.body);
    const product = await prisma.product.findUnique({ where: { id: body.productId } });
    if (!product)
        return res.status(400).json({ error: "Invalid product" });
    try {
        const created = await prisma.homeFeaturedProduct.create({
            data: { productId: body.productId, sortOrder: body.sortOrder, active: body.active },
            include: { product: true },
        });
        res.json({ item: created });
    }
    catch (err) {
        res.status(400).json({ error: err?.message || "Failed" });
    }
});
// Admin: update featured product
router.put("/admin/featured-products/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const existing = await prisma.homeFeaturedProduct.findUnique({ where: { id } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    const body = z
        .object({
        productId: z.coerce.number().int().positive().optional(),
        sortOrder: z.coerce.number().int().optional(),
        active: z.boolean().optional(),
    })
        .parse(req.body);
    if (body.productId !== undefined) {
        const product = await prisma.product.findUnique({ where: { id: body.productId } });
        if (!product)
            return res.status(400).json({ error: "Invalid product" });
    }
    const updated = await prisma.homeFeaturedProduct.update({
        where: { id },
        data: body,
        include: { product: true },
    });
    res.json({ item: updated });
});
// Admin: delete featured product
router.delete("/admin/featured-products/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    await prisma.homeFeaturedProduct.delete({ where: { id } });
    res.json({ ok: true });
});
// ===================== COUPONS =====================
// Public: Validate coupon (productIds = cart product IDs; coupon must apply to at least one when not appliesToAll)
router.post("/coupons/validate", async (req, res) => {
    const body = z.object({
        code: z.string().min(1),
        productIds: z.array(z.coerce.number().int().positive()).optional(),
        productId: z.coerce.number().int().positive().optional(), // legacy single product
    }).parse(req.body);
    const cartProductIds = body.productIds ?? (body.productId != null ? [body.productId] : []);
    const coupon = await prisma.coupon.findUnique({ where: { code: body.code.toUpperCase() } });
    if (!coupon)
        return res.status(404).json({ error: "Invalid coupon code" });
    if (!coupon.active)
        return res.status(400).json({ error: "Coupon is not active" });
    if (coupon.maxUses > 0 && coupon.usedCount >= coupon.maxUses)
        return res.status(400).json({ error: "Coupon usage limit reached" });
    if (coupon.validUntil && new Date() > coupon.validUntil)
        return res.status(400).json({ error: "Coupon has expired" });
    if (new Date() < coupon.validFrom)
        return res.status(400).json({ error: "Coupon is not yet valid" });
    const allowedIds = jsonNumberArray(coupon.applicableProductIds);
    if (!coupon.appliesToAll) {
        if (cartProductIds.length === 0)
            return res.status(400).json({ error: "Coupon applies to specific products; add items to cart first" });
        const hasEligible = cartProductIds.some((pid) => allowedIds.includes(pid));
        if (!hasEligible)
            return res.status(400).json({ error: "Coupon not valid for any product in your cart" });
    }
    res.json({
        valid: true,
        coupon: {
            code: coupon.code,
            description: coupon.description,
            discountType: coupon.discountType,
            discountValue: coupon.discountValue,
            minPurchase: coupon.minPurchase,
            appliesToAll: coupon.appliesToAll,
            applicableProductIds: allowedIds,
        },
    });
});
// Public: Get active coupons (for coupon page)
router.get("/coupons/active", async (_req, res) => {
    const now = new Date();
    const coupons = await prisma.coupon.findMany({
        where: {
            active: true,
            validFrom: { lte: now },
            OR: [
                { validUntil: null },
                { validUntil: { gte: now } }
            ]
        },
        select: {
            code: true,
            description: true,
            discountType: true,
            discountValue: true,
            minPurchase: true,
            validUntil: true,
            appliesToAll: true,
            applicableProductIds: true,
        },
        orderBy: { discountValue: "desc" }
    });
    res.json({ items: coupons });
});
// Admin: Get all coupons
router.get("/admin/coupons", requireAuth, requireAdmin, async (_req, res) => {
    const coupons = await prisma.coupon.findMany({ orderBy: { createdAt: "desc" } });
    res.json({ items: coupons });
});
// Admin: Create coupon
router.post("/admin/coupons", requireAuth, requireAdmin, async (req, res) => {
    const body = z.object({
        code: z.string().min(3).transform((s) => s.toUpperCase()),
        description: z.string().optional().default(""),
        discountType: z.enum(["PERCENTAGE", "FIXED"]).optional().default("PERCENTAGE"),
        discountValue: z.coerce.number().min(0),
        minPurchase: z.coerce.number().min(0).optional().default(0),
        appliesToAll: z.boolean().optional().default(true),
        applicableProductIds: z.array(z.coerce.number().int().positive()).optional().default([]),
        maxUses: z.coerce.number().int().min(0).optional().default(0),
        validFrom: z.string().optional(),
        validUntil: z.string().optional(),
        active: z.boolean().optional().default(true)
    }).parse(req.body);
    const existing = await prisma.coupon.findUnique({ where: { code: body.code } });
    if (existing)
        return res.status(400).json({ error: "Coupon code already exists" });
    const created = await prisma.coupon.create({
        data: {
            ...body,
            applicableProductIds: body.appliesToAll ? [] : body.applicableProductIds,
            validFrom: body.validFrom ? new Date(body.validFrom) : new Date(),
            validUntil: body.validUntil ? new Date(body.validUntil) : null
        }
    });
    res.json({ item: created });
});
// Admin: Update coupon
router.put("/admin/coupons/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    const existing = await prisma.coupon.findUnique({ where: { id } });
    if (!existing)
        return res.status(404).json({ error: "Not found" });
    const body = z.object({
        code: z.string().min(3).transform((s) => s.toUpperCase()).optional(),
        description: z.string().optional(),
        discountType: z.enum(["PERCENTAGE", "FIXED"]).optional(),
        discountValue: z.coerce.number().min(0).optional(),
        minPurchase: z.coerce.number().min(0).optional(),
        appliesToAll: z.boolean().optional(),
        applicableProductIds: z.array(z.coerce.number().int().positive()).optional(),
        maxUses: z.coerce.number().int().min(0).optional(),
        validFrom: z.string().optional(),
        validUntil: z.string().nullable().optional(),
        active: z.boolean().optional()
    }).parse(req.body);
    const updated = await prisma.coupon.update({
        where: { id },
        data: {
            ...body,
            ...(body.appliesToAll !== undefined && { applicableProductIds: body.appliesToAll ? [] : body.applicableProductIds || [] }),
            ...(body.validFrom && { validFrom: new Date(body.validFrom) }),
            ...(body.validUntil !== undefined && { validUntil: body.validUntil ? new Date(body.validUntil) : null })
        }
    });
    res.json({ item: updated });
});
// Admin: Delete coupon
router.delete("/admin/coupons/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    await prisma.coupon.delete({ where: { id } });
    res.json({ ok: true });
});
// ===================== TESTIMONIALS =====================
// Public: Get active testimonials
router.get("/testimonials", async (_req, res) => {
    try {
        const items = await prisma.testimonial.findMany({
            where: { active: true },
            orderBy: { sortOrder: "asc" }
        });
        res.json({ items });
    }
    catch (err) {
        console.error("[/testimonials] error:", err);
        res.status(500).json({ error: err?.message || "Failed to load testimonials" });
    }
});
// Admin: Get all testimonials
router.get("/admin/testimonials", requireAuth, requireAdmin, async (_req, res) => {
    const items = await prisma.testimonial.findMany({ orderBy: { sortOrder: "asc" } });
    res.json({ items });
});
// Admin: Create testimonial with photo/logo upload
router.post("/admin/testimonials", requireAuth, requireAdmin, upload.fields([
    { name: "photo", maxCount: 1 },
    { name: "companyLogo", maxCount: 1 }
]), async (req, res) => {
    try {
        const name = req.body?.name?.trim();
        const role = req.body?.role?.trim() || "";
        const company = req.body?.company?.trim() || "";
        const text = req.body?.text?.trim();
        const sortOrder = Number(req.body?.sortOrder) || 0;
        if (!name || !text) {
            return res.status(400).json({ error: "Name and text are required" });
        }
        const files = req.files;
        const photoFile = files?.photo?.[0];
        const logoFile = files?.companyLogo?.[0];
        const created = await prisma.testimonial.create({
            data: {
                name,
                role,
                company,
                text,
                sortOrder,
                photo: photoFile ? `/api/uploads/${photoFile.filename}` : "",
                companyLogo: logoFile ? `/api/uploads/${logoFile.filename}` : ""
            }
        });
        res.json({ item: created });
    }
    catch (err) {
        console.error("Testimonial create error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Admin: Update testimonial
router.put("/admin/testimonials/:id", requireAuth, requireAdmin, upload.fields([
    { name: "photo", maxCount: 1 },
    { name: "companyLogo", maxCount: 1 }
]), async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!Number.isFinite(id))
            return res.status(400).json({ error: "Invalid id" });
        const existing = await prisma.testimonial.findUnique({ where: { id } });
        if (!existing)
            return res.status(404).json({ error: "Not found" });
        const files = req.files;
        const photoFile = files?.photo?.[0];
        const logoFile = files?.companyLogo?.[0];
        const updateData = {};
        if (req.body?.name?.trim())
            updateData.name = req.body.name.trim();
        if (req.body?.role !== undefined)
            updateData.role = req.body.role.trim();
        if (req.body?.company !== undefined)
            updateData.company = req.body.company.trim();
        if (req.body?.text?.trim())
            updateData.text = req.body.text.trim();
        if (req.body?.sortOrder !== undefined)
            updateData.sortOrder = Number(req.body.sortOrder);
        if (req.body?.active !== undefined)
            updateData.active = req.body.active === "true";
        if (photoFile)
            updateData.photo = `/api/uploads/${photoFile.filename}`;
        if (logoFile)
            updateData.companyLogo = `/api/uploads/${logoFile.filename}`;
        const updated = await prisma.testimonial.update({ where: { id }, data: updateData });
        res.json({ item: updated });
    }
    catch (err) {
        console.error("Testimonial update error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Admin: Delete testimonial
router.delete("/admin/testimonials/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id))
        return res.status(400).json({ error: "Invalid id" });
    await prisma.testimonial.delete({ where: { id } });
    res.json({ ok: true });
});
// ========== CHAT FAQ (Admin) ==========
// Get all FAQs
router.get("/admin/chat/faqs", requireAuth, requireAdmin, async (req, res) => {
    try {
        const itemsNew = await prisma.fAQItem
            .findMany({ orderBy: { sortOrder: "asc" } })
            .catch(() => []);
        const itemsOld = await prisma.chatFAQ
            .findMany({ orderBy: { sortOrder: "asc" } })
            .catch(() => []);
        const merged = [
            ...itemsNew.map((x) => ({ ...x, source: "new" })),
            ...itemsOld.map((x) => ({ ...x, source: "old" })),
        ].sort((a, b) => (Number(a.sortOrder || 0) - Number(b.sortOrder || 0)) ||
            (String(a.source).localeCompare(String(b.source))) ||
            (Number(a.id || 0) - Number(b.id || 0)));
        return res.json({ items: merged });
    }
    catch (err) {
        console.error("FAQ list error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Create FAQ
router.post("/admin/chat/faqs", requireAuth, requireAdmin, async (req, res) => {
    try {
        const body = z
            .object({
            question: z.string().min(1).max(500),
            answer: z.string().min(1).max(5000),
            keywords: z.array(z.string()).optional().default([]),
            seoTitle: z.string().optional().default(""),
            seoDescription: z.string().optional().default(""),
            seoSlug: z.string().optional().default(""),
            seoOgImage: z.string().optional().default(""),
            primaryKeyword: z.string().optional().default(""),
            secondaryKeywords: z.array(z.string()).optional().default([]),
            sortOrder: z.coerce.number().int().default(0),
            active: z.boolean().optional().default(true),
        })
            .parse(req.body);
        const item = await prisma.$transaction(async (db) => {
            const created = await db.fAQItem.create({ data: body });
            await syncSeoKeywordUsage({
                db,
                entityType: "FAQ",
                entityId: created.id,
                primaryKeyword: created.primaryKeyword,
                secondaryKeywords: jsonStringArray(created.secondaryKeywords),
            });
            return created;
        });
        res.json({ item });
    }
    catch (err) {
        console.error("FAQ create error:", err);
        res.status(400).json({ error: err?.message || "Failed" });
    }
});
router.post("/admin/chat/faqs/import-defaults", requireAuth, requireAdmin, async (_req, res) => {
    try {
        const defaults = [
            {
                question: "What is RipCrack?",
                answer: "RipCrack is a software development and IT consulting team providing custom development, reverse engineering, authorized cracking services, software analysis, and security research. We have been actively delivering services since 2019.",
                keywords: ["ripcrack", "services"],
                sortOrder: 1,
                active: true,
                seoTitle: "",
                seoDescription: "",
                seoSlug: "",
                seoOgImage: "",
                primaryKeyword: "",
            },
            {
                question: "Is RipCrack a legal company?",
                answer: "Yes. All services are performed legally, ethically, and with client authorization. Reverse engineering and cracking-related services are used for license recovery, legacy software access, security testing, software protection analysis, and compatibility purposes.",
                keywords: ["legal", "authorization"],
                sortOrder: 2,
                active: true,
                seoTitle: "",
                seoDescription: "",
                seoSlug: "",
                seoOgImage: "",
                primaryKeyword: "",
            },
            {
                question: "What do you mean by \"crack services\"?",
                answer: "Authorized software cracking and license bypass solutions performed only with the permission of the software owner or rights holder. Examples: license recovery, DRM/protection analysis, internal security testing, legacy software unlocking, and crack prevention. We do not support piracy or illegal distribution.",
                keywords: ["crack", "authorization", "drm"],
                sortOrder: 3,
                active: true,
                seoTitle: "",
                seoDescription: "",
                seoSlug: "",
                seoOgImage: "",
                primaryKeyword: "",
            },
            {
                question: "Do you offer reverse engineering services?",
                answer: "Yes. We specialize in reverse engineering and binary analysis for desktop, web, and embedded software. We help clients understand behavior, improve security, migrate legacy systems, and protect IP.",
                keywords: ["reverse engineering", "binary analysis"],
                sortOrder: 4,
                active: true,
                seoTitle: "",
                seoDescription: "",
                seoSlug: "",
                seoOgImage: "",
                primaryKeyword: "",
            },
            {
                question: "Since when has RipCrack been operating?",
                answer: "We have been delivering services since 2019.",
                keywords: ["since", "2019"],
                sortOrder: 5,
                active: true,
                seoTitle: "",
                seoDescription: "",
                seoSlug: "",
                seoOgImage: "",
                primaryKeyword: "",
            },
            {
                question: "What industries do you work with?",
                answer: "We work with a wide range of industries including financial services, energy, retail & e-commerce, entertainment & media, telecommunications, technology & startups, printing & print management, dental software, embroidery & textile automation, and CNC machine software/control systems.",
                keywords: ["industries"],
                sortOrder: 6,
                active: true,
                seoTitle: "",
                seoDescription: "",
                seoSlug: "",
                seoOgImage: "",
                primaryKeyword: "",
            },
            {
                question: "How large is your team?",
                answer: "We work with a distributed team of 30+ highly skilled engineers located in multiple countries worldwide.",
                keywords: ["team"],
                sortOrder: 7,
                active: true,
                seoTitle: "",
                seoDescription: "",
                seoSlug: "",
                seoOgImage: "",
                primaryKeyword: "",
            },
            {
                question: "Do you offer nearshore and offshore development?",
                answer: "Yes. We provide nearshore and offshore software development, reverse engineering, and crack services to help clients reduce costs while maintaining high quality and security standards.",
                keywords: ["nearshore", "offshore"],
                sortOrder: 8,
                active: true,
                seoTitle: "",
                seoDescription: "",
                seoSlug: "",
                seoOgImage: "",
                primaryKeyword: "",
            },
            {
                question: "What is your typical engagement process?",
                answer: "We usually start with a short discovery call, define scope and deliverables, then execute with weekly updates. For sensitive reverse engineering/cracking requests, we may require proof of authorization.",
                keywords: ["process", "discovery"],
                sortOrder: 9,
                active: true,
                seoTitle: "",
                seoDescription: "",
                seoSlug: "",
                seoOgImage: "",
                primaryKeyword: "",
            },
            {
                question: "Do you provide ongoing support?",
                answer: "Yes. We can provide maintenance, updates, security reviews, and long-term technical support depending on the engagement.",
                keywords: ["support", "maintenance"],
                sortOrder: 10,
                active: true,
                seoTitle: "",
                seoDescription: "",
                seoSlug: "",
                seoOgImage: "",
                primaryKeyword: "",
            },
            {
                question: "How do I contact support?",
                answer: "Use the Contact page or message us through the support channels listed on the website.",
                keywords: ["contact", "support"],
                sortOrder: 11,
                active: true,
                seoTitle: "",
                seoDescription: "",
                seoSlug: "",
                seoOgImage: "",
                primaryKeyword: "",
            },
            {
                question: "Why choose RipCrack?",
                answer: "Clients choose RipCrack because we offer proven expertise in software development, reverse engineering, and crack services; strong focus on security and legality; on-time and within-scope delivery; competitive pricing; and a long-term technical partnership mindset.",
                keywords: ["why", "choose"],
                sortOrder: 12,
                active: true,
                seoTitle: "",
                seoDescription: "",
                seoSlug: "",
                seoOgImage: "",
                primaryKeyword: "",
            },
        ];
        let createdCount = 0;
        let skippedCount = 0;
        for (const d of defaults) {
            const existing = await prisma.fAQItem.findFirst({ where: { question: d.question } });
            if (existing) {
                skippedCount += 1;
                continue;
            }
            await prisma.fAQItem.create({ data: d });
            createdCount += 1;
        }
        res.json({ ok: true, createdCount, skippedCount, total: defaults.length });
    }
    catch (err) {
        console.error("FAQ import-defaults error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Update FAQ
router.patch("/admin/chat/faqs/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!Number.isFinite(id))
            return res.status(400).json({ error: "Invalid id" });
        const body = z
            .object({
            question: z.string().min(1).max(500).optional(),
            answer: z.string().min(1).max(5000).optional(),
            keywords: z.array(z.string()).optional(),
            seoTitle: z.string().optional(),
            seoDescription: z.string().optional(),
            seoSlug: z.string().optional(),
            seoOgImage: z.string().optional(),
            primaryKeyword: z.string().optional(),
            secondaryKeywords: z.array(z.string()).optional(),
            sortOrder: z.coerce.number().int().optional(),
            active: z.boolean().optional(),
            source: z.enum(["new", "old"]).optional(),
        })
            .parse(req.body);
        const { source, ...data } = body;
        let item;
        if (source === "new") {
            try {
                item = await prisma.$transaction(async (db) => {
                    const updated = await db.fAQItem.update({ where: { id }, data });
                    await syncSeoKeywordUsage({
                        db,
                        entityType: "FAQ",
                        entityId: updated.id,
                        primaryKeyword: updated.primaryKeyword,
                        secondaryKeywords: jsonStringArray(updated.secondaryKeywords),
                    });
                    return updated;
                });
                return res.json({ item: { ...item, source: "new" } });
            }
            catch (e) {
                return res.status(400).json({ error: e?.message || "Failed" });
            }
        }
        if (source === "old") {
            item = await prisma.chatFAQ.update({ where: { id }, data });
            return res.json({ item: { ...item, source: "old" } });
        }
        try {
            item = await prisma.$transaction(async (db) => {
                const updated = await db.fAQItem.update({ where: { id }, data });
                await syncSeoKeywordUsage({
                    db,
                    entityType: "FAQ",
                    entityId: updated.id,
                    primaryKeyword: updated.primaryKeyword,
                    secondaryKeywords: jsonStringArray(updated.secondaryKeywords),
                });
                return updated;
            });
            return res.json({ item: { ...item, source: "new" } });
        }
        catch (e) {
            if (e?.code !== "P2025")
                throw e;
            item = await prisma.chatFAQ.update({ where: { id }, data });
            return res.json({ item: { ...item, source: "old" } });
        }
    }
    catch (err) {
        console.error("FAQ update error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Delete FAQ
router.delete("/admin/chat/faqs/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!Number.isFinite(id))
            return res.status(400).json({ error: "Invalid id" });
        const source = typeof req.query?.source === "string" ? req.query.source : undefined;
        if (source === "new") {
            await prisma.$transaction(async (db) => {
                await db.seoKeywordUsage.deleteMany({ where: { entityType: "FAQ", entityId: id } });
                await db.fAQItem.delete({ where: { id } });
            });
            return res.json({ ok: true });
        }
        if (source === "old") {
            await prisma.chatFAQ.delete({ where: { id } });
            return res.json({ ok: true });
        }
        try {
            await prisma.$transaction(async (db) => {
                await db.seoKeywordUsage.deleteMany({ where: { entityType: "FAQ", entityId: id } });
                await db.fAQItem.delete({ where: { id } });
            });
        }
        catch (e) {
            if (e?.code !== "P2025")
                throw e;
            await prisma.chatFAQ.delete({ where: { id } });
        }
        res.json({ ok: true });
    }
    catch (err) {
        console.error("FAQ delete error:", err);
        res.status(500).json({ error: err?.message || "Failed to delete FAQ" });
    }
});
// ========== CHAT API ==========
// Get or create chat session
async function getOrCreateChatSession(opts) {
    let geo = { country: "", city: "" };
    try {
        geo = await getGeoForIp(opts.ip);
    }
    catch (err) {
        console.error("Geo lookup error:", err);
        // Continue with empty geo data
    }
    let session;
    try {
        session = await prisma.chatSession.findFirst({
            where: {
                deviceId: opts.deviceId,
                status: { in: ["BOT", "WAITING_FOR_HUMAN", "HUMAN"] },
            },
            orderBy: { createdAt: "desc" },
        });
    }
    catch (err) {
        console.error("Session find error:", err);
        throw new Error("Database connection error");
    }
    if (session) {
        // Update session info
        try {
            await prisma.chatSession.update({
                where: { id: session.id },
                data: {
                    email: opts.email || session.email,
                    ip: opts.ip,
                    country: geo.country,
                    city: geo.city,
                    currentPage: opts.currentPage,
                    userAgent: opts.userAgent,
                    updatedAt: new Date(),
                },
            });
        }
        catch (err) {
            console.error("Session update error:", err);
            // Return existing session even if update fails
        }
        return session;
    }
    try {
        return await prisma.chatSession.create({
            data: {
                deviceId: opts.deviceId,
                email: opts.email || null,
                ip: opts.ip,
                country: geo.country,
                city: geo.city,
                currentPage: opts.currentPage,
                userAgent: opts.userAgent,
                status: "BOT",
            },
        });
    }
    catch (err) {
        console.error("Session create error:", err);
        throw new Error("Failed to create chat session");
    }
}
// Find matching FAQ answer
async function findFAQAnswer(message) {
    const lowerMessage = message.toLowerCase();
    // Try new FAQItem model first
    const newFaqs = await prisma.fAQItem.findMany({
        where: { active: true },
        orderBy: { sortOrder: "asc" },
    }).catch(() => []);
    for (const faq of newFaqs) {
        // Check if question matches (more flexible matching)
        const faqQuestionLower = faq.question.toLowerCase();
        if (faqQuestionLower.includes(lowerMessage) || lowerMessage.includes(faqQuestionLower)) {
            return faq.answer;
        }
        // Check if message contains any word from the question
        const questionWords = faqQuestionLower.split(/\s+/).filter(w => w.length > 3);
        if (questionWords.some(word => lowerMessage.includes(word))) {
            return faq.answer;
        }
        // Check keywords (more flexible)
        const keywordsArr = jsonStringArray(faq.keywords);
        if (keywordsArr.length > 0) {
            const hasKeyword = keywordsArr.some((kw) => {
                const kwLower = kw.toLowerCase().trim();
                return kwLower.length > 0 && lowerMessage.includes(kwLower);
            });
            if (hasKeyword)
                return faq.answer;
        }
    }
    // Fallback to old ChatFAQ model
    const oldFaqs = await prisma.chatFAQ.findMany({
        where: { active: true },
        orderBy: { sortOrder: "asc" },
    }).catch(() => []);
    for (const faq of oldFaqs) {
        // Check if question matches (more flexible matching)
        const faqQuestionLower = faq.question.toLowerCase();
        if (faqQuestionLower.includes(lowerMessage) || lowerMessage.includes(faqQuestionLower)) {
            return faq.answer;
        }
        // Check if message contains any word from the question
        const questionWords = faqQuestionLower.split(/\s+/).filter(w => w.length > 3);
        if (questionWords.some(word => lowerMessage.includes(word))) {
            return faq.answer;
        }
        // Check keywords (more flexible)
        const keywordsArrOld = jsonStringArray(faq.keywords);
        if (keywordsArrOld.length > 0) {
            const hasKeyword = keywordsArrOld.some((kw) => {
                const kwLower = kw.toLowerCase().trim();
                return kwLower.length > 0 && lowerMessage.includes(kwLower);
            });
            if (hasKeyword)
                return faq.answer;
        }
    }
    return null;
}
// Chat endpoint
router.post("/chat", rateLimit({ windowMs: 60 * 1000, max: 20, keyPrefix: "chat" }), async (req, res) => {
    try {
        const body = z
            .object({
            message: z.string().min(1).max(2000),
            deviceId: z.string().min(3).max(200),
            email: z.string().email().optional(),
            currentPage: z.string().optional().default(""),
        })
            .parse(req.body);
        const ip = getClientIp(req);
        const userAgent = String(req.headers["user-agent"] || "").slice(0, 500);
        // Get or create session
        let session;
        try {
            session = await getOrCreateChatSession({
                deviceId: body.deviceId,
                email: body.email,
                ip,
                userAgent,
                currentPage: body.currentPage,
            });
        }
        catch (err) {
            console.error("Session creation error:", err);
            return res.status(500).json({ error: "Failed to create chat session" });
        }
        // Save user message
        try {
            await prisma.chatMessage.create({
                data: {
                    sessionId: session.id,
                    role: "USER",
                    text: body.message,
                },
            });
        }
        catch (err) {
            console.error("Message creation error:", err);
            // Continue even if message save fails
        }
        // If waiting for human or already with human, just acknowledge
        if (session.status === "WAITING_FOR_HUMAN" || session.status === "HUMAN") {
            return res.json({
                reply: "Your message has been received. A support agent will respond shortly.",
                sessionId: session.id,
                status: session.status,
            });
        }
        // Check if user wants to speak with human
        const transferKeywords = ["human", "agent", "operator", "support", "help", "person", "real person", "live chat", "speak with", "talk to", "i want human", "need human"];
        const lowerMessage = body.message.toLowerCase();
        const wantsHuman = transferKeywords.some(keyword => lowerMessage.includes(keyword));
        // If user wants human and email is provided, transfer immediately
        if (wantsHuman && body.email) {
            try {
                await prisma.chatSession.update({
                    where: { id: session.id },
                    data: { status: "WAITING_FOR_HUMAN", email: body.email },
                });
                const transferReply = "Thank you! Your request has been sent to our support team. An agent will respond shortly.";
                try {
                    await prisma.chatMessage.create({
                        data: {
                            sessionId: session.id,
                            role: "BOT",
                            text: transferReply,
                        },
                    });
                }
                catch (err) {
                    console.error("Bot message creation error:", err);
                }
                return res.json({
                    reply: transferReply,
                    sessionId: session.id,
                    status: "WAITING_FOR_HUMAN",
                    needsEmail: false,
                });
            }
            catch (err) {
                console.error("Session update error:", err);
                return res.status(500).json({ error: "Failed to transfer to human agent" });
            }
        }
        // If user wants human but no email, ask for email
        if (wantsHuman && !body.email) {
            const emailRequestMessage = "I'd be happy to connect you with a human agent! Please provide your email address so we can assist you.";
            try {
                await prisma.chatMessage.create({
                    data: {
                        sessionId: session.id,
                        role: "BOT",
                        text: emailRequestMessage,
                    },
                });
            }
            catch (err) {
                console.error("Bot message creation error:", err);
            }
            return res.json({
                reply: emailRequestMessage,
                sessionId: session.id,
                status: session.status,
                needsEmail: true,
            });
        }
        // Try to find FAQ answer
        let faqAnswer = null;
        try {
            faqAnswer = await findFAQAnswer(body.message);
        }
        catch (err) {
            console.error("FAQ lookup error:", err);
        }
        if (faqAnswer) {
            // Save bot response
            try {
                await prisma.chatMessage.create({
                    data: {
                        sessionId: session.id,
                        role: "BOT",
                        text: faqAnswer,
                    },
                });
            }
            catch (err) {
                console.error("Bot message creation error:", err);
            }
            return res.json({
                reply: faqAnswer,
                sessionId: session.id,
                status: "BOT",
                needsEmail: false,
            });
        }
        // No FAQ match - ask if they want to transfer to human
        const transferMessage = "I couldn't find an answer to your question. Would you like to speak with a human agent? (Please provide your email address if you haven't already)";
        try {
            await prisma.chatMessage.create({
                data: {
                    sessionId: session.id,
                    role: "BOT",
                    text: transferMessage,
                },
            });
        }
        catch (err) {
            console.error("Bot message creation error:", err);
        }
        // Update session to waiting for human if email provided
        if (body.email) {
            try {
                await prisma.chatSession.update({
                    where: { id: session.id },
                    data: { status: "WAITING_FOR_HUMAN", email: body.email },
                });
            }
            catch (err) {
                console.error("Session update error:", err);
            }
        }
        return res.json({
            reply: transferMessage,
            sessionId: session.id,
            status: body.email ? "WAITING_FOR_HUMAN" : "BOT",
            needsEmail: !body.email,
        });
    }
    catch (err) {
        console.error("Chat error:", err);
        // More detailed error logging
        if (err instanceof z.ZodError) {
            return res.status(400).json({ error: "Invalid request: " + err.errors.map(e => e.message).join(", ") });
        }
        res.status(500).json({ error: err?.message || "Chat failed" });
    }
});
// Transfer to human (requires email)
router.post("/chat/transfer", rateLimit({ windowMs: 60 * 1000, max: 10, keyPrefix: "chat-transfer" }), async (req, res) => {
    try {
        const body = z
            .object({
            sessionId: z.string().min(1),
            email: z.string().email(),
        })
            .parse(req.body);
        const session = await prisma.chatSession.findUnique({ where: { id: body.sessionId } });
        if (!session) {
            return res.status(404).json({ error: "Session not found" });
        }
        try {
            await prisma.chatSession.update({
                where: { id: body.sessionId },
                data: { status: "WAITING_FOR_HUMAN", email: body.email },
            });
            try {
                await prisma.chatMessage.create({
                    data: {
                        sessionId: body.sessionId,
                        role: "BOT",
                        text: "Thank you! Your request has been sent to our support team. An agent will respond shortly.",
                    },
                });
            }
            catch (err) {
                console.error("Bot message creation error:", err);
                // Continue even if message creation fails
            }
            res.json({ ok: true, status: "WAITING_FOR_HUMAN" });
        }
        catch (err) {
            console.error("Session update error:", err);
            return res.status(500).json({ error: "Failed to transfer to human agent" });
        }
    }
    catch (err) {
        console.error("Transfer error:", err);
        if (err instanceof z.ZodError) {
            return res.status(400).json({ error: "Invalid request: " + err.errors.map(e => e.message).join(", ") });
        }
        res.status(500).json({ error: err?.message || "Transfer failed" });
    }
});
// ========== ADMIN CHAT INTERFACE ==========
// Get all chat sessions
router.get("/admin/chat/sessions", requireAuth, requireAdmin, async (req, res) => {
    try {
        const status = req.query.status;
        const where = {};
        if (status && ["BOT", "WAITING_FOR_HUMAN", "HUMAN", "CLOSED"].includes(status)) {
            where.status = status;
        }
        const sessions = await prisma.chatSession.findMany({
            where,
            include: {
                messages: {
                    orderBy: { createdAt: "asc" },
                    take: 1, // Just get first message for preview
                },
            },
            orderBy: { updatedAt: "desc" },
            take: 100,
        });
        res.json({ items: sessions });
    }
    catch (err) {
        console.error("Sessions list error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Get single chat session with all messages
router.get("/admin/chat/sessions/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
        const session = await prisma.chatSession.findUnique({
            where: { id: req.params.id },
            include: {
                messages: {
                    orderBy: { createdAt: "desc" },
                    take: 50,
                },
            },
        });
        if (!session)
            return res.status(404).json({ error: "Session not found" });
        session.messages.reverse();
        res.json({ item: session });
    }
    catch (err) {
        console.error("Session get error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Admin sends message to user
router.post("/admin/chat/sessions/:id/message", requireAuth, requireAdmin, async (req, res) => {
    try {
        const body = z
            .object({
            text: z.string().min(1).max(2000),
        })
            .parse(req.body);
        const session = await prisma.chatSession.findUnique({ where: { id: req.params.id } });
        if (!session)
            return res.status(404).json({ error: "Session not found" });
        // Update session to HUMAN if it was waiting
        if (session.status === "WAITING_FOR_HUMAN") {
            await prisma.chatSession.update({
                where: { id: session.id },
                data: { status: "HUMAN" },
            });
        }
        // Create admin message
        const message = await prisma.chatMessage.create({
            data: {
                sessionId: session.id,
                role: "ADMIN",
                text: body.text,
            },
        });
        res.json({ item: message });
    }
    catch (err) {
        console.error("Admin message error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Update session status
router.patch("/admin/chat/sessions/:id/status", requireAuth, requireAdmin, async (req, res) => {
    try {
        const body = z
            .object({
            status: z.enum(["BOT", "WAITING_FOR_HUMAN", "HUMAN", "CLOSED"]),
        })
            .parse(req.body);
        const session = await prisma.chatSession.update({
            where: { id: req.params.id },
            data: { status: body.status },
        });
        res.json({ item: session });
    }
    catch (err) {
        console.error("Status update error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// ========== NEW CHAT SYSTEM (TIDIO-LIKE) ==========
function parseUserAgent(ua) {
    const s = (ua || "").toLowerCase();
    let device = "desktop";
    if (/mobile|android|iphone|ipod|blackberry|opera mini|iemobile/i.test(s))
        device = "mobile";
    else if (/ipad|tablet|playbook|silk/i.test(s))
        device = "tablet";
    let browser = "Other";
    if (s.includes("chrome") && !s.includes("edg"))
        browser = "Chrome";
    else if (s.includes("firefox"))
        browser = "Firefox";
    else if (s.includes("safari") && !s.includes("chrome"))
        browser = "Safari";
    else if (s.includes("edg"))
        browser = "Edge";
    else if (s.includes("opera") || s.includes("opr"))
        browser = "Opera";
    return { device, browser };
}
// Get or create visitor
async function getOrCreateVisitor(opts) {
    const { device, browser } = parseUserAgent(opts.userAgent);
    const geo = await getGeoForIp(opts.ip);
    const visitor = await prisma.visitor.findUnique({
        where: { visitorId: opts.visitorId },
    });
    if (visitor) {
        return await prisma.visitor.update({
            where: { id: visitor.id },
            data: {
                email: opts.email || visitor.email,
                ip: opts.ip,
                country: geo.country,
                city: geo.city,
                userAgent: opts.userAgent,
                device,
                browser,
                lastSeenAt: new Date(),
            },
        });
    }
    return await prisma.visitor.create({
        data: {
            visitorId: opts.visitorId,
            email: opts.email || null,
            ip: opts.ip,
            country: geo.country,
            city: geo.city,
            userAgent: opts.userAgent,
            device,
            browser,
        },
    });
}
// Track page view
router.post("/chat/track-page", rateLimit({ windowMs: 60 * 1000, max: 240, keyPrefix: "chat:track" }), async (req, res) => {
    try {
        const body = z
            .object({
            visitorId: z.string().min(3).max(200),
            url: z.string().min(1).max(500),
            referrer: z.string().nullable().optional().transform(v => v || ""),
        })
            .parse(req.body);
        const ip = getClientIp(req);
        const userAgent = String(req.headers["user-agent"] || "").slice(0, 500);
        const visitor = await getOrCreateVisitor({
            visitorId: body.visitorId,
            ip,
            userAgent,
        });
        await prisma.viewedPageEvent.create({
            data: {
                visitorId: visitor.id,
                url: body.url,
                referrer: body.referrer || "",
            },
        });
        res.json({ ok: true });
    }
    catch (err) {
        console.error("Track page error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Get or create conversation
router.post("/chat/conversation", rateLimit({ windowMs: 60 * 1000, max: 20, keyPrefix: "chat:conv" }), async (req, res) => {
    try {
        const body = z
            .object({
            visitorId: z.string().min(3).max(200),
            email: z.string().email().optional(),
        })
            .parse(req.body);
        const ip = getClientIp(req);
        const userAgent = String(req.headers["user-agent"] || "").slice(0, 500);
        const visitor = await getOrCreateVisitor({
            visitorId: body.visitorId,
            ip,
            userAgent,
            email: body.email,
        });
        // Find active conversation
        let conversation = await prisma.conversation.findFirst({
            where: {
                visitorId: visitor.id,
                status: { in: ["UNASSIGNED", "OPEN"] },
            },
            orderBy: { createdAt: "desc" },
        });
        if (!conversation) {
            conversation = await prisma.conversation.create({
                data: {
                    visitorId: visitor.id,
                    status: "UNASSIGNED",
                },
            });
        }
        res.json({ conversationId: conversation.id, visitorId: visitor.id });
    }
    catch (err) {
        console.error("Create conversation error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Get conversation messages
router.get("/chat/conversation/:id/messages", async (req, res) => {
    try {
        const conversation = await prisma.conversation.findUnique({
            where: { id: req.params.id },
            include: {
                messages: {
                    orderBy: { createdAt: "asc" },
                },
            },
        });
        if (!conversation) {
            return res.status(404).json({ error: "Conversation not found" });
        }
        res.json({ messages: conversation.messages });
    }
    catch (err) {
        console.error("Get messages error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Admin: Get all conversations
router.get("/admin/chat/conversations", requireAuth, requireAdmin, async (req, res) => {
    try {
        const status = req.query.status;
        const assigneeId = req.query.assigneeId;
        const where = {};
        if (status && ["UNASSIGNED", "OPEN", "SOLVED"].includes(status)) {
            where.status = status;
        }
        if (assigneeId) {
            where.assigneeId = assigneeId;
        }
        // If user is not admin, only show their assigned conversations
        if (req.user?.role !== "ADMIN") {
            where.assigneeId = req.user?.id;
        }
        const conversations = await prisma.conversation.findMany({
            where,
            include: {
                visitor: {
                    select: {
                        id: true,
                        visitorId: true,
                        email: true,
                        ip: true,
                        country: true,
                        city: true,
                        device: true,
                        browser: true,
                        firstSeenAt: true,
                        lastSeenAt: true,
                    },
                },
                assignee: {
                    select: {
                        id: true,
                        email: true,
                        firstName: true,
                        lastName: true,
                    },
                },
                messages: {
                    orderBy: { createdAt: "desc" },
                    take: 1,
                },
                _count: {
                    select: { messages: true },
                },
            },
            orderBy: { updatedAt: "desc" },
            take: 100,
        });
        res.json({ items: conversations });
    }
    catch (err) {
        console.error("Get conversations error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Admin: Get single conversation with full details
router.get("/admin/chat/conversations/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
        const conversation = await prisma.conversation.findUnique({
            where: { id: req.params.id },
            include: {
                visitor: {
                    include: {
                        viewedPages: {
                            orderBy: { timestamp: "desc" },
                            take: 50,
                        },
                    },
                },
                assignee: {
                    select: {
                        id: true,
                        email: true,
                        firstName: true,
                        lastName: true,
                    },
                },
                messages: {
                    orderBy: { createdAt: "asc" },
                },
                notes: {
                    include: {
                        author: {
                            select: {
                                id: true,
                                email: true,
                                firstName: true,
                                lastName: true,
                            },
                        },
                    },
                    orderBy: { createdAt: "desc" },
                },
            },
        });
        if (!conversation) {
            return res.status(404).json({ error: "Conversation not found" });
        }
        res.json({ item: conversation });
    }
    catch (err) {
        console.error("Get conversation error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Admin: Assign conversation
router.patch("/admin/chat/conversations/:id/assign", requireAuth, requireAdmin, async (req, res) => {
    try {
        const body = z
            .object({
            assigneeId: z.string().optional(),
        })
            .parse(req.body);
        const conversation = await prisma.conversation.update({
            where: { id: req.params.id },
            data: {
                assigneeId: body.assigneeId || req.user?.id || null,
                status: body.assigneeId ? "OPEN" : "UNASSIGNED",
            },
            include: {
                assignee: {
                    select: {
                        id: true,
                        email: true,
                        firstName: true,
                        lastName: true,
                    },
                },
            },
        });
        res.json({ item: conversation });
    }
    catch (err) {
        console.error("Assign conversation error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Admin: Solve conversation
router.patch("/admin/chat/conversations/:id/solve", requireAuth, requireAdmin, async (req, res) => {
    try {
        const conversation = await prisma.conversation.update({
            where: { id: req.params.id },
            data: { status: "SOLVED" },
        });
        res.json({ item: conversation });
    }
    catch (err) {
        console.error("Solve conversation error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Admin: Get all visitors
router.get("/admin/chat/visitors", requireAuth, requireAdmin, async (req, res) => {
    try {
        const hasEmail = req.query.hasEmail;
        const where = {};
        if (hasEmail === "true") {
            where.email = { not: null };
        }
        const visitors = await prisma.visitor.findMany({
            where,
            include: {
                _count: {
                    select: { conversations: true },
                },
            },
            orderBy: { lastSeenAt: "desc" },
            take: 500,
        });
        res.json({ items: visitors });
    }
    catch (err) {
        console.error("Get visitors error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Admin: Export visitors (CSV/Excel)
router.get("/admin/chat/visitors/export", requireAuth, requireAdmin, async (req, res) => {
    try {
        const format = req.query.format || "csv";
        const hasEmail = req.query.hasEmail;
        const dateFrom = req.query.dateFrom;
        const dateTo = req.query.dateTo;
        const where = {};
        if (hasEmail === "true") {
            where.email = { not: null };
        }
        if (dateFrom || dateTo) {
            where.createdAt = {};
            if (dateFrom)
                where.createdAt.gte = new Date(dateFrom);
            if (dateTo)
                where.createdAt.lte = new Date(dateTo);
        }
        const visitors = await prisma.visitor.findMany({
            where,
            include: {
                _count: {
                    select: { conversations: true },
                },
            },
            orderBy: { lastSeenAt: "desc" },
        });
        if (format === "xlsx") {
            const XLSX = await import("xlsx");
            const worksheet = XLSX.utils.json_to_sheet(visitors.map((v) => ({
                "Visitor ID": v.visitorId,
                Email: v.email || "",
                IP: v.ip,
                Country: v.country,
                City: v.city,
                Device: v.device,
                Browser: v.browser,
                "First Seen": v.firstSeenAt.toISOString(),
                "Last Seen": v.lastSeenAt.toISOString(),
                "Conversations": v._count.conversations,
            })));
            const workbook = XLSX.utils.book_new();
            XLSX.utils.book_append_sheet(workbook, worksheet, "Visitors");
            const buffer = XLSX.write(workbook, { type: "buffer", bookType: "xlsx" });
            res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            res.setHeader("Content-Disposition", `attachment; filename=visitors-${Date.now()}.xlsx`);
            res.send(buffer);
        }
        else {
            // CSV
            const headers = ["Visitor ID", "Email", "IP", "Country", "City", "Device", "Browser", "First Seen", "Last Seen", "Conversations"];
            const rows = visitors.map((v) => [
                v.visitorId,
                v.email || "",
                v.ip,
                v.country,
                v.city,
                v.device,
                v.browser,
                v.firstSeenAt.toISOString(),
                v.lastSeenAt.toISOString(),
                v._count.conversations,
            ]);
            const csv = [headers.join(","), ...rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(","))].join("\n");
            res.setHeader("Content-Type", "text/csv");
            res.setHeader("Content-Disposition", `attachment; filename=visitors-${Date.now()}.csv`);
            res.send(csv);
        }
    }
    catch (err) {
        console.error("Export visitors error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// Admin: Add note
router.post("/admin/chat/notes", requireAuth, requireAdmin, async (req, res) => {
    try {
        const body = z
            .object({
            conversationId: z.string().optional(),
            visitorId: z.string().optional(),
            text: z.string().min(1).max(5000),
        })
            .parse(req.body);
        if (!body.conversationId && !body.visitorId) {
            return res.status(400).json({ error: "Either conversationId or visitorId required" });
        }
        const note = await prisma.note.create({
            data: {
                conversationId: body.conversationId || null,
                visitorId: body.visitorId || null,
                authorId: req.user.id,
                text: body.text,
            },
            include: {
                author: {
                    select: {
                        id: true,
                        email: true,
                        firstName: true,
                        lastName: true,
                    },
                },
            },
        });
        res.json({ item: note });
    }
    catch (err) {
        console.error("Create note error:", err);
        res.status(500).json({ error: err?.message || "Failed" });
    }
});
// ========== WIDGET COMPATIBILITY API ==========
async function getGeoForIp(ip) {
    try {
        if (ip === "127.0.0.1" || ip === "::1" || ip.startsWith("192.168.") || ip.startsWith("10.")) {
            return { country: "Local", city: "Local", region: "Local", timezone: "UTC" };
        }
        if (typeof fetch !== "function")
            return { country: "Unknown", city: "Unknown" };
        const res = await fetch(`https://ipapi.co/${ip}/json/`);
        if (res.ok) {
            const data = await res.json();
            return {
                country: data.country_name || "Unknown",
                city: data.city || "Unknown",
                region: data.region || "Unknown",
                timezone: data.timezone || "UTC",
            };
        }
    }
    catch (e) {
        console.error("Geo lookup error:", e);
    }
    return { country: "Unknown", city: "Unknown", region: "Unknown", timezone: "UTC" };
}
router.get("/widget/config", async (req, res) => {
    const { apiKey } = req.query;
    // Try to find tenant by apiKey (id or name)
    let tenant = null;
    if (apiKey && typeof apiKey === "string") {
        tenant = await prisma.tenant.findUnique({ where: { id: apiKey } }).catch(() => null);
    }
    const settings = tenant?.settings || {};
    res.json({
        appearance: {
            brandColor: settings.brandColor || "#059669",
            brandColorDark: settings.brandColorDark || "#047857",
            title: settings.title || "Dəstək",
            subtitle: settings.subtitle || "Sizə necə kömək edə bilərik?",
            language: settings.language || "AZ",
        },
        agent: {
            name: settings.agentName || "Support Agent",
            avatarUrl: settings.agentAvatarUrl || null,
        },
        quickActions: settings.quickActions || [],
    });
});
router.post("/widget/session", async (req, res) => {
    try {
        const body = z.object({
            apiKey: z.string().min(1),
            visitorToken: z.string().nullable().optional(),
            currentUrl: z.string().nullable().optional().transform(v => v || ""),
            referrer: z.string().nullable().optional().transform(v => v || ""),
            language: z.string().nullable().optional().default("AZ"),
            metadata: z.any().optional(),
        }).parse(req.body);
        const ip = getClientIp(req);
        const userAgent = String(req.headers["user-agent"] || "");
        const visitorId = body.visitorToken || crypto.randomUUID();
        const visitor = await getOrCreateVisitor({
            visitorId,
            ip,
            userAgent,
        });
        // Check if tenant exists
        const tenantExists = await prisma.tenant.findUnique({ where: { id: body.apiKey } }).catch(() => null);
        const validTenantId = tenantExists ? body.apiKey : null;
        if (!visitor.tenantId && validTenantId) {
            await prisma.visitor.update({
                where: { id: visitor.id },
                data: { tenantId: validTenantId }
            }).catch(() => { });
        }
        // Find or create conversation
        let conversation = await prisma.conversation.findFirst({
            where: { visitorId: visitor.id, status: { in: ["UNASSIGNED", "OPEN"] } },
            orderBy: { updatedAt: "desc" }
        });
        if (!conversation) {
            conversation = await prisma.conversation.create({
                data: { visitorId: visitor.id, status: "UNASSIGNED", tenantId: validTenantId }
            });
        }
        // Track page view
        if (body.currentUrl) {
            await prisma.viewedPageEvent.create({
                data: {
                    visitorId: visitor.id,
                    url: body.currentUrl,
                    referrer: body.referrer || "",
                }
            }).catch(() => { });
        }
        let messages = await prisma.message.findMany({
            where: { conversationId: conversation.id },
            orderBy: { createdAt: "asc" }
        });
        // Build the response messages array
        const mappedMessages = messages.map((m) => ({
            id: m.id,
            from: m.senderType,
            text: m.text,
            attachments: m.attachments || null,
            createdAt: m.createdAt,
        }));
        res.json({
            visitorToken: visitor.visitorId,
            conversation: { id: conversation.id },
            messages: mappedMessages,
            contact: {
                name: visitor.name || "",
                email: visitor.email || "",
                phone: visitor.phone || "",
            }
        });
    }
    catch (err) {
        console.error("Widget session error:", err);
        res.status(500).json({ error: err.message });
    }
});
router.post("/widget/identify", async (req, res) => {
    try {
        const body = z.object({
            apiKey: z.string(),
            visitorToken: z.string(),
            name: z.string().optional(),
            email: z.string().email().optional(),
            phone: z.string().optional(),
        }).parse(req.body);
        const visitor = await prisma.visitor.findUnique({ where: { visitorId: body.visitorToken } });
        if (!visitor)
            return res.status(404).json({ error: "Visitor not found" });
        // Always update email (guaranteed to exist in schema)
        await prisma.visitor.update({
            where: { id: visitor.id },
            data: { email: body.email || visitor.email || null }
        }).catch(() => { });
        // Try to update name & phone (may not exist in DB if db push not yet run)
        await prisma.visitor.update({
            where: { id: visitor.id },
            data: { name: body.name || null, phone: body.phone || null }
        }).catch(() => {
            // Silently ignore if name/phone columns don't exist yet
            console.warn("Widget identify: name/phone columns may not exist yet. Run: npx prisma db push");
        });
        res.json({ ok: true });
    }
    catch (err) {
        res.status(400).json({ error: err.message });
    }
});
router.post("/widget/message", async (req, res) => {
    try {
        const body = z.object({
            apiKey: z.string(),
            visitorToken: z.string(),
            text: z.string().min(1).max(5000),
            attachments: z.any().optional(),
        }).parse(req.body);
        const visitor = await prisma.visitor.findUnique({
            where: { visitorId: body.visitorToken },
            include: { conversations: { where: { status: { in: ["UNASSIGNED", "OPEN"] } }, orderBy: { updatedAt: "desc" }, take: 1 } }
        });
        if (!visitor)
            return res.status(404).json({ error: "Visitor not found" });
        const conversation = visitor.conversations[0];
        if (!conversation)
            return res.status(400).json({ error: "No active conversation" });
        const message = await prisma.message.create({
            data: {
                conversationId: conversation.id,
                senderType: "VISITOR",
                text: body.text,
            }
        });
        // Update conversation updatedAt
        await prisma.conversation.update({
            where: { id: conversation.id },
            data: { updatedAt: new Date() }
        });
        // Emit to socket room
        const io = req.app.get("io");
        if (io) {
            io.to(conversation.id).emit("new-message", {
                id: message.id,
                from: "VISITOR",
                text: message.text,
                createdAt: message.createdAt
            });
        }
        res.json({ message: {
                id: message.id,
                from: "VISITOR",
                text: message.text,
                createdAt: message.createdAt
            } });
    }
    catch (err) {
        res.status(500).json({ error: err.message });
    }
});
router.post("/widget/page-update", async (req, res) => {
    try {
        const body = z.object({
            visitorToken: z.string(),
            page: z.string().nullable().optional().transform(v => v || ""),
        }).parse(req.body);
        const visitor = await prisma.visitor.findUnique({ where: { visitorId: body.visitorToken } });
        if (!visitor)
            return res.status(404).json({ error: "Visitor not found" });
        await prisma.viewedPageEvent.create({
            data: {
                visitorId: visitor.id,
                url: body.page,
            }
        });
        res.json({ ok: true });
    }
    catch (err) {
        res.status(500).json({ error: err.message });
    }
});
