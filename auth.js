import { prisma } from "./prisma.js";
import { getBearerToken, verifyJwt } from "./utils.js";
export async function requireAuth(req, res, next) {
    try {
        const token = getBearerToken(req);
        if (!token)
            return res.status(401).json({ error: "Missing Bearer token" });
        const decoded = verifyJwt(token);
        const user = await prisma.user.findUnique({ where: { id: decoded.sub } });
        if (!user)
            return res.status(401).json({ error: "User not found" });
        req.user = { id: user.id, role: user.role, email: user.email, firstName: user.firstName, lastName: user.lastName };
        next();
    }
    catch {
        return res.status(401).json({ error: "Invalid token" });
    }
}
export async function requireOptionalAuth(req, _res, next) {
    try {
        const token = getBearerToken(req);
        if (!token)
            return next();
        const decoded = verifyJwt(token);
        const user = await prisma.user.findUnique({ where: { id: decoded.sub } });
        if (user)
            req.user = { id: user.id, role: user.role, email: user.email, firstName: user.firstName, lastName: user.lastName };
        return next();
    }
    catch {
        return next();
    }
}
export function requireAdmin(req, res, next) {
    if (!req.user)
        return res.status(401).json({ error: "Unauthenticated" });
    if (req.user.role !== "ADMIN" && req.user.role !== "AGENT")
        return res.status(403).json({ error: "Admin only" });
    next();
}
