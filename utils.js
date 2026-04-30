import jwt from "jsonwebtoken";
export function mustEnv(name) {
    const v = process.env[name];
    if (!v)
        throw new Error(`Missing env ${name}`);
    return v;
}
export function signJwt(payload) {
    return jwt.sign(payload, mustEnv("JWT_SECRET"), { expiresIn: "7d" });
}
export function verifyJwt(token) {
    return jwt.verify(token, mustEnv("JWT_SECRET"));
}
export function getBearerToken(req) {
    const h = req.headers.authorization;
    if (!h)
        return null;
    const m = h.match(/^Bearer\s+(.+)$/i);
    return m ? m[1] : null;
}
