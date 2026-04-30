import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import { createServer } from "http";
import { Server } from "socket.io";
import { fileURLToPath } from "url";
import { router } from "./routes.js";
import { prisma } from "./prisma.js";
import path from "path";
import fs from "fs";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const mailchimpImagesPath = path.resolve(__dirname, "..", "..", "Mailchimp", "images");
const app = express();
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
    frameguard: false, // Explicitly disable frameguard
}));
// Custom middleware to ensure iframe embedding works
app.use((req, res, next) => {
    res.removeHeader("X-Frame-Options");
    res.setHeader("Content-Security-Policy", "frame-ancestors 'self' http://localhost:5173 http://localhost:3003 https://api.chatmesaj.cc https://chatmesaj.cc;");
    next();
});
// Specific routes for widget files to ensure they are served correctly even if they are in public
app.use(express.json({ limit: "2mb" }));
// CORS configuration
const isDev = process.env.NODE_ENV !== "production";
const corsOrigin = process.env.CORS_ORIGIN;
const widgetOrigins = (process.env.WIDGET_ORIGINS || "*").split(",").map(o => o.trim());
app.use(cors({
    origin: (origin, callback) => {
        if (!origin)
            return callback(null, true);
        if (widgetOrigins.includes("*"))
            return callback(null, true);
        const allowedOrigins = corsOrigin ? corsOrigin.split(',').map(o => o.trim()) : ["http://localhost:5173"];
        if (allowedOrigins.includes(origin) || widgetOrigins.includes(origin)) {
            callback(null, true);
        }
        else {
            callback(null, false); // Blocked by CORS
        }
    },
    credentials: true
}));
fs.mkdirSync(path.resolve(process.cwd(), "uploads"), { recursive: true });
fs.mkdirSync(path.resolve(process.cwd(), "public"), { recursive: true });
app.use("/api/uploads", express.static(path.resolve(process.cwd(), "uploads")));
app.use(express.static(path.resolve(process.cwd(), "public")));
// Specific routes for widget files to ensure they are served correctly even if they are in public
app.get("/widget-embed.js", (req, res) => {
    const filePath = path.resolve(process.cwd(), "public", "widget-embed.js");
    if (fs.existsSync(filePath)) {
        res.setHeader('Content-Type', 'application/javascript');
        res.sendFile(filePath);
    }
    else {
        res.status(404).send("Not found");
    }
});
app.get("/embed.html", (req, res) => {
    const filePath = path.resolve(process.cwd(), "public", "embed.html");
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    }
    else {
        res.status(404).send("Not found");
    }
});
// Email templates reference ${appUrl}/api/email-assets/* — serve Mailchimp/images so images show in emails
if (fs.existsSync(mailchimpImagesPath)) {
    app.use("/api/email-assets", express.static(mailchimpImagesPath));
}
app.use("/api", router);
app.use((err, _req, res, _next) => {
    console.error("Unhandled API error:", err);
    if (res.headersSent)
        return;
    res.status(500).json({ error: err?.message || "Internal Server Error" });
});
// In production, serve built frontend (Vite SPA) so Nginx can proxy a single app to this port
const isProduction = process.env.NODE_ENV === "production";
const frontendDist = process.env.FRONTEND_DIST || path.resolve(process.cwd(), "../frontend/dist");
if (isProduction && fs.existsSync(frontendDist)) {
    app.use(express.static(frontendDist));
    app.get("*", (_req, res) => {
        res.sendFile(path.join(frontendDist, "index.html"));
    });
}
const port = Number(process.env.PORT || 8080);
const host = process.env.HOST || "0.0.0.0";
const httpServer = createServer(app);
// Socket.io initialization
const io = new Server(httpServer, {
    cors: {
        origin: (origin, callback) => {
            if (!origin)
                return callback(null, true);
            if (widgetOrigins.includes("*"))
                return callback(null, true);
            const allowedOrigins = corsOrigin ? corsOrigin.split(',').map(o => o.trim()) : ["http://localhost:5173"];
            if (allowedOrigins.includes(origin) || widgetOrigins.includes(origin)) {
                callback(null, true);
            }
            else {
                callback(null, false);
            }
        },
        credentials: true
    }
});
app.set("io", io);
io.on("connection", (socket) => {
    console.log("Client connected:", socket.id);
    socket.on("join-conversation", (conversationId) => {
        socket.join(conversationId);
        console.log(`Socket ${socket.id} joined conversation ${conversationId}`);
    });
    socket.on("disconnect", () => {
        console.log("Client disconnected:", socket.id);
    });
});
// Export io for use in routes
export { io };
httpServer.listen(port, host, () => {
    console.log(`API listening on http://${host}:${port}`);
});
process.on("unhandledRejection", (reason) => {
    console.error("UnhandledRejection:", reason);
});
process.on("uncaughtException", (err) => {
    console.error("UncaughtException:", err);
});
process.on("SIGINT", async () => {
    await prisma.$disconnect();
    process.exit(0);
});
