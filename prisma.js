import { PrismaClient } from "@prisma/client";
// CRITICAL FIX: Optimize Prisma connection pool to prevent slow database queries
export const prisma = new PrismaClient({
    log: process.env.NODE_ENV === "development" ? ["error", "warn"] : ["error"],
});
