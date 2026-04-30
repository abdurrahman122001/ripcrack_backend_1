import "dotenv/config";
import { createPool } from "mysql2/promise";
import bcrypt from "bcryptjs";
import { prisma } from "./prisma.js";
async function main() {
    const wpDb = String(process.env.WP_DB || "ripcrack").trim() || "ripcrack";
    const wpTable = String(process.env.WP_USERS_TABLE || "ripcrack_users").trim() || "ripcrack_users";
    const host = String(process.env.WP_DB_HOST || process.env.DB_HOST || "127.0.0.1");
    const port = Number(process.env.WP_DB_PORT || process.env.DB_PORT || 3306);
    const user = String(process.env.WP_DB_USER || process.env.DB_USER || "root");
    const password = String(process.env.WP_DB_PASSWORD || process.env.DB_PASSWORD || "");
    const tempPass = String(process.env.WP_TEMP_PASSWORD || "ChangeMe123!");
    const tempHash = await bcrypt.hash(tempPass, 10);
    const pool = createPool({
        host,
        port,
        user,
        password,
        database: wpDb,
        connectionLimit: 4,
    });
    const [raw] = await pool.query(`SELECT ID, user_login, user_email, display_name FROM \`${wpTable}\` WHERE user_email IS NOT NULL AND user_email <> ''`);
    const rows = raw;
    let created = 0;
    let updated = 0;
    let skipped = 0;
    for (const r of rows) {
        const email = String(r.user_email || "").trim().toLowerCase();
        if (!email) {
            skipped++;
            continue;
        }
        const name = String(r.display_name || r.user_login || "").trim();
        const [firstName, ...rest] = name.split(/\s+/).filter(Boolean);
        const lastName = rest.length ? rest.join(" ") : undefined;
        const existing = await prisma.user.findUnique({ where: { email } });
        if (existing) {
            await prisma.user.update({
                where: { email },
                data: {
                    firstName: existing.firstName ?? firstName ?? null,
                    lastName: existing.lastName ?? lastName ?? null,
                },
            });
            updated++;
        }
        else {
            await prisma.user.create({
                data: {
                    email,
                    password: tempHash,
                    firstName: firstName || null,
                    lastName: lastName || null,
                    role: "USER",
                    emailVerified: false,
                },
            });
            created++;
        }
    }
    await pool.end();
    console.log(JSON.stringify({
        wpDb,
        wpTable,
        read: rows.length,
        created,
        updated,
        skipped,
        tempPassword: tempPass,
    }, null, 2));
}
main()
    .then(() => prisma.$disconnect())
    .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
});
