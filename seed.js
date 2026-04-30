import "dotenv/config";
import { prisma } from "./prisma.js";
async function main() {
    const existing = await prisma.product.count();
    if (existing === 0) {
        const categories = ["Design", "Security", "Marketing", "Automation", "AI Tools"];
        const products = Array.from({ length: 18 }).map((_, i) => ({
            title: `Product ${i + 1}`,
            category: categories[i % categories.length],
            description: "",
            badge: i % 7 === 0 ? "Hot" : i % 5 === 0 ? "New" : "",
            price: i % 4 === 0 ? "From $49" : "Price on request",
            seoTitle: "",
            seoDescription: "",
            seoSlug: "",
            seoOgImage: "",
            primaryKeyword: "",
            views: 200 + i * 37,
            sold: 15 + i * 3
        }));
        await prisma.product.createMany({ data: products });
        console.log("Seeded products:", products.length);
    }
    const adminEmail = (process.env.ADMIN_EMAIL || "admin@example.com").toLowerCase();
    const adminExists = await prisma.user.findUnique({ where: { email: adminEmail } });
    if (!adminExists) {
        const bcrypt = await import("bcryptjs");
        const password = await bcrypt.default.hash("admin123", 10);
        await prisma.user.create({ data: { email: adminEmail, password, role: "ADMIN" } });
        console.log("Created admin:", adminEmail, "password: admin123");
    }
    // Seed default tenant for widget
    const tenantId = "site_2q6v69gck3amoimei25";
    const tenantExists = await prisma.tenant.findUnique({ where: { id: tenantId } });
    if (!tenantExists) {
        await prisma.tenant.create({
            data: {
                id: tenantId,
                name: "RipCrack Support",
                settings: {
                    brandColor: "#059669",
                    brandColorDark: "#047857",
                    title: "RipCrack Support",
                    subtitle: "We typically reply in a few minutes",
                    language: "AZ",
                    agentName: "Support",
                }
            }
        });
        console.log("Created default tenant:", tenantId);
    }
}
main()
    .then(() => prisma.$disconnect())
    .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
});
