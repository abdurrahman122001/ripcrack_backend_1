import nodemailer from "nodemailer";
/**
 * Email config is loaded from .env (via dotenv in server.ts):
 *   SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASS
 *   SMTP_USE_URL ("true" = use URL format), SMTP_DEBUG ("true" = verbose)
 *   MAIL_FROM (e.g. "RIPCRACK <noreply@ripcrack.com>")
 */
function hasSmtp() {
    return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}
export async function sendMail(opts) {
    if (!hasSmtp()) {
        console.log("\n--- EMAIL (DEV MODE: SMTP not configured) ---");
        console.log("TO:", opts.to);
        console.log("SUBJECT:", opts.subject);
        console.log("HTML:", opts.html);
        console.log("--- END EMAIL ---\n");
        return;
    }
    const port = Number(process.env.SMTP_PORT || 587);
    const isSecurePort = port === 465;
    // Retry configuration
    const maxRetries = 3;
    const retryDelay = 3000; // 3 seconds between retries
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        let transporter = null;
        try {
            // Try using connection URL format first (sometimes more reliable)
            const useUrlFormat = process.env.SMTP_USE_URL === "true";
            if (useUrlFormat) {
                // URL format: smtp://user:pass@host:port
                const protocol = isSecurePort ? 'smtps' : 'smtp';
                const auth = encodeURIComponent(process.env.SMTP_USER) + ':' + encodeURIComponent(process.env.SMTP_PASS);
                const url = `${protocol}://${auth}@${process.env.SMTP_HOST}:${port}`;
                console.log(`Using URL format connection (attempt ${attempt})...`);
                transporter = nodemailer.createTransport(url);
            }
            else {
                // Try using IP address if provided (can help with DNS issues)
                const smtpHost = process.env.SMTP_IP || process.env.SMTP_HOST;
                // Object format with explicit options
                const transportOptions = {
                    host: smtpHost,
                    port: port,
                    secure: isSecurePort, // true for 465 (direct SSL), false for 587 (STARTTLS)
                    auth: {
                        user: process.env.SMTP_USER,
                        pass: process.env.SMTP_PASS
                    },
                    // Critical: Gmail closes idle connections after ~2 minutes
                    // We need to read the greeting IMMEDIATELY after connection
                    connectionTimeout: 20000, // 20 seconds
                    greetingTimeout: 10000, // 10 seconds - MUST be short to read greeting quickly
                    socketTimeout: 60000, // 60 seconds - for socket operations
                    // Disable any delays that might prevent immediate greeting read
                    disableFileAccess: true,
                    disableUrlAccess: true,
                    // Disable connection pooling to avoid stale connections
                    pool: false,
                    // Enable debug logging to see what's happening
                    debug: process.env.SMTP_DEBUG === "true",
                    logger: process.env.SMTP_DEBUG === "true",
                    // Try to use IPv4 explicitly
                    family: 4
                };
                // TLS/SSL configuration
                if (isSecurePort) {
                    // For port 465 (SSL)
                    transportOptions.tls = {
                        rejectUnauthorized: false,
                        // Allow legacy TLS versions if needed
                        minVersion: 'TLSv1',
                        // Increase TLS handshake timeout
                        handshakeTimeout: 120000
                    };
                }
                else {
                    // For port 587 (STARTTLS)
                    transportOptions.requireTLS = true;
                    transportOptions.tls = {
                        rejectUnauthorized: false,
                        minVersion: 'TLSv1',
                        handshakeTimeout: 30000 // Reduced - should be faster
                    };
                    // Explicitly enable STARTTLS
                    transportOptions.ignoreTLS = false;
                    // Don't wait too long for STARTTLS
                    transportOptions.opportunisticTLS = false;
                }
                console.log(`Creating SMTP transporter (attempt ${attempt}, port ${port}, secure: ${isSecurePort})...`);
                transporter = nodemailer.createTransport(transportOptions);
            }
            // Verify connection first - this forces nodemailer to read the greeting
            // and complete the SMTP handshake, which prevents "Unexpected socket close"
            // The connection is established but Gmail closes it if we don't respond to greeting
            console.log(`Verifying SMTP connection (attempt ${attempt})...`);
            try {
                // Add timeout to verification to prevent hanging
                const verifyPromise = transporter.verify();
                const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error("Verification timeout")), 15000));
                await Promise.race([verifyPromise, timeoutPromise]);
                console.log("SMTP connection verified successfully");
            }
            catch (verifyError) {
                console.error("SMTP verification failed:", verifyError.message);
                // If verification fails, try sending anyway - sometimes verify() has issues but sendMail() works
                console.log("Skipping verification, attempting to send directly...");
            }
            console.log(`Sending email (attempt ${attempt}/${maxRetries})...`);
            console.log(`Email recipient: ${opts.to}`);
            console.log(`Email subject: ${opts.subject}`);
            await transporter.sendMail({
                from: process.env.MAIL_FROM || "Catalog <no-reply@example.com>",
                to: opts.to,
                subject: opts.subject,
                html: opts.html,
            });
            console.log(`Email sent successfully to: ${opts.to}`);
            // Success - close and return
            if (transporter) {
                transporter.close();
            }
            return;
        }
        catch (error) {
            console.error(`Email sending failed (attempt ${attempt}/${maxRetries}):`, error.message);
            if (error.code) {
                console.error(`Error code: ${error.code}, command: ${error.command || 'N/A'}`);
            }
            // Clean up transporter on error
            if (transporter) {
                try {
                    transporter.close();
                }
                catch (closeError) {
                    // Ignore close errors
                }
            }
            // If this is the last attempt, throw the error
            if (attempt === maxRetries) {
                throw error;
            }
            // Wait before retrying with exponential backoff
            const delay = retryDelay * attempt;
            console.log(`Retrying in ${delay}ms...`);
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
}
