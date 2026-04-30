import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
// Get directory name in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// Path to Mailchimp folder (one level up from backend/src)
const mailchimpDir = path.resolve(__dirname, "..", "..", "Mailchimp");
/** Replace Mailchimp merge tag so it doesn't show as literal text in inbox preview */
function replaceMailchimpPreviewText(html, previewText) {
    return html.replace(/\*\|\s*MC_PREVIEW_TEXT\s*\|\*/g, previewText);
}
/**
 * Get email verification template with original PNG images
 */
export function getEmailVerificationTemplate(opts) {
    const templatePath = path.join(mailchimpDir, "email-v16-mailchimp.html");
    if (!fs.existsSync(templatePath)) {
        console.error(`Template file not found: ${templatePath}`);
        return `<h2>Verify your email</h2><p><b>Verification code:</b> ${opts.verificationCode}</p><p>This code expires in 15 minutes.</p>`;
    }
    let html = fs.readFileSync(templatePath, "utf-8");
    // Replace verification code placeholder
    html = html.replace(/123456/g, opts.verificationCode);
    // Update expiration time to match actual expiration (15 minutes)
    html = html.replace(/This code will expire in 10 minutes\./g, "This code will expire in 15 minutes.");
    const appUrl = (process.env.APP_URL || "").trim().replace(/\/$/, "");
    // Replace ${appUrl} placeholder in HTML with actual base URL so image src URLs work
    if (appUrl) {
        html = html.replace(/\$\{appUrl\}/g, appUrl);
    }
    return replaceMailchimpPreviewText(html, "Verify your email address with the code we sent.");
}
/**
 * Get welcome email template with original PNG images (same method as verification email)
 */
export function getWelcomeEmailTemplate() {
    const templatePath = path.join(mailchimpDir, "email-v01-mailchimp.html");
    if (!fs.existsSync(templatePath)) {
        console.error(`Template file not found: ${templatePath}`);
        return `<h2>Welcome to RipCrack!</h2><p>We're excited to have you join our community.</p>`;
    }
    let html = fs.readFileSync(templatePath, "utf-8");
    const appUrl = (process.env.APP_URL || "").trim().replace(/\/$/, "");
    if (appUrl) {
        html = html.replace(/\$\{appUrl\}/g, appUrl);
    }
    // Replace "Subscribe Now" button link with APP_URL/pricing
    if (appUrl) {
        const subscribeLink = `${appUrl}/pricing`;
        if (html.includes("<!-- SUBSCRIBE_BUTTON_LINK -->")) {
            html = html.replace(/<!-- SUBSCRIBE_BUTTON_LINK -->[\s\S]*?href="[^"]*"[\s\S]*?<!-- END_SUBSCRIBE_BUTTON_LINK -->/g, (match) => {
                return match.replace(/href="[^"]*"/, `href="${escapeHtml(subscribeLink)}"`);
            });
        }
        else {
            // Fallback: replace href="#" target="_blank"
            html = html.replace(/href="#" target="_blank"/g, `href="${escapeHtml(subscribeLink)}" target="_blank"`);
        }
    }
    return replaceMailchimpPreviewText(html, "Welcome to RipCrack! We're glad to have you.");
}
/**
 * Get password reset email template with reset code (same method as verification email)
 */
export function getPasswordResetTemplate(opts) {
    const templatePath = path.join(mailchimpDir, "email-v04-mailchimp.html");
    if (!fs.existsSync(templatePath)) {
        console.error(`Template file not found: ${templatePath}`);
        return `<h2>Password reset</h2><p>You requested a password reset.</p><p><b>Reset code:</b> ${opts.resetCode}</p><p>This code expires in 1 hour.</p>`;
    }
    let html = fs.readFileSync(templatePath, "utf-8");
    const appUrl = (process.env.APP_URL || "").trim().replace(/\/$/, "");
    if (appUrl) {
        html = html.replace(/\$\{appUrl\}/g, appUrl);
    }
    // Update the description text
    html = html.replace(/Click the button below to reset your password\. This link is valid for 24 hours\. If you didn't request this, please ignore this email\./g, "Please use the reset code below to reset your password on RipCrack. This code will expire in 1 hour. If you didn't request this, please ignore this email.");
    // Replace the button section with reset code display (similar to verification code)
    const resetCodeDisplay = `																								<tr>
																									<td class="pb-35" style="padding-bottom: 35px;">
																										<table width="100%" border="0" cellspacing="0" cellpadding="0">
																											<tr>
																												<td class="verification-code" style="background-color: #f1f5f9; border: 2px dashed #10b981; border-radius: 10px; padding: 10px; text-align: center; font-size: 10px; font-weight: bold; letter-spacing: 1px; color: #282828; font-family: 'Courier New', monospace; word-break: break-all;">
																													<div mc:edit="text_4">
																														${opts.resetCode}
																													</div>
																												</td>
																											</tr>
																										</table>
																									</td>
																								</tr>
																								<tr>
																									<td class="text-14 lh-24 a-center c-grey" style="font-size:14px; color:#64748b; font-family:'PT Sans', Arial, sans-serif; min-width:auto !important; line-height: 24px; text-align:center;">
																										<div mc:edit="text_5">
																											If you didn't request this code, please ignore this email or contact our support team if you have concerns.
																										</div>
																									</td>
																								</tr>`;
    // Replace the button section with reset code display
    html = html.replace(/<tr>\s*<td align="center">\s*<!-- Button -->[\s\S]*?<!-- END Button -->\s*<\/td>\s*<\/tr>/g, resetCodeDisplay);
    return replaceMailchimpPreviewText(html, "Use the code below to reset your password on RipCrack.");
}
/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(s) {
    return String(s || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
/**
 * Format price string - handles "Price on request" and numeric prices
 */
function formatPrice(price) {
    if (!price || price === "Price on request" || price.trim() === "") {
        return "Price on request";
    }
    // If it's already formatted with $, return as is
    if (price.includes("$")) {
        return price;
    }
    // Try to parse as number and format
    const num = parseFloat(price);
    if (!isNaN(num)) {
        return `$${num.toFixed(2)}`;
    }
    return price;
}
/**
 * Format product image URL to use APP_URL/api/uploads/filename
 * Product "cover" may come from product.images[0] (path like /api/uploads/xxx.jpg).
 */
function formatProductImageUrl(cover) {
    const rawAppUrl = (process.env.APP_URL || "").trim();
    const appUrl = rawAppUrl.replace(/\/+$/, ""); // no trailing slash to avoid double slashes
    const placeholder = "https://i.ibb.co/placeholder.png";
    if (!cover || cover.trim() === "") {
        return placeholder;
    }
    const trimmedCover = cover.trim();
    // If it's already a full URL (http:// or https://), return as is
    if (trimmedCover.startsWith("http://") || trimmedCover.startsWith("https://")) {
        return trimmedCover;
    }
    // If APP_URL is not set, use placeholder
    if (!appUrl) {
        console.warn("APP_URL environment variable is not set. Using placeholder image.");
        return placeholder;
    }
    // Remove leading slash if present
    const cleanPath = trimmedCover.startsWith("/") ? trimmedCover.slice(1) : trimmedCover;
    // If it already starts with "api/uploads/", just prepend APP_URL
    if (cleanPath.startsWith("api/uploads/")) {
        return `${appUrl}/${cleanPath}`;
    }
    // If it's just a filename (contains a dot but no slashes), add api/uploads/
    if (cleanPath.includes(".") && !cleanPath.includes("/")) {
        return `${appUrl}/api/uploads/${cleanPath}`;
    }
    // If it contains slashes, assume it's a relative path and prepend APP_URL
    if (cleanPath.includes("/")) {
        return `${appUrl}/${cleanPath}`;
    }
    // Default: treat as filename and add api/uploads/
    return `${appUrl}/api/uploads/${cleanPath}`;
}
/**
 * Get order confirmation email template
 */
export function getOrderConfirmationTemplate(opts) {
    const templatePath = path.join(mailchimpDir, "email-v14-mailchimp.html");
    if (!fs.existsSync(templatePath)) {
        console.error(`Template file not found: ${templatePath}`);
        return `<h2>Order Confirmation</h2><p><b>Order ID:</b> ${opts.orderId}</p><p>Thank you for your order!</p>`;
    }
    let html = fs.readFileSync(templatePath, "utf-8");
    const appUrl = (process.env.APP_URL || "").trim().replace(/\/$/, "");
    if (appUrl) {
        html = html.replace(/\$\{appUrl\}/g, appUrl);
    }
    html = replaceMailchimpPreviewText(html, "Thank you for your order. View your order details and tracking inside.");
    // Replace order number
    html = html.replace(/#123456/g, `#${opts.orderId}`);
    // Replace tracking link using the marker we added to the template
    const trackLink = appUrl ? `${appUrl}/account` : "";
    const trackButtonPattern = /<!-- TRACK_BUTTON_LINK -->[\s\S]*?href="[^"]*"[\s\S]*?<!-- END_TRACK_BUTTON_LINK -->/g;
    if (trackButtonPattern.test(html) && appUrl) {
        html = html.replace(trackButtonPattern, (match) => {
            return match.replace(/href="[^"]*"/, `href="${escapeHtml(trackLink)}"`);
        });
    }
    else if (appUrl) {
        // Fallback: replace any href="#" near "TRACK MY PACKAGE"
        html = html.replace(/href="#" target="_blank"/g, `href="${escapeHtml(trackLink)}" target="_blank"`);
    }
    // Calculate delivery date (3-5 business days from now)
    const deliveryDate = new Date();
    deliveryDate.setDate(deliveryDate.getDate() + 3);
    const deliveryDateEnd = new Date();
    deliveryDateEnd.setDate(deliveryDateEnd.getDate() + 5);
    const deliveryDateStr = `${String(deliveryDate.getMonth() + 1).padStart(2, "0")}/${String(deliveryDate.getDate()).padStart(2, "0")} – ${String(deliveryDateEnd.getMonth() + 1).padStart(2, "0")}/${String(deliveryDateEnd.getDate()).padStart(2, "0")}/${String(deliveryDateEnd.getFullYear()).slice(-2)}`;
    html = html.replace(/04\/22 – 04\/25\/18/g, deliveryDateStr);
    // Replace shipping details
    // Format: Name<br />ZIP<br />Street<br />City, Country
    const shippingAddress = `${escapeHtml(opts.customerName || "")}<br />${escapeHtml(opts.zip || "")}<br />${escapeHtml(opts.street || "")}<br />${escapeHtml(opts.city || "")}, ${escapeHtml(opts.country || "")}`.trim();
    // Replace the shipping details - match the content inside the div with mc:edit="text_9"
    // Template format has newlines and spaces: "Daniel Bergamot <br />3409 S. Canondale Road <br />Chicago, IL 60301"
    // Use a more flexible pattern that handles all whitespace variations
    const shippingDetailsPattern = /(<div[^>]*mc:edit="text_9"[^>]*>[\s]*)Daniel Bergamot[\s]*<br\s*\/>[\s]*3409 S\.\s*Canondale Road[\s]*<br\s*\/>[\s]*Chicago,\s*IL\s*60301([\s]*<\/div>)/g;
    if (shippingDetailsPattern.test(html)) {
        html = html.replace(shippingDetailsPattern, `$1${shippingAddress}$2`);
    }
    else {
        // Fallback: try matching just the content without the div tags (more flexible)
        html = html.replace(/Daniel Bergamot[\s]*<br\s*\/>[\s]*3409 S\.\s*Canondale Road[\s]*<br\s*\/>[\s]*Chicago,\s*IL\s*60301/g, shippingAddress);
    }
    // Generate order items HTML (use per-item productType when present for mixed cart)
    let orderItemsHtml = "";
    let subtotal = 0;
    const hasNumericPrices = opts.orderItems.some((item) => {
        const type = item.productType || opts.selectedType;
        const price = type === "Business" ? (item.product.businessPrice || item.product.price) : (item.product.personalPrice || item.product.price);
        return price && price !== "Price on request" && !isNaN(parseFloat(price));
    });
    opts.orderItems.forEach((item, index) => {
        const itemType = item.productType || opts.selectedType;
        const productPrice = itemType === "Business"
            ? (item.product.businessPrice || item.product.price)
            : (item.product.personalPrice || item.product.price);
        const priceStr = formatPrice(productPrice);
        const priceNum = productPrice && productPrice !== "Price on request" ? parseFloat(productPrice) * item.qty : 0;
        if (!isNaN(priceNum)) {
            subtotal += priceNum;
        }
        const productImage = formatProductImageUrl(item.product.cover);
        const productTitle = escapeHtml(item.product.title || "Product");
        const productDescription = escapeHtml(item.product.description || "Professional software license with fast email delivery and full support.");
        // Generate product item HTML (replicate the structure from template)
        // Note: Product images should NOT have links
        const itemHtml = `																								<tr>
																									<td class="pb-30" style="padding-bottom: 30px;">
																										<table width="100%" border="0" cellspacing="0" cellpadding="0">
																											<tr>
																												<th class="column-top" valign="top" width="230" style="font-size:0pt; line-height:0pt; padding:0; margin:0; font-weight:normal; vertical-align:top;">
																													<div class="fluid-img" style="font-size:0pt; line-height:0pt; text-align:left;"><img src="${escapeHtml(productImage)}" border="0" width="230" height="180" mc:edit="image_${index + 3}" style="max-width:230px;" alt="${productTitle}" /></div>
																												</th>
																												<th class="column-top mpb-15" valign="top" width="30" style="font-size:0pt; line-height:0pt; padding:0; margin:0; font-weight:normal; vertical-align:top;"></th>
																												<th class="column-top" valign="top" style="font-size:0pt; line-height:0pt; padding:0; margin:0; font-weight:normal; vertical-align:top;">
																													<table width="100%" border="0" cellspacing="0" cellpadding="0">
																														<tr>
																															<td class="title-20 pb-10" style="font-size:20px; line-height:24px; color:#282828; font-family:'PT Sans', Arial, sans-serif; text-align:left; min-width:auto !important; padding-bottom: 10px;">
																																<div mc:edit="text_${11 + index * 2}">
																																	<strong>${productTitle}</strong>
																																</div>
																															</td>
																														</tr>
																														<tr>
																															<td class="text-16 lh-26 pb-15" style="font-size:16px; color:#64748b; font-family:'PT Sans', Arial, sans-serif; text-align:left; min-width:auto !important; line-height: 26px; padding-bottom: 15px;">
																																
																															</td>
																														</tr>
																														<tr>
																															<td class="text-16 lh-26 c-black" style="font-size:16px; font-family:'PT Sans', Arial, sans-serif; text-align:left; min-width:auto !important; line-height: 26px; color:#282828;">
																																<div mc:edit="text_${13 + index * 2}">
																																	<strong>Type:</strong> ${escapeHtml(itemType)}
																																	<br />
																																	<strong>Term:</strong> ${escapeHtml(opts.purchaseTerm)}
																																	<br />
																																	<strong>Qty:</strong> ${item.qty}
																																	<br />
																																	<strong>Price:</strong> ${priceStr}
																																</div>
																															</td>
																														</tr>
																													</table>
																												</th>
																											</tr>
																										</table>
																									</td>
																								</tr>`;
        orderItemsHtml += itemHtml;
    });
    // Replace all product items using the clear markers we added to the template
    // The template now has <!-- START_SAMPLE_PRODUCTS --> and <!-- END_SAMPLE_PRODUCTS --> markers
    const startMarker = '<!-- START_SAMPLE_PRODUCTS -->';
    const endMarker = '<!-- END_SAMPLE_PRODUCTS -->';
    const startPos = html.indexOf(startMarker);
    const endPos = html.indexOf(endMarker);
    if (startPos !== -1 && endPos !== -1 && endPos > startPos) {
        // Replace everything between the markers with our real order items
        const beforeProducts = html.substring(0, startPos);
        const afterProducts = html.substring(endPos + endMarker.length);
        html = beforeProducts + orderItemsHtml + afterProducts;
    }
    else {
        // Fallback: use the old method if markers aren't found
        const orderDetailsMarker = '<strong>Order details</strong>';
        const orderDetailsPos = html.indexOf(orderDetailsMarker);
        if (orderDetailsPos !== -1) {
            const afterOrderDetails = html.substring(orderDetailsPos);
            const firstProductMarker = '<tr>\n																									<td class="pb-30" style="padding-bottom: 30px;">';
            const firstProductPos = afterOrderDetails.indexOf(firstProductMarker);
            if (firstProductPos !== -1) {
                const separatorMarker = '<tr>\n																								<td class="pt-10 pb-40"';
                const separatorPos = afterOrderDetails.indexOf(separatorMarker, firstProductPos);
                if (separatorPos !== -1) {
                    const beforeProducts = html.substring(0, orderDetailsPos + firstProductPos);
                    const afterProducts = html.substring(orderDetailsPos + separatorPos);
                    html = beforeProducts + orderItemsHtml + afterProducts;
                }
            }
        }
    }
    // Remove ALL remaining template products that weren't replaced
    // This ensures no sample/template products remain in the email
    // We identify template products by their content, not just markers (since real products use same markers)
    const templateProductPatterns = [
        // Remove products with "Product Name" (template default text) - this is the key identifier
        /<tr>\s*<td class="pb-30" style="padding-bottom: 30px;">[\s\S]*?<strong>Product Name<\/strong>[\s\S]*?<\/tr>\s*<\/table>\s*<\/td>\s*<\/tr>\s*/g,
        // Remove products with "Color:" in details (template uses "Color:" while real products use "Type:")
        /<tr>\s*<td class="pb-30" style="padding-bottom: 30px;">[\s\S]*?<strong>Color:<\/strong>[\s\S]*?<\/tr>\s*<\/table>\s*<\/td>\s*<\/tr>\s*/g,
        // Remove products with placeholder image paths (template uses ../images/img_product.jpg)
        /<tr>\s*<td class="pb-30" style="padding-bottom: 30px;">[\s\S]*?\.\.\/images\/img_product\.jpg[\s\S]*?<\/tr>\s*<\/table>\s*<\/td>\s*<\/tr>\s*/g,
    ];
    templateProductPatterns.forEach(pattern => {
        html = html.replace(pattern, '');
    });
    // Use orderSummary from checkout when provided; otherwise compute from items
    const useOrderSummary = opts.orderSummary && typeof opts.orderSummary.subtotal === "number" && typeof opts.orderSummary.total === "number";
    const shipping = 0; // Free shipping
    const summarySubtotal = useOrderSummary ? opts.orderSummary.subtotal : subtotal;
    const summaryDiscount = useOrderSummary ? (opts.orderSummary.discount ?? 0) : 0;
    const summaryTotal = useOrderSummary ? opts.orderSummary.total : (subtotal + shipping + (hasNumericPrices ? subtotal * 0.015 : 0));
    const tax = useOrderSummary ? 0 : (hasNumericPrices ? subtotal * 0.015 : 0);
    const hasNumericSummary = useOrderSummary || hasNumericPrices;
    // Replace payment method (since this is email confirmation, no payment method)
    html = html.replace(/Mastercard ending in 4097/g, "Email confirmation (No payment required)");
    // Insert Discount row after Subtotal when discount > 0 (before Shipping row)
    if (summaryDiscount > 0 && hasNumericSummary) {
        const discountRow = `<tr>
																																		<td class="title-20 lh-30 a-right mt-left" style="font-size:20px; color:#282828; font-family:'PT Sans', Arial, sans-serif; min-width:auto !important; line-height: 30px; text-align:right;">
																																			<div mc:edit="text_discount">
																																				<strong>Discount:</strong>
																																			</div>
																																		</td>
																																		<td class="img mw-15" width="20" style="font-size:0pt; line-height:0pt; text-align:left;"></td>
																																		<td class="title-20 lh-30 mt-right" style="font-size:20px; color:#22c55e; font-family:'PT Sans', Arial, sans-serif; text-align:left; min-width:auto !important; line-height: 30px;">
																																			<div mc:edit="text_discount_val">
																																				-$${summaryDiscount.toFixed(2)}
																																			</div>
																																		</td>
																																	</tr>
																																	`;
        // Match Subtotal row end (</tr>) followed by Shipping row start
        const afterSubtotalBeforeShipping = html.indexOf("<strong>Subtotal:</strong>");
        if (afterSubtotalBeforeShipping !== -1) {
            const afterSubtotalTr = html.indexOf("</tr>", html.indexOf("text_20", afterSubtotalBeforeShipping));
            const shippingTrStart = html.indexOf("<tr>", afterSubtotalTr + 1);
            const shippingLabel = html.indexOf("<strong>Shipping:</strong>", afterSubtotalTr);
            if (afterSubtotalTr !== -1 && shippingTrStart !== -1 && shippingLabel !== -1) {
                html = html.slice(0, afterSubtotalTr + 5) + discountRow + html.slice(afterSubtotalTr + 5);
            }
        }
    }
    // Replace price totals (Subtotal, Shipping, Tax, TOTAL)
    if (hasNumericSummary) {
        html = html.replace(/\$290\.99/g, (match, offset) => {
            const firstIdx = html.indexOf("$290.99");
            if (offset === firstIdx)
                return `$${summarySubtotal.toFixed(2)}`;
            return `$${summaryTotal.toFixed(2)}`;
        });
        html = html.replace(/\$0\.00/g, `$${shipping.toFixed(2)}`);
        html = html.replace(/\$4\.32/g, useOrderSummary ? "$0.00" : `$${tax.toFixed(2)}`);
    }
    else {
        html = html.replace(/\$290\.99/g, "Price on request");
        html = html.replace(/\$0\.00/g, "$0.00");
        html = html.replace(/\$4\.32/g, "N/A");
    }
    return html;
}
/**
 * Get "order confirmed by admin" email template (email-v17: "Your order is confirmed")
 * Used when admin clicks Confirm on an order.
 */
export function getOrderConfirmedByAdminTemplate(opts) {
    const templatePath = path.join(mailchimpDir, "email-v17-mailchimp.html");
    if (!fs.existsSync(templatePath)) {
        console.error(`Template file not found: ${templatePath}`);
        return `<h2>Order Confirmed</h2><p><b>Order ID:</b> ${opts.orderId}</p><p>Your order has been confirmed. <a href="${escapeHtml(opts.trackingLink)}">View your order</a>.</p>`;
    }
    let html = fs.readFileSync(templatePath, "utf-8");
    const appUrl = (process.env.APP_URL || "").trim().replace(/\/$/, "");
    if (appUrl) {
        html = html.replace(/\$\{appUrl\}/g, appUrl);
    }
    html = replaceMailchimpPreviewText(html, "Your order is confirmed. View your order details inside.");
    // Replace VIEW ORDER button link (template has single href="#")
    html = html.replace(/href="#"/g, `href="${escapeHtml(opts.trackingLink)}"`);
    return html;
}
/**
 * Get order cancellation email template
 */
export function getOrderCancellationTemplate(opts) {
    const templatePath = path.join(mailchimpDir, "email-v15-mailchimp.html");
    const isRejection = opts.isRejection === true;
    if (!fs.existsSync(templatePath)) {
        console.error(`Template file not found: ${templatePath}`);
        if (isRejection) {
            return `<h2>Order Rejected</h2><p><b>Order ID:</b> ${opts.orderId}</p><p>Your order has been successfully Rejected.</p>`;
        }
        return `<h2>Order Cancelled</h2><p><b>Order ID:</b> ${opts.orderId}</p><p>Your order has been successfully cancelled.</p>`;
    }
    let html = fs.readFileSync(templatePath, "utf-8");
    const appUrl = (process.env.APP_URL || "").trim().replace(/\/$/, "");
    if (appUrl) {
        html = html.replace(/\$\{appUrl\}/g, appUrl);
    }
    const previewText = isRejection
        ? "Your order has been Rejected. Browse our shop for more products."
        : "Your order has been cancelled. Browse our shop for more products.";
    html = replaceMailchimpPreviewText(html, previewText);
    // Replace order number
    html = html.replace(/#123456/g, `#${opts.orderId}`);
    // Replace cancellation date
    const cancellationDateStr = `${String(opts.cancellationDate.getMonth() + 1).padStart(2, "0")}/${String(opts.cancellationDate.getDate()).padStart(2, "0")}/${opts.cancellationDate.getFullYear()}`;
    html = html.replace(/01\/03\/2026/g, cancellationDateStr);
    // Replace "Browse Catalog" button link using the marker we added to the template
    const browseButtonPattern = /<!-- BROWSE_BUTTON_LINK -->[\s\S]*?href="[^"]*"[\s\S]*?<!-- END_BROWSE_BUTTON_LINK -->/g;
    if (browseButtonPattern.test(html) && appUrl) {
        const browseLink = `${appUrl}/shop`;
        html = html.replace(browseButtonPattern, (match) => {
            return match.replace(/href="[^"]*"/, `href="${escapeHtml(browseLink)}"`);
        });
    }
    else {
        // Fallback: replace any href with ripcrack.net
        if (appUrl) {
            const browseLink = `${appUrl}/shop`;
            html = html.replace(/href="https:\/\/ripcrack\.net[^"]*" target="_blank"/g, `href="${browseLink}" target="_blank"`);
        }
        else {
            html = html.replace(/href="https:\/\/ripcrack\.net" target="_blank"/g, 'href="https://ripcrack.net/shop" target="_blank"');
        }
    }
    // Generate cancelled items HTML
    let cancelledItemsHtml = "";
    let subtotal = 0;
    const hasNumericPrices = opts.orderItems.some((item) => {
        const price = opts.selectedType === "Business" ? (item.product.businessPrice || item.product.price) : (item.product.personalPrice || item.product.price);
        return price && price !== "Price on request" && !isNaN(parseFloat(price));
    });
    opts.orderItems.forEach((item, index) => {
        const productPrice = opts.selectedType === "Business"
            ? (item.product.businessPrice || item.product.price)
            : (item.product.personalPrice || item.product.price);
        const priceStr = formatPrice(productPrice);
        const priceNum = productPrice && productPrice !== "Price on request" ? parseFloat(productPrice) * item.qty : 0;
        if (!isNaN(priceNum)) {
            subtotal += priceNum;
        }
        const productImage = formatProductImageUrl(item.product.cover);
        const productTitle = escapeHtml(item.product.title || "Product");
        const productDescription = escapeHtml(item.product.description || "Professional software license with fast email delivery and full support.");
        // Generate cancelled item HTML
        // Note: Product images should NOT have links
        const itemHtml = `																								<tr>
																									<td class="pb-30" style="padding-bottom: 30px;">
																										<table width="100%" border="0" cellspacing="0" cellpadding="0">
																											<tr>
																												<th class="column-top" valign="top" width="230" style="font-size:0pt; line-height:0pt; padding:0; margin:0; font-weight:normal; vertical-align:top;">
																													<div class="fluid-img" style="font-size:0pt; line-height:0pt; text-align:left;"><img src="${escapeHtml(productImage)}" border="0" width="230" height="180" mc:edit="image_${index + 3}" style="max-width:230px;" alt="${productTitle}" /></div>
																												</th>
																												<th class="column-top mpb-15" valign="top" width="30" style="font-size:0pt; line-height:0pt; padding:0; margin:0; font-weight:normal; vertical-align:top;"></th>
																												<th class="column-top" valign="top" style="font-size:0pt; line-height:0pt; padding:0; margin:0; font-weight:normal; vertical-align:top;">
																													<table width="100%" border="0" cellspacing="0" cellpadding="0">
																														<tr>
																															<td class="title-20 pb-10" style="font-size:20px; line-height:24px; color:#282828; font-family:'PT Sans', Arial, sans-serif; text-align:left; min-width:auto !important; padding-bottom: 10px;">
																																<div mc:edit="text_${11 + index * 2}">
																																	<strong>${productTitle}</strong>
																																</div>
																															</td>
																														</tr>
																														<tr>
																															<td class="text-16 lh-26 pb-15" style="font-size:16px; color:#64748b; font-family:'PT Sans', Arial, sans-serif; text-align:left; min-width:auto !important; line-height: 26px; padding-bottom: 15px;">
																															</td>
																														</tr>
																														<tr>
																															<td class="text-16 lh-26 c-black" style="font-size:16px; font-family:'PT Sans', Arial, sans-serif; text-align:left; min-width:auto !important; line-height: 26px; color:#282828;">
																																<div mc:edit="text_${13 + index * 2}">
																																	<strong>Type:</strong> ${escapeHtml(opts.selectedType)}
																																	<br />
																																	<strong>Term:</strong> ${escapeHtml(opts.purchaseTerm)}
																																	<br />
																																	<strong>Qty:</strong> ${item.qty}
																																	<br />
																																	<strong>Price:</strong> ${priceStr}
																																</div>
																															</td>
																														</tr>
																													</table>
																																				</th>
																																			</tr>
																																		</table>
																																	</td>
																																</tr>`;
        cancelledItemsHtml += itemHtml;
    });
    // Replace cancelled items section using the clear markers we added to the template
    // The template now has <!-- START_SAMPLE_PRODUCTS --> and <!-- END_SAMPLE_PRODUCTS --> markers
    const startMarker = '<!-- START_SAMPLE_PRODUCTS -->';
    const endMarker = '<!-- END_SAMPLE_PRODUCTS -->';
    const startPos = html.indexOf(startMarker);
    const endPos = html.indexOf(endMarker);
    if (startPos !== -1 && endPos !== -1 && endPos > startPos) {
        // Replace everything between the markers with our real cancelled items
        const beforeItems = html.substring(0, startPos);
        const afterItems = html.substring(endPos + endMarker.length);
        html = beforeItems + cancelledItemsHtml + afterItems;
    }
    else {
        // Fallback: use the old method if markers aren't found
        const cancelledItemsMarker = '<strong>Cancelled items</strong>';
        const cancelledItemsPos = html.indexOf(cancelledItemsMarker);
        if (cancelledItemsPos !== -1) {
            const afterCancelledItems = html.substring(cancelledItemsPos);
            const firstItemMarker = '<tr>\n																									<td class="pb-30" style="padding-bottom: 30px;">';
            const firstItemPos = afterCancelledItems.indexOf(firstItemMarker);
            if (firstItemPos !== -1) {
                const separatorMarker = '<tr>\n																								<td class="pt-10 pb-40"';
                const separatorPos = afterCancelledItems.indexOf(separatorMarker, firstItemPos);
                if (separatorPos !== -1) {
                    const beforeItems = html.substring(0, cancelledItemsPos + firstItemPos);
                    const afterItems = html.substring(cancelledItemsPos + separatorPos);
                    html = beforeItems + cancelledItemsHtml + afterItems;
                }
            }
        }
    }
    // Remove ALL remaining template products that weren't replaced
    // This ensures no sample/template products remain in the email
    // We identify template products by their content, not just markers (since real products use same markers)
    const templateProductPatterns = [
        // Remove products with "Product Name" (template default text) - this is the key identifier
        /<tr>\s*<td class="pb-30" style="padding-bottom: 30px;">[\s\S]*?<strong>Product Name<\/strong>[\s\S]*?<\/tr>\s*<\/table>\s*<\/td>\s*<\/tr>\s*/g,
        // Remove products with "Color:" in details (template uses "Color:" while real products use "Type:")
        /<tr>\s*<td class="pb-30" style="padding-bottom: 30px;">[\s\S]*?<strong>Color:<\/strong>[\s\S]*?<\/tr>\s*<\/table>\s*<\/td>\s*<\/tr>\s*/g,
        // Remove products with placeholder image paths (template uses ../images/img_product.jpg)
        /<tr>\s*<td class="pb-30" style="padding-bottom: 30px;">[\s\S]*?\.\.\/images\/img_product\.jpg[\s\S]*?<\/tr>\s*<\/table>\s*<\/td>\s*<\/tr>\s*/g,
    ];
    templateProductPatterns.forEach(pattern => {
        html = html.replace(pattern, '');
    });
    // Use order summary from order when available (so Subtotal, Discount, REFUND TOTAL show real values)
    const tax = (opts.orderSummary != null ? 0 : (hasNumericPrices ? subtotal * 0.015 : 0)); // when using order total, tax is already in refund total
    const useOrderSummary = opts.orderSummary != null && Number.isFinite(opts.orderSummary.subtotal) && Number.isFinite(opts.orderSummary.refundTotal);
    const summarySubtotal = useOrderSummary ? opts.orderSummary.subtotal : subtotal;
    const summaryDiscount = useOrderSummary ? (opts.orderSummary.discount ?? 0) : 0;
    const summaryRefundTotal = useOrderSummary ? opts.orderSummary.refundTotal : (subtotal + tax);
    const hasNumericSummary = useOrderSummary || hasNumericPrices;
    // Replace payment method (since this is email confirmation, no payment method)
    html = html.replace(/Mastercard ending in 4097/g, "Email confirmation (No payment required)");
    // Insert Discount row after Subtotal when discount > 0 (before Tax row)
    if (summaryDiscount > 0 && hasNumericSummary) {
        const discountRow = `<tr>
																																		<td class="title-20 lh-30 a-right mt-left" style="font-size:20px; color:#282828; font-family:'PT Sans', Arial, sans-serif; min-width:auto !important; line-height: 30px; text-align:right;">
																																			<div mc:edit="text_discount">
																																				<strong>Discount:</strong>
																																			</div>
																																		</td>
																																		<td class="img mw-15" width="20" style="font-size:0pt; line-height:0pt; text-align:left;"></td>
																																		<td class="title-20 lh-30 mt-right" style="font-size:20px; color:#22c55e; font-family:'PT Sans', Arial, sans-serif; text-align:left; min-width:auto !important; line-height: 30px;">
																																			<div mc:edit="text_discount_val">
																																				-$${summaryDiscount.toFixed(2)}
																																			</div>
																																		</td>
																																	</tr>
																																	`;
        const afterSubtotalLabel = html.indexOf("<strong>Subtotal:</strong>");
        if (afterSubtotalLabel !== -1) {
            const afterSubtotalTr = html.indexOf("</tr>", html.indexOf("text_20", afterSubtotalLabel));
            const taxLabel = html.indexOf("<strong>Tax:</strong>", afterSubtotalTr);
            if (afterSubtotalTr !== -1 && taxLabel !== -1) {
                html = html.slice(0, afterSubtotalTr + 5) + discountRow + html.slice(afterSubtotalTr + 5);
            }
        }
    }
    // Replace price totals (Subtotal, Tax, REFUND TOTAL)
    if (hasNumericSummary) {
        html = html.replace(/\$290\.99/, `$${summarySubtotal.toFixed(2)}`);
        html = html.replace(/\$4\.32/g, useOrderSummary ? "N/A" : `$${tax.toFixed(2)}`);
        html = html.replace(/\$295\.31/g, `$${summaryRefundTotal.toFixed(2)}`);
        // Replace possible <strong>$295.31</strong> as well
        html = html.replace(/\$295\.31/g, `$${summaryRefundTotal.toFixed(2)}`);
    }
    else {
        html = html.replace(/\$290\.99/g, "Price on request");
        html = html.replace(/\$4\.32/g, "N/A");
        html = html.replace(/\$295\.31/g, "Price on request");
    }
    // For admin rejection emails, use "Rejected" / "Rejection" wording instead of "Cancelled" / "Cancellation"
    if (isRejection) {
        html = html.replace(/Order Cancelled/g, "Order Rejected");
        html = html.replace(/successfully cancelled\./g, "successfully Rejected.");
        html = html.replace(/Cancellation date/g, "Rejection date");
        html = html.replace(/Cancelled items/g, "Rejected items");
    }
    return html;
}
