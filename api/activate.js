const crypto = require("crypto");

function hmac(value, secret) {
  return crypto.createHmac("sha256", secret).update(value).digest("hex");
}
function safeEqual(a,b) {
  if (!a || !b || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
function base64url(value) {
  return Buffer.from(value).toString("base64").replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
}
function issueLicense(paymentId, referenceId) {
  const now = Math.floor(Date.now()/1000);
  const payload = {v:1, sub:paymentId, ref:referenceId || "", iat:now, exp:now + 31536000};
  const body = base64url(JSON.stringify(payload));
  const sig = hmac(body, process.env.LICENSE_SECRET);
  return body + "." + base64url(Buffer.from(sig, "hex"));
}
function pageError(message) {
  return new Response(`<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>CLADHABITS Access</title><style>body{font-family:system-ui;background:#0b1020;color:#fff;display:grid;place-items:center;min-height:100vh;padding:24px}.c{max-width:520px;text-align:center;background:#11182b;border:1px solid #27304a;border-radius:20px;padding:32px}p{color:#aeb8cf;line-height:1.6}</style><div class="c"><h1>Access not ready</h1><p>${message}</p><p>Please return to the CLADHABITS payment page or contact support.</p></div>`, {status:400, headers:{"content-type":"text/html; charset=utf-8"}});
}

export default async function handler(req, res) {
  try {
    const q = new URL(req.url, "https://cladhabits.vercel.app").searchParams;
    const paymentId = q.get("razorpay_payment_id");
    const linkId = q.get("razorpay_payment_link_id");
    const referenceId = q.get("razorpay_payment_link_reference_id") || "";
    const linkStatus = q.get("razorpay_payment_link_status") || "";
    const signature = q.get("razorpay_signature");

    if (!process.env.LICENSE_SECRET || !process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
      return res.status(503).send("CLADHABITS access system is waiting for Razorpay/Vercel configuration.");
    }
    if (!paymentId || !linkId || !signature || linkStatus !== "paid") {
      return res.status(400).send("Payment confirmation was incomplete.");
    }

    const expected = hmac(linkId + "|" + referenceId + "|" + linkStatus + "|" + paymentId, process.env.RAZORPAY_KEY_SECRET);
    if (!safeEqual(expected, signature)) {
      return res.status(403).send("Payment verification failed.");
    }

    const auth = Buffer.from(process.env.RAZORPAY_KEY_ID + ":" + process.env.RAZORPAY_KEY_SECRET).toString("base64");
    const r = await fetch("https://api.razorpay.com/v1/payment_links/" + encodeURIComponent(linkId), {
      headers: {Authorization:"Basic " + auth}
    });
    if (!r.ok) return res.status(502).send("Could not verify the payment with Razorpay.");
    const link = await r.json();
    if (link.status !== "paid" || Number(link.amount_paid || 0) <= 0) {
      return res.status(403).send("Payment is not confirmed as paid.");
    }

    const token = issueLicense(paymentId, referenceId);
    const cookie = "clad_license=" + token + "; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax";
    return res.setHeader("Set-Cookie", cookie), res.redirect(302, "/app.html");
  } catch (e) {
    console.error("CLADHABITS activation error", e);
    return res.status(500).send("Activation failed. Please contact CLADHABITS support.");
  }
}
