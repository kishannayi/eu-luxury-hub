// EU Luxury Hub — Admin Email OTP (two-factor login)
// Vercel serverless function. Generates a one-time code on the SERVER, emails it to the
// owner via Resend, and verifies it. The code is NEVER sent to the browser, so even someone
// who can read the page source cannot get in without access to the owner's inbox.
//
// SETUP (Vercel → Settings → Environment Variables → add these → Redeploy):
//   RESEND_API_KEY = your Resend API key (starts with re_...)   free at https://resend.com
//   ADMIN_PASSWORD = euluxury2025      (keeps the password OUT of the public code)
//   ADMIN_EMAIL    = kishannayi30@gmail.com   (optional — defaults to this)
//
// Free Resend note: with no verified domain, Resend sends FROM onboarding@resend.dev and
// ONLY TO the email you signed up with. So sign up for Resend using ADMIN_EMAIL.
//
// If RESEND_API_KEY or ADMIN_PASSWORD are missing, this returns {error:"not_configured"}
// so the login page can safely fall back to password-only (owner is never locked out).

import crypto from 'node:crypto';

const OTP_TTL_MS = 10 * 60 * 1000;            // code valid for 10 minutes
const FROM = 'EU Luxury Hub <onboarding@resend.dev>';

function hmac(secret, msg) {
  return crypto.createHmac('sha256', secret).update(msg).digest('hex');
}
function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (e) { return res.status(400).json({ error: 'Invalid JSON' }); }
  }
  body = body || {};

  const RESEND_API_KEY = process.env.RESEND_API_KEY;
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'kishannayi30@gmail.com';

  // Not set up yet → let the page fall back to password-only login (no lockout).
  if (!RESEND_API_KEY || !ADMIN_PASSWORD) {
    console.log('[otp] NOT_CONFIGURED — RESEND_API_KEY present=' + (!!RESEND_API_KEY) + ', ADMIN_PASSWORD present=' + (!!ADMIN_PASSWORD));
    return res.status(200).json({ error: 'not_configured' });
  }
  const SECRET = RESEND_API_KEY; // server-only value, reused as the HMAC signing key

  const action = body.action;

  // ---- Step 1: password correct → email a fresh code, return a signed token (NOT the code)
  if (action === 'request') {
    const password = (body.password || '').toString();
    if (password !== ADMIN_PASSWORD) { console.log('[otp] request — WRONG password'); return res.status(401).json({ error: 'wrong_password' }); }
    console.log('[otp] request — password OK, sending code to ' + ADMIN_EMAIL);

    const code = '' + Math.floor(100000 + Math.random() * 900000); // 6 digits
    const expiry = Date.now() + OTP_TTL_MS;
    const sig = hmac(SECRET, code + '|' + expiry);
    const token = expiry + '.' + sig; // browser holds this; cannot be reversed to the code

    try {
      const er = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: FROM,
          to: [ADMIN_EMAIL],
          subject: 'EU Luxury Hub — Admin login code: ' + code,
          html: '<div style="font-family:Arial,Helvetica,sans-serif;background:#000;color:#fff;padding:30px;border-radius:12px;max-width:440px;margin:auto">'
              + '<div style="font-size:12px;letter-spacing:3px;color:#d6ff00;text-transform:uppercase;margin-bottom:14px">EU Luxury Hub &middot; Admin</div>'
              + '<div style="font-size:16px;color:#ccc;margin-bottom:18px">Your one-time login code:</div>'
              + '<div style="font-size:40px;font-weight:800;letter-spacing:10px;color:#d6ff00;background:#111;padding:18px;text-align:center;border-radius:8px">' + code + '</div>'
              + '<div style="font-size:13px;color:#888;margin-top:18px">Valid for 10 minutes. If this wasn\'t you, just ignore this email.</div>'
              + '</div>'
        })
      });
      if (!er.ok) {
        const ed = await er.json().catch(() => ({}));
        console.log('[otp] RESEND FAILED ' + er.status + ' — ' + JSON.stringify(ed).slice(0,300));
        return res.status(200).json({ error: 'email_failed', detail: (ed && (ed.message || ed.name)) || ('HTTP ' + er.status) });
      }
      console.log('[otp] RESEND OK — email sent to ' + ADMIN_EMAIL);
    } catch (e) {
      console.log('[otp] RESEND EXCEPTION — ' + (e.message || String(e)));
      return res.status(200).json({ error: 'email_failed', detail: e.message || String(e) });
    }

    return res.status(200).json({ ok: true, token });
  }

  // ---- Step 2: verify the code the owner typed against the signed token
  if (action === 'verify') {
    const token = (body.token || '').toString();
    const code = (body.code || '').toString().trim();
    const dot = token.indexOf('.');
    if (dot < 0) return res.status(400).json({ error: 'bad_token' });
    const expiry = Number(token.slice(0, dot));
    const sig = token.slice(dot + 1);
    if (!expiry || Date.now() > expiry) return res.status(200).json({ error: 'expired' });
    const expectSig = hmac(SECRET, code + '|' + expiry);
    if (!safeEqual(sig, expectSig)) return res.status(200).json({ error: 'wrong_code' });
    return res.status(200).json({ ok: true });
  }

  return res.status(400).json({ error: 'unknown_action' });
}
