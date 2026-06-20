// EU Luxury Hub — Admin Email OTP (two-factor login) + password management
// Vercel serverless function.
//
//  • action 'request'      → checks password, emails a 6-digit code, returns a signed token
//  • action 'verify'       → verifies the emailed code against the token
//  • action 'set_password' → owner changes the admin password (stored hashed in Supabase)
//
// The emailed code is NEVER sent to the browser, so reading the page source is not enough
// to get in — you also need access to the owner's inbox. That email step is the real lock.
//
// PASSWORD SOURCES (a login password is accepted if it matches EITHER):
//   1. ADMIN_PASSWORD env var  → permanent master / recovery key (set in Vercel, stays private,
//      so the owner can NEVER be locked out even if the stored password is changed or wiped).
//   2. The hashed password stored in Supabase (table "site", row key='security'), which the
//      owner can change any time from the admin panel.
//
// ENV VARS (Vercel → Settings → Environment Variables → Production → Redeploy):
//   RESEND_API_KEY = re_...            (email sending + HMAC signing key)
//   ADMIN_PASSWORD = euluxury2025      (master/recovery password — keep private)
//   ADMIN_EMAIL    = kishannayi30@gmail.com   (optional, defaults to this)

import crypto from 'node:crypto';

const OTP_TTL_MS = 10 * 60 * 1000;            // code valid for 10 minutes
const FROM = 'EU Luxury Hub <onboarding@resend.dev>';

// Supabase (publishable values — safe to keep in code; same key the storefront uses)
const SUPABASE_URL = 'https://nymycljtgnzjzimpnzeq.supabase.co';
const SUPABASE_KEY = 'sb_publishable_s0GQkAWcCC1R3xQdrB_-2Q_FVf3YSaR';

function hmac(secret, msg) {
  return crypto.createHmac('sha256', secret).update(msg).digest('hex');
}
function sha256(salt, pw) {
  return crypto.createHash('sha256').update(salt + ':' + pw).digest('hex');
}
function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// Read the stored password record {salt, hash} from Supabase (or null if none yet)
async function getStoredSecurity() {
  try {
    const r = await fetch(SUPABASE_URL + '/rest/v1/site?key=eq.security&select=value', {
      headers: { apikey: SUPABASE_KEY, Authorization: 'Bearer ' + SUPABASE_KEY }
    });
    if (!r.ok) return null;
    const arr = await r.json().catch(() => []);
    let v = Array.isArray(arr) && arr[0] ? arr[0].value : null;
    if (typeof v === 'string') { try { v = JSON.parse(v); } catch (_) { v = null; } }
    return (v && v.salt && v.hash) ? v : null;
  } catch (_) { return null; }
}

// Save the new password record to Supabase (upsert on key)
async function storeSecurity(rec) {
  const r = await fetch(SUPABASE_URL + '/rest/v1/site', {
    method: 'POST',
    headers: {
      apikey: SUPABASE_KEY,
      Authorization: 'Bearer ' + SUPABASE_KEY,
      'Content-Type': 'application/json',
      Prefer: 'resolution=merge-duplicates,return=minimal'
    },
    body: JSON.stringify([{ key: 'security', value: rec }])
  });
  return r.ok;
}

// A password is valid if it matches the env master OR the stored hashed password
async function validatePassword(pw, ADMIN_PASSWORD) {
  pw = (pw || '').toString();
  if (!pw) return false;
  if (ADMIN_PASSWORD && safeEqual(pw, ADMIN_PASSWORD)) return true;   // master / recovery
  const sec = await getStoredSecurity();
  if (sec) { try { return safeEqual(sha256(sec.salt, pw), sec.hash); } catch (_) { return false; } }
  return false;
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
  const action = body.action;

  // ---- Change the admin password (no email needed). Requires the CURRENT password.
  if (action === 'set_password') {
    const current = (body.current || '').toString();
    const next = (body.next || '').toString();
    if (!(await validatePassword(current, ADMIN_PASSWORD))) {
      return res.status(200).json({ error: 'wrong_password' });
    }
    if (next.length < 6) return res.status(200).json({ error: 'weak' });
    const salt = crypto.randomBytes(16).toString('hex');
    const rec = { salt, hash: sha256(salt, next), updated: Date.now() };
    const ok = await storeSecurity(rec);
    if (!ok) { console.log('[otp] set_password — Supabase save FAILED'); return res.status(200).json({ error: 'save_failed' }); }
    console.log('[otp] set_password — admin password updated OK');
    return res.status(200).json({ ok: true });
  }

  // OTP flow (request/verify) needs Resend + a master password configured.
  if (!RESEND_API_KEY || !ADMIN_PASSWORD) {
    console.log('[otp] NOT_CONFIGURED — RESEND_API_KEY present=' + (!!RESEND_API_KEY) + ', ADMIN_PASSWORD present=' + (!!ADMIN_PASSWORD));
    return res.status(200).json({ error: 'not_configured' });
  }
  const SECRET = RESEND_API_KEY; // server-only value, reused as the HMAC signing key

  // ---- Step 1: password correct → email a fresh code, return a signed token (NOT the code)
  if (action === 'request') {
    const password = (body.password || '').toString();
    if (!(await validatePassword(password, ADMIN_PASSWORD))) {
      console.log('[otp] request — WRONG password');
      return res.status(401).json({ error: 'wrong_password' });
    }
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
        console.log('[otp] RESEND FAILED ' + er.status + ' — ' + JSON.stringify(ed).slice(0, 300));
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
