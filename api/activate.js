import crypto from 'node:crypto';

const COOKIE_NAME = 'clad_session';
const SESSION_DAYS = 365;

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

function hashUserAgent(userAgent) {
  return crypto.createHash('sha256').update(userAgent || '').digest('base64url');
}

function signSession(payload, secret) {
  const body = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function normalizeKey(value) {
  return String(value || '').trim().toUpperCase();
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function json(status, body, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...extraHeaders },
  });
}

async function findLicense(key) {
  const url = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !serviceKey) throw new Error('Supabase server credentials are not configured.');

  const endpoint = `${url.replace(/\/$/, '')}/rest/v1/cladhabits_licenses?license_key=eq.${encodeURIComponent(key)}&select=id,license_key,customer_email,customer_id,status,expires_at,activation_count,max_activations&limit=1`;
  const response = await fetch(endpoint, {
    headers: {
      apikey: serviceKey,
      Authorization: `Bearer ${serviceKey}`,
      Accept: 'application/json',
    },
  });
  if (!response.ok) throw new Error(`License database lookup failed (${response.status}).`);
  const rows = await response.json();
  return rows[0] || null;
}

async function consumeActivation(id, key, currentCount, maxActivations) {
  const url = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
  const nextCount = currentCount + 1;
  const endpoint = `${url.replace(/\/$/, '')}/rest/v1/cladhabits_licenses?id=eq.${encodeURIComponent(id)}&license_key=eq.${encodeURIComponent(key)}&activation_count=lt.${encodeURIComponent(String(maxActivations))}`;
  const response = await fetch(endpoint, {
    method: 'PATCH',
    headers: {
      apikey: serviceKey,
      Authorization: `Bearer ${serviceKey}`,
      'Content-Type': 'application/json',
      Prefer: 'return=representation',
    },
    body: JSON.stringify({ activation_count: nextCount }),
  });
  if (!response.ok) throw new Error(`License activation update failed (${response.status}).`);
  const rows = await response.json();
  return rows[0] || null;
}

async function handler(request) {
  if (request.method !== 'POST') return json(405, { valid: false, message: 'Method not allowed.' });

  const secret = process.env.CLAD_SESSION_SECRET || process.env.LICENSE_SECRET;
  if (!secret) return json(500, { valid: false, message: 'Access security is not configured.' });

  try {
    const body = await request.json();
    const licenseKey = normalizeKey(body?.licenseKey);
    const email = normalizeEmail(body?.email);
    if (!licenseKey) return json(400, { valid: false, message: 'Enter your CLADHABITS license key.' });

    const license = await findLicense(licenseKey);
    if (!license) return json(404, { valid: false, message: 'License not found.' });
    if (license.status !== 'active') return json(403, { valid: false, message: 'This license is not active.' });
    if (license.expires_at && new Date(license.expires_at).getTime() <= Date.now()) {
      return json(403, { valid: false, message: 'This license has expired.' });
    }

    if (license.customer_email && email && normalizeEmail(license.customer_email) !== email) {
      return json(403, { valid: false, message: 'The email does not match the purchase.' });
    }
    if (license.customer_email && !email) {
      return json(400, { valid: false, message: 'Enter the email used for your purchase.' });
    }

    const currentCount = Number(license.activation_count || 0);
    const maxActivations = Number(license.max_activations || 1);
    if (currentCount >= maxActivations) {
      return json(409, { valid: false, message: 'This license has already been activated on another device.' });
    }

    const activated = await consumeActivation(license.id, licenseKey, currentCount, maxActivations);
    if (!activated) {
      return json(409, { valid: false, message: 'This license was activated already. Access is limited to one device.' });
    }

    const now = Math.floor(Date.now() / 1000);
    const exp = license.expires_at ? Math.floor(new Date(license.expires_at).getTime() / 1000) : now + SESSION_DAYS * 86400;
    const session = signSession({
      v: 1,
      licenseId: license.id,
      customerId: license.customer_id || null,
      email: license.customer_email || email || null,
      exp,
      ua: hashUserAgent(request.headers.get('user-agent') || ''),
    }, secret);

    const headers = new Headers({ 'content-type': 'application/json; charset=utf-8' });
    headers.append('Set-Cookie', `${COOKIE_NAME}=${session}; Path=/; Max-Age=${Math.max(60, exp - now)}; HttpOnly; Secure; SameSite=Lax`);
    return new Response(JSON.stringify({ valid: true, message: 'CLADHABITS activated on this device.' }), { status: 200, headers });
  } catch (error) {
    return json(500, { valid: false, message: error?.message || 'Activation failed.' });
  }
}

module.exports = handler;
