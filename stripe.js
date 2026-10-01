'use strict';

// Minimal Stripe integration over its REST API directly (no stripe npm SDK), to keep this
// project's dependency footprint small and avoid bundling a large SDK into the functions.

const crypto = require('crypto');

const STRIPE_API = 'https://api.stripe.com/v1';

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Payments aren't configured yet (missing ${name}).`);
  return value;
}

async function stripeRequest(path, body) {
  const secretKey = requireEnv('STRIPE_SECRET_KEY');
  const res = await fetch(`${STRIPE_API}${path}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${secretKey}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams(body).toString(),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error((data && data.error && data.error.message) || `Stripe API error (${res.status})`);
  }
  return data;
}

async function createCheckoutSession({ successUrl, cancelUrl, email }) {
  const priceId = requireEnv('STRIPE_PRICE_ID');
  const body = {
    mode: 'subscription',
    'line_items[0][price]': priceId,
    'line_items[0][quantity]': '1',
    success_url: successUrl,
    cancel_url: cancelUrl,
    'allow_promotion_codes': 'true',
  };
  if (email) body.customer_email = email;
  const session = await stripeRequest('/checkout/sessions', body);
  return session.url;
}

// Verifies the `Stripe-Signature` header against the raw request body, per Stripe's documented
// scheme: HMAC-SHA256 of "<timestamp>.<payload>" using the webhook signing secret.
function verifyWebhookSignature(rawBody, signatureHeader, secret, toleranceSeconds = 300) {
  if (!signatureHeader) throw new Error('Missing Stripe-Signature header.');
  const parts = Object.fromEntries(signatureHeader.split(',').map((part) => part.split('=')));
  const { t: timestamp, v1 } = parts;
  if (!timestamp || !v1) throw new Error('Malformed Stripe-Signature header.');
  const expected = crypto.createHmac('sha256', secret).update(`${timestamp}.${rawBody}`, 'utf8').digest('hex');
  const expectedBuf = Buffer.from(expected, 'hex');
  const actualBuf = Buffer.from(v1, 'hex');
  if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
    throw new Error('Signature mismatch.');
  }
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > toleranceSeconds) {
    throw new Error('Signature timestamp outside tolerance.');
  }
  return true;
}

module.exports = { createCheckoutSession, verifyWebhookSignature, stripeRequest };
