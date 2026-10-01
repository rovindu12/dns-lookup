'use strict';

// Netlify Function logic for the paid-tier flow: start a Stripe Checkout session, receive Stripe's
// webhook when a subscription starts or ends, and let the success page claim its new API key once.

const billing = require('./billing');
const stripeApi = require('./stripe');

const json = (status, body) => new Response(JSON.stringify(body), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
});

async function checkout(req) {
  if (req.method !== 'POST') return json(405, { error: 'Use POST.' });
  const url = new URL(req.url);
  let email = null;
  try {
    const text = await req.text();
    if (text) {
      const body = JSON.parse(text);
      if (body && typeof body.email === 'string' && body.email.length < 200) email = body.email;
    }
  } catch {
    return json(400, { error: 'The request body is not valid JSON.' });
  }
  try {
    const checkoutUrl = await stripeApi.createCheckoutSession({
      successUrl: `${url.origin}/pricing.html?session_id={CHECKOUT_SESSION_ID}`,
      cancelUrl: `${url.origin}/pricing.html`,
      email,
    });
    return json(200, { url: checkoutUrl });
  } catch (err) {
    return json(503, { error: err.message });
  }
}

async function webhook(req) {
  if (req.method !== 'POST') return json(405, { error: 'Use POST.' });
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) return json(503, { error: "Payments aren't configured yet (missing STRIPE_WEBHOOK_SECRET)." });

  const rawBody = await req.text();
  let event;
  try {
    stripeApi.verifyWebhookSignature(rawBody, req.headers.get('stripe-signature'), secret);
    event = JSON.parse(rawBody);
  } catch (err) {
    return json(400, { error: err.message });
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const key = await billing.activateKeyForSubscription({
        customerId: session.customer,
        subscriptionId: session.subscription,
        email: (session.customer_details && session.customer_details.email) || session.customer_email || null,
      });
      if (session.id) await billing.stashSessionKey(session.id, key);
    } else if (event.type === 'customer.subscription.deleted') {
      await billing.deactivateKeyForSubscription(event.data.object.id);
    } else if (event.type === 'customer.subscription.updated') {
      const subscription = event.data.object;
      if (subscription.status !== 'active' && subscription.status !== 'trialing') {
        await billing.deactivateKeyForSubscription(subscription.id);
      }
    }
  } catch {
    // A storage hiccup, not a bad event — ask Stripe to retry rather than silently dropping it.
    return json(500, { error: 'Failed to process event.' });
  }
  return json(200, { received: true });
}

async function sessionKey(req) {
  const url = new URL(req.url);
  const sessionId = url.searchParams.get('session_id');
  if (!sessionId) return json(400, { error: 'Missing session_id.' });
  const key = await billing.claimSessionKey(sessionId);
  if (!key) {
    return json(404, {
      error: 'No key is waiting for that session yet. If you just paid, wait a few seconds and try again.',
    });
  }
  return json(200, { key });
}

module.exports = { checkout, webhook, sessionKey };
