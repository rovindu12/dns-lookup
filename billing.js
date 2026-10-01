'use strict';

// Metering and API keys for the hosted DNS endpoint, backed by Netlify Blobs so counts and keys
// survive across function instances and deploys (a plain in-memory counter would not).

const crypto = require('crypto');
const { getStore } = require('@netlify/blobs');

const KEY_PREFIX = 'dnslk_';

const PLANS = {
  free: { dailyLimit: 10, label: 'Free' },
  pro: { dailyLimit: 1000, label: 'Pro' },
};

function generateApiKey() {
  const key = KEY_PREFIX + crypto.randomBytes(24).toString('base64url');
  return { key, hash: hashApiKey(key) };
}

function hashApiKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

// Global (cross-deploy) stores, not deploy-scoped: keys and usage must survive a redeploy.
// Strong consistency so a quota check always sees the latest count, not a cached one.
const keysStore = () => getStore({ name: 'apikeys', consistency: 'strong' });
const usageStore = () => getStore({ name: 'usage', consistency: 'strong' });

const today = () => new Date().toISOString().slice(0, 10); // YYYY-MM-DD, UTC

async function lookupKey(apiKey) {
  if (!apiKey) return null;
  const hash = hashApiKey(apiKey);
  const record = await keysStore().get(hash, { type: 'json' });
  if (!record || record.status !== 'active') return null;
  return { hash, ...record };
}

// Checks and, if allowed, consumes one unit of today's quota. Usage counts are last-write-wins
// (Blobs has no compare-and-swap), so two requests racing in the same instant could both squeak
// through; fine for a soft daily quota at this volume, not meant as a hard security boundary.
async function checkQuota({ apiKey, ip }) {
  const record = apiKey ? await lookupKey(apiKey) : null;
  if (apiKey && !record) {
    return { allowed: false, status: 401, error: 'That API key is invalid or no longer active.' };
  }
  const plan = record && PLANS[record.plan] ? record.plan : (record ? 'pro' : 'free');
  const limit = PLANS[plan].dailyLimit;
  const usageKey = record ? `key:${record.hash}:${today()}` : `free:${ip || 'unknown'}:${today()}`;
  const store = usageStore();
  const current = Number((await store.get(usageKey)) || '0');
  if (current >= limit) {
    const upgrade = record ? '' : ' Get an API key for a higher limit at /pricing.html.';
    return {
      allowed: false, status: 429, plan, limit, used: current,
      error: `Daily limit of ${limit} checks reached for the ${PLANS[plan].label} tier.${upgrade}`,
    };
  }
  await store.set(usageKey, String(current + 1));
  return { allowed: true, plan, limit, used: current + 1, remaining: limit - current - 1 };
}

async function activateKeyForSubscription({ customerId, subscriptionId, email, plan = 'pro' }) {
  const { key, hash } = generateApiKey();
  await keysStore().setJSON(hash, {
    email: email || null,
    plan,
    stripeCustomerId: customerId || null,
    stripeSubscriptionId: subscriptionId || null,
    status: 'active',
    createdAt: new Date().toISOString(),
  });
  if (subscriptionId) await keysStore().setJSON(`sub:${subscriptionId}`, { hash });
  return key;
}

async function deactivateKeyForSubscription(subscriptionId) {
  const index = await keysStore().get(`sub:${subscriptionId}`, { type: 'json' });
  if (!index) return false;
  const record = await keysStore().get(index.hash, { type: 'json' });
  if (!record) return false;
  record.status = 'canceled';
  await keysStore().setJSON(index.hash, record);
  return true;
}

async function stashSessionKey(sessionId, key) {
  await keysStore().setJSON(`session:${sessionId}`, { key, createdAt: new Date().toISOString() });
}

// One-time reveal: returns the key the first time it's fetched, then deletes it so a leaked
// success-page URL can't be replayed to read someone else's key later.
async function claimSessionKey(sessionId) {
  const store = keysStore();
  const entry = await store.get(`session:${sessionId}`, { type: 'json' });
  if (!entry) return null;
  await store.delete(`session:${sessionId}`);
  return entry.key;
}

module.exports = {
  PLANS, KEY_PREFIX,
  generateApiKey, hashApiKey, lookupKey, checkQuota,
  activateKeyForSubscription, deactivateKeyForSubscription,
  stashSessionKey, claimSessionKey,
};
