// Starts a Stripe Checkout session for the paid tier. The logic lives in lib/billing-api.js.
// The unused import forces the bundler to include @netlify/blobs: it only detects the package
// via a static top-level import, not the transitive require() chain inside the lib/*.js files.
import '@netlify/blobs';
import billingApi from './lib/billing-api.js';

export default async (req: Request) => billingApi.checkout(req);

export const config = { path: '/api/checkout' };
