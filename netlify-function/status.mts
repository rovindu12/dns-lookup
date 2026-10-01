// Tells the page that the hosted DNS endpoint exists. Kept apart from /api/dns so that a visitor who
// hits the rate limit still gets the DNS box (the limit applies per function, not to this one).
// The unused import forces the bundler to include @netlify/blobs: hosted-dns.js requires billing.js
// at module load time, and the bundler only detects the package via a static top-level import here.
import '@netlify/blobs';
import hosted from './lib/hosted-dns.js';

export default async () => hosted.status();

export const config = { path: '/api/status' };
