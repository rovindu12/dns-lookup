// Netlify Function entry point for the hosted DNS endpoint. The logic lives in lib/hosted-dns.js.
// The unused import forces the bundler to include @netlify/blobs: it only detects the package
// via a static top-level import, not the transitive require() chain inside the lib/*.js files.
import '@netlify/blobs';
import hosted from './lib/hosted-dns.js';

export default async (req: Request, context: { ip?: string }) => hosted.handle(req, context);

export const config = {
  path: '/api/dns',
  // Platform-level cap in addition to the per-instance limit in hosted-dns.js.
  rateLimit: { windowSize: 60, windowLimit: 60, aggregateBy: ['ip', 'domain'] },
};
