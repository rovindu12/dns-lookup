// Tells the page which address its request came from, so a visitor whose browser uses a proxy can see the
// address websites get. Returns only the caller's own information.
// The unused import forces the bundler to include @netlify/blobs: hosted-dns.js requires billing.js
// at module load time, and the bundler only detects the package via a static top-level import here.
import '@netlify/blobs';
import hosted from './lib/hosted-dns.js';

export default async (req: Request, context: { ip?: string; geo?: unknown }) => hosted.whoami(req, context);

export const config = { path: '/api/whoami' };
