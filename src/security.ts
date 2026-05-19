import crypto from 'crypto';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { ServerConfig } from './types';

// --------------------------------------------------------------------------
// Security headers
// --------------------------------------------------------------------------

/**
 * Attach security headers to all responses. Cache-Control no-store is applied
 * to / and /api/* routes.
 */
export const securityHeaders: RequestHandler = (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'interest-cohort=(), browsing-topics=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self'",
      "form-action 'self'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "object-src 'none'",
    ].join('; ')
  );
  if (req.path === '/' || req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, private');
    res.setHeader('Pragma', 'no-cache');
  }
  next();
};

// --------------------------------------------------------------------------
// HTTP Basic Auth
// --------------------------------------------------------------------------

function timingEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  const len = Math.max(ab.length, bb.length, 1);
  const aPad = Buffer.concat([ab, Buffer.alloc(len - ab.length)]);
  const bPad = Buffer.concat([bb, Buffer.alloc(len - bb.length)]);
  return crypto.timingSafeEqual(aPad, bPad) && ab.length === bb.length;
}

/**
 * Return a middleware that enforces HTTP Basic Auth when authUser is
 * configured. Always constant-time compares credentials.
 */
export function basicAuth(config: ServerConfig): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!config.authUser) {
      return next();
    }
    const h = req.get('Authorization') ?? '';
    if (h.startsWith('Basic ')) {
      let cred = '';
      try {
        cred = Buffer.from(h.slice(6), 'base64').toString('utf8');
      } catch (_) {}
      const i = cred.indexOf(':');
      const u = i >= 0 ? cred.slice(0, i) : cred;
      const p = i >= 0 ? cred.slice(i + 1) : '';
      if (
        timingEqual(u, config.authUser) &&
        timingEqual(p, config.authPass ?? '')
      ) {
        return next();
      }
    }
    res.set('WWW-Authenticate', 'Basic realm="SBOM Extractor", charset="UTF-8"');
    res.status(401).send('Authentication required.');
  };
}

// --------------------------------------------------------------------------
// CSRF guard
// --------------------------------------------------------------------------

/**
 * Reject requests whose Sec-Fetch-Site indicates a cross-origin context.
 * Browsers always set this header on Fetch/XHR. Old clients that omit it
 * (e.g. curl) are allowed through — this is defense-in-depth only.
 */
export const sameOriginOnly: RequestHandler = (req, res, next) => {
  const sfs = req.get('Sec-Fetch-Site');
  if (sfs && sfs !== 'same-origin' && sfs !== 'none') {
    res.status(403).json({ error: 'Cross-origin request rejected.' });
    return;
  }
  next();
};

// --------------------------------------------------------------------------
// Per-IP upload rate limit
// --------------------------------------------------------------------------

interface Bucket {
  count: number;
  resetAt: number;
}

/**
 * Per-IP token-bucket rate limiter for upload creation. Apply only to the
 * POST (creation) endpoint, not to PATCH (chunk) or HEAD requests.
 */
export function rateLimitUpload(config: ServerConfig): RequestHandler {
  const buckets = new Map<string, Bucket>();

  return (req: Request, res: Response, next: NextFunction) => {
    const ip = req.ip ?? req.socket.remoteAddress ?? 'unknown';
    const now = Date.now();
    let b = buckets.get(ip);
    if (!b || b.resetAt < now) {
      b = { count: 0, resetAt: now + 60_000 };
      buckets.set(ip, b);
    }
    b.count++;
    res.setHeader('X-RateLimit-Limit', String(config.uploadRatePerMin));
    res.setHeader(
      'X-RateLimit-Remaining',
      String(Math.max(0, config.uploadRatePerMin - b.count))
    );
    if (b.count > config.uploadRatePerMin) {
      const retry = Math.ceil((b.resetAt - now) / 1000);
      res.setHeader('Retry-After', String(retry));
      res.status(429).json({ error: 'Too many uploads. Try again later.' });
      return;
    }
    // Periodically trim stale buckets to prevent unbounded memory growth.
    if (buckets.size > 10_000) {
      for (const [k, v] of buckets) {
        if (v.resetAt < now) buckets.delete(k);
      }
    }
    next();
  };
}
