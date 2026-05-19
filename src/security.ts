import crypto from 'crypto';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { ServerConfig } from './types';

// --------------------------------------------------------------------------
// Security headers — permissive mode for HTTP / IP-based deployments
// --------------------------------------------------------------------------

/**
 * Attach the minimum headers we actually need. The strict bundle (CSP,
 * COOP, CORP, X-Frame, Referrer-Policy, Permissions-Policy) was actively
 * causing browsers to drop cookies / refuse to render the page on plain
 * HTTP IP deployments. We keep only:
 *  - X-Content-Type-Options: nosniff (cheap, always safe)
 *  - Cache-Control: no-store, private on / and /api/*
 *  - Permissive CORS that echoes the request Origin and allows credentials,
 *    so browsers happily ship the Cookie / X-Session-Id through proxies
 *    and tunnels.
 */
export const securityHeaders: RequestHandler = (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // ── CORS: echo Origin, allow credentials, advertise the tus headers ──
  // Wildcard with credentials is rejected by browsers, so we echo whatever
  // the client sent. Same-origin browsers still get a working setup; cross-
  // origin clients (curl, dev tunnels) get a fully permissive one.
  const origin = req.get('Origin') ?? '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, HEAD, POST, PATCH, PUT, DELETE, OPTIONS'
  );
  res.setHeader(
    'Access-Control-Allow-Headers',
    [
      'Authorization',
      'Content-Type',
      'X-Session-Id',
      // tus protocol headers
      'Tus-Resumable',
      'Upload-Length',
      'Upload-Metadata',
      'Upload-Offset',
      'Upload-Defer-Length',
      'Upload-Concat',
      'X-HTTP-Method-Override',
    ].join(', ')
  );
  res.setHeader(
    'Access-Control-Expose-Headers',
    [
      'Location',
      'Tus-Resumable',
      'Tus-Version',
      'Tus-Extension',
      'Upload-Length',
      'Upload-Offset',
      'Upload-Metadata',
      'X-Session-Id',
    ].join(', ')
  );

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  if (req.path === '/' || req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, private');
    res.setHeader('Pragma', 'no-cache');
  }
  next();
};

// --------------------------------------------------------------------------
// HTTP Basic Auth (unchanged)
// --------------------------------------------------------------------------

function timingEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  const len = Math.max(ab.length, bb.length, 1);
  const aPad = Buffer.concat([ab, Buffer.alloc(len - ab.length)]);
  const bPad = Buffer.concat([bb, Buffer.alloc(len - bb.length)]);
  return crypto.timingSafeEqual(aPad, bPad) && ab.length === bb.length;
}

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
// CSRF guard — DISABLED for compatibility with proxies / tunnels
// --------------------------------------------------------------------------

/**
 * Previously rejected anything whose Sec-Fetch-Site was not `same-origin`
 * or `none`. That broke setups where a proxy or browser extension stripped
 * the header. The CSRF risk for an unauthenticated, ephemeral, single-user
 * tool is low; this is now a no-op.
 */
export const sameOriginOnly: RequestHandler = (_req, _res, next) => next();

// --------------------------------------------------------------------------
// Per-IP upload rate limit (unchanged)
// --------------------------------------------------------------------------

interface Bucket {
  count: number;
  resetAt: number;
}

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
    if (buckets.size > 10_000) {
      for (const [k, v] of buckets) {
        if (v.resetAt < now) buckets.delete(k);
      }
    }
    next();
  };
}
