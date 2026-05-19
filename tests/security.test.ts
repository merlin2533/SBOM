import { describe, it, expect, afterEach } from 'vitest';
import request from 'supertest';
import { makeApp } from './helpers';

describe('Security headers', () => {
  let app: ReturnType<typeof makeApp>;

  afterEach(async () => {
    await app.drain();
  });

  it('GET / returns CSP header containing default-src \'self\'', async () => {
    app = makeApp();
    const res = await request(app.app).get('/');
    expect(res.headers['content-security-policy']).toContain("default-src 'self'");
  });

  it('GET / returns X-Frame-Options: DENY', async () => {
    app = makeApp();
    const res = await request(app.app).get('/');
    expect(res.headers['x-frame-options']).toBe('DENY');
  });

  it('GET / returns X-Content-Type-Options: nosniff', async () => {
    app = makeApp();
    const res = await request(app.app).get('/');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  it('GET / returns Referrer-Policy: no-referrer', async () => {
    app = makeApp();
    const res = await request(app.app).get('/');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
  });

  it('GET / returns Cache-Control: no-store, private', async () => {
    app = makeApp();
    const res = await request(app.app).get('/');
    expect(res.headers['cache-control']).toBe('no-store, private');
  });

  it('GET / does not include X-Powered-By header', async () => {
    app = makeApp();
    const res = await request(app.app).get('/');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});

describe('Session cookie', () => {
  let app: ReturnType<typeof makeApp>;

  afterEach(async () => {
    await app.drain();
  });

  it('GET / sets HttpOnly cookie named sid', async () => {
    app = makeApp();
    const res = await request(app.app).get('/');
    const setCookie = res.headers['set-cookie'] as string[] | string | undefined;
    expect(setCookie).toBeDefined();
    const cookies = Array.isArray(setCookie) ? setCookie : [setCookie as string];
    const sidCookie = cookies.find((c) => c.startsWith('sid='));
    expect(sidCookie).toBeDefined();
    expect(sidCookie!.toLowerCase()).toContain('httponly');
    expect(sidCookie!.toLowerCase()).toContain('samesite=lax');
    expect(sidCookie!.toLowerCase()).toContain('path=/');
  });
});

describe('CSRF guard (sameOriginOnly)', () => {
  let app: ReturnType<typeof makeApp>;

  afterEach(async () => {
    await app.drain();
  });

  it('POST /api/cancel with Sec-Fetch-Site: cross-site → 403', async () => {
    app = makeApp();
    const res = await request(app.app)
      .post('/api/cancel')
      .set('Sec-Fetch-Site', 'cross-site')
      .set('Content-Type', 'application/json');
    expect(res.status).toBe(403);
  });

  it('POST /api/cancel with Sec-Fetch-Site: same-origin does NOT return 403', async () => {
    app = makeApp();
    // First establish a session
    const agent = request.agent(app.app);
    await agent.get('/');
    const res = await agent
      .post('/api/cancel')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Content-Type', 'application/json');
    // Should be 409 (no job running) or another app error, but not 403
    expect(res.status).not.toBe(403);
  });

  it('POST /api/cancel without Sec-Fetch-Site does NOT return 403', async () => {
    app = makeApp();
    const agent = request.agent(app.app);
    await agent.get('/');
    const res = await agent
      .post('/api/cancel')
      .set('Content-Type', 'application/json');
    expect(res.status).not.toBe(403);
  });

  it('POST /api/cancel without session returns 440 (not 403)', async () => {
    app = makeApp();
    const res = await request(app.app)
      .post('/api/cancel')
      .set('Content-Type', 'application/json');
    // no Sec-Fetch-Site header means cross-origin check passes; no session → 440
    expect(res.status).toBe(440);
  });
});

describe('Basic Auth', () => {
  let app: ReturnType<typeof makeApp>;

  afterEach(async () => {
    await app.drain();
  });

  it('GET / without Authorization → 401 with WWW-Authenticate: Basic header', async () => {
    app = makeApp({ authUser: 'ops', authPass: 'secret' });
    const res = await request(app.app).get('/');
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toMatch(/^Basic /i);
  });

  it('GET / with wrong credentials → 401', async () => {
    app = makeApp({ authUser: 'ops', authPass: 'secret' });
    const res = await request(app.app)
      .get('/')
      .set('Authorization', `Basic ${Buffer.from('ops:wrong').toString('base64')}`);
    expect(res.status).toBe(401);
  });

  it('GET / with correct credentials → 200', async () => {
    app = makeApp({ authUser: 'ops', authPass: 'secret' });
    const res = await request(app.app)
      .get('/')
      .set('Authorization', `Basic ${Buffer.from('ops:secret').toString('base64')}`);
    expect(res.status).toBe(200);
  });

  it('GET / with wrong username → 401', async () => {
    app = makeApp({ authUser: 'ops', authPass: 'secret' });
    const res = await request(app.app)
      .get('/')
      .set('Authorization', `Basic ${Buffer.from('admin:secret').toString('base64')}`);
    expect(res.status).toBe(401);
  });
});

describe('Upload rate limit', () => {
  let app: ReturnType<typeof makeApp>;

  afterEach(async () => {
    await app.drain();
  });

  it('POST /api/tus returns 429 with Retry-After after exceeding rate limit', async () => {
    app = makeApp({ uploadRatePerMin: 2 });
    const agent = request.agent(app.app);
    // Establish a session first
    await agent.get('/');

    // First two should not be rate-limited (they may fail for other reasons like missing tus headers)
    const r1 = await agent.post('/api/tus').set('Content-Type', 'application/json');
    const r2 = await agent.post('/api/tus').set('Content-Type', 'application/json');

    // Third should be 429
    const r3 = await agent.post('/api/tus').set('Content-Type', 'application/json');

    expect(r1.status).not.toBe(429);
    expect(r2.status).not.toBe(429);
    expect(r3.status).toBe(429);
    expect(r3.headers['retry-after']).toBeDefined();
  });
});

describe('Health endpoint', () => {
  let app: ReturnType<typeof makeApp>;

  afterEach(async () => {
    await app.drain();
  });

  it('GET /api/health returns 200 JSON { ok: true } without a session', async () => {
    app = makeApp();
    const res = await request(app.app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it('GET /api/health is not CSRF-gated (no Sec-Fetch-Site check)', async () => {
    app = makeApp();
    const res = await request(app.app)
      .get('/api/health')
      .set('Sec-Fetch-Site', 'cross-site');
    // health endpoint has no sameOriginOnly guard
    expect(res.status).toBe(200);
  });

  it('GET /api/health returns sandbox and sessions fields', async () => {
    app = makeApp();
    const res = await request(app.app).get('/api/health');
    expect(res.body).toHaveProperty('sessions');
    expect(res.body).toHaveProperty('sandbox');
  });
});
