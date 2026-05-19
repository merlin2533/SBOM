import { describe, it, expect, afterEach } from 'vitest';
import { statSync } from 'fs';
import { join } from 'path';
import request from 'supertest';
import { makeApp } from './helpers';

describe('Session lifecycle', () => {
  let app: ReturnType<typeof makeApp>;

  afterEach(async () => {
    await app.drain();
  });

  it('GET / issues a session cookie and snapshot is state: idle with jobs: []', async () => {
    app = makeApp();
    const agent = request.agent(app.app);
    await agent.get('/');

    const res = await agent
      .get('/api/state')
      .set('Sec-Fetch-Site', 'same-origin');
    expect(res.status).toBe(200);
    expect(res.body.state).toBe('idle');
    expect(res.body.jobs).toEqual([]);
  });

  it('calling GET / again rotates the cookie (new sid)', async () => {
    app = makeApp();

    const r1 = await request(app.app).get('/');
    const cookies1 = r1.headers['set-cookie'] as string[] | string;
    const cookieArr1 = Array.isArray(cookies1) ? cookies1 : [cookies1 as string];
    const sid1 = cookieArr1.find((c) => c.startsWith('sid='))?.split(';')[0]?.split('=')[1];

    const r2 = await request(app.app).get('/').set('Cookie', `sid=${sid1}`);
    const cookies2 = r2.headers['set-cookie'] as string[] | string;
    const cookieArr2 = Array.isArray(cookies2) ? cookies2 : [cookies2 as string];
    const sid2 = cookieArr2.find((c) => c.startsWith('sid='))?.split(';')[0]?.split('=')[1];

    expect(sid1).toBeDefined();
    expect(sid2).toBeDefined();
    expect(sid1).not.toBe(sid2);
  });

  it('POST /api/reset destroys session: subsequent GET /api/state returns 440', async () => {
    app = makeApp();
    const agent = request.agent(app.app);
    await agent.get('/');

    // Confirm session exists
    const before = await agent.get('/api/state').set('Sec-Fetch-Site', 'same-origin');
    expect(before.status).toBe(200);

    // Reset destroys session
    await agent.post('/api/reset').set('Sec-Fetch-Site', 'same-origin');

    // After reset, the same cookie no longer has a session
    const after = await agent.get('/api/state').set('Sec-Fetch-Site', 'same-origin');
    expect(after.status).toBe(440);
  });

  it('session scratch dir is created with mode 0700', async () => {
    app = makeApp();
    const agent = request.agent(app.app);
    const res = await agent.get('/');
    const setCookie = res.headers['set-cookie'] as string[] | string;
    const cookieArr = Array.isArray(setCookie) ? setCookie : [setCookie as string];
    const sid = cookieArr.find((c) => c.startsWith('sid='))?.split(';')[0]?.split('=')[1];

    expect(sid).toBeDefined();
    const sess = app.sessions.get(sid);
    expect(sess).toBeDefined();

    const st = statSync(sess!.dir);
    expect(st.mode & 0o777).toBe(0o700);
  });

  it('session pendingUpload starts null', async () => {
    app = makeApp();
    const agent = request.agent(app.app);
    const res = await agent.get('/');
    const setCookie = res.headers['set-cookie'] as string[] | string;
    const cookieArr = Array.isArray(setCookie) ? setCookie : [setCookie as string];
    const sid = cookieArr.find((c) => c.startsWith('sid='))?.split(';')[0]?.split('=')[1];

    const sess = app.sessions.get(sid);
    expect(sess).toBeDefined();
    expect(sess!.pendingUploadPath).toBeNull();
    expect(sess!.pendingUploadName).toBeNull();
    expect(sess!.pendingUploadSize).toBeNull();
    expect(sess!.pendingUploadId).toBeNull();
  });

  it('GET /api/state without a session returns 440', async () => {
    app = makeApp();
    const res = await request(app.app)
      .get('/api/state')
      .set('Sec-Fetch-Site', 'same-origin');
    expect(res.status).toBe(440);
  });

  it('snapshot pendingUpload is null initially', async () => {
    app = makeApp();
    const agent = request.agent(app.app);
    await agent.get('/');
    const res = await agent.get('/api/state').set('Sec-Fetch-Site', 'same-origin');
    expect(res.body.pendingUpload).toBeNull();
  });
});
