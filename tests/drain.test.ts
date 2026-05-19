import { describe, it, expect, afterEach } from 'vitest';
import request from 'supertest';
import { makeApp, makeSleepyExtractSbom, injectPendingUpload, waitFor } from './helpers';

describe('drain()', () => {
  let app: ReturnType<typeof makeApp> | undefined;

  afterEach(async () => {
    if (app) {
      await app.drain();
      app = undefined;
    }
  });

  it('drain() returns quickly when no job is running', async () => {
    app = makeApp();
    const start = Date.now();
    await app.drain();
    const elapsed = Date.now() - start;
    // Should complete very quickly (well under 1 second)
    expect(elapsed).toBeLessThan(1000);
    app = undefined; // already drained
  });

  it('drain() terminates a long-running job within shutdownGraceMs', async () => {
    const sleepyBin = makeSleepyExtractSbom(30);
    app = makeApp({ extractSbomBin: sleepyBin, shutdownGraceMs: 200 });
    const agent = request.agent(app.app);

    // Create session and inject upload
    const loginRes = await agent.get('/');
    const setCookie = loginRes.headers['set-cookie'] as string[] | string;
    const cookieArr = Array.isArray(setCookie) ? setCookie : [setCookie as string];
    const sid = cookieArr.find((c) => c.startsWith('sid='))?.split(';')[0]?.split('=')[1];
    expect(sid).toBeDefined();

    const sess = app.sessions.get(sid!);
    expect(sess).toBeDefined();
    injectPendingUpload(sess!);

    const jobRes = await agent
      .post('/api/jobs')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Content-Type', 'application/json')
      .send({ passwords: '' });
    expect(jobRes.status).toBe(200);
    const jobId: string = jobRes.body.jobId;

    // Wait until the job is actually running
    await waitFor(() => {
      const s = app!.sessions.get(sid!);
      const job = s?.jobs.find((j) => j.id === jobId);
      return job?.state === 'running';
    }, 3000);

    // Verify the job is running before draining
    const runningJob = app.sessions.get(sid!)?.jobs.find((j) => j.id === jobId);
    expect(runningJob?.state).toBe('running');

    // Drain should complete quickly even with the 30s sleep script
    const start = Date.now();
    await app.drain();
    const elapsed = Date.now() - start;

    // Should complete within shutdownGraceMs + buffer (200ms grace + ~500ms buffer)
    expect(elapsed).toBeLessThan(2000);
    app = undefined; // already drained
  }, 10000);

  it('after drain(), POST /api/jobs returns 503', async () => {
    app = makeApp();
    const agent = request.agent(app.app);
    await agent.get('/');

    // Drain
    await app.drain();

    const res = await agent
      .post('/api/jobs')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Content-Type', 'application/json')
      .send({ passwords: '' });
    expect(res.status).toBe(503);

    app = undefined; // already drained
  });

  it('drain() with a running job results in job being cancelled or failed', async () => {
    const sleepyBin = makeSleepyExtractSbom(30);
    app = makeApp({ extractSbomBin: sleepyBin, shutdownGraceMs: 200 });
    const agent = request.agent(app.app);

    const loginRes = await agent.get('/');
    const setCookie = loginRes.headers['set-cookie'] as string[] | string;
    const cookieArr = Array.isArray(setCookie) ? setCookie : [setCookie as string];
    const sid = cookieArr.find((c) => c.startsWith('sid='))?.split(';')[0]?.split('=')[1];

    const sess = app.sessions.get(sid!);
    injectPendingUpload(sess!);

    const jobRes = await agent
      .post('/api/jobs')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Content-Type', 'application/json')
      .send({ passwords: '' });
    const jobId: string = jobRes.body.jobId;

    // Wait for running
    await waitFor(() => {
      const s = app!.sessions.get(sid!);
      const job = s?.jobs.find((j) => j.id === jobId);
      return job?.state === 'running';
    }, 3000);

    // Capture job reference before draining (sessions will be destroyed)
    const capturedJob = app.sessions.get(sid!)?.jobs.find((j) => j.id === jobId);
    expect(capturedJob).toBeDefined();

    await app.drain();

    // After drain, the child's close event sets state to cancelled (SIGTERM) or failed.
    // If drain exited via the grace timeout rather than waiting for the close event,
    // the state update in job.ts may lag slightly. Poll briefly to allow it to settle.
    await waitFor(() => capturedJob!.state !== 'running', 1000);
    expect(['cancelled', 'failed']).toContain(capturedJob!.state);

    app = undefined; // already drained
  }, 10000);
});
