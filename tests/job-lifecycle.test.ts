import { describe, it, expect, afterEach } from 'vitest';
import request from 'supertest';
import { makeApp, injectPendingUpload, waitFor } from './helpers';

describe('Job lifecycle', () => {
  let app: ReturnType<typeof makeApp>;

  afterEach(async () => {
    await app.drain();
  });

  it('POST /api/jobs without pending upload returns 409', async () => {
    app = makeApp();
    const agent = request.agent(app.app);
    await agent.get('/');

    const res = await agent
      .post('/api/jobs')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Content-Type', 'application/json')
      .send({ passwords: '' });
    expect(res.status).toBe(409);
  });

  it('full job lifecycle: enqueue → running → done with outputs', async () => {
    app = makeApp();
    const agent = request.agent(app.app);

    // Create session
    const loginRes = await agent.get('/');
    const setCookie = loginRes.headers['set-cookie'] as string[] | string;
    const cookieArr = Array.isArray(setCookie) ? setCookie : [setCookie as string];
    const sid = cookieArr.find((c) => c.startsWith('sid='))?.split(';')[0]?.split('=')[1];
    expect(sid).toBeDefined();

    // Get session object and inject pending upload
    const sess = app.sessions.get(sid);
    expect(sess).toBeDefined();
    injectPendingUpload(sess!, 'test.zip', 'fake zip content');

    // POST /api/jobs
    const jobRes = await agent
      .post('/api/jobs')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Content-Type', 'application/json')
      .send({ passwords: '' });

    expect(jobRes.status).toBe(200);
    expect(jobRes.body.ok).toBe(true);
    const jobId: string = jobRes.body.jobId;
    expect(jobId).toBeDefined();

    // Poll GET /api/state until done (max 5 seconds)
    await waitFor(() => {
      const s = app.sessions.get(sid);
      if (!s) return false;
      const job = s.jobs.find((j) => j.id === jobId);
      return job?.state === 'done';
    }, 5000);

    // Verify state via API
    const stateRes = await agent
      .get('/api/state')
      .set('Sec-Fetch-Site', 'same-origin');
    expect(stateRes.status).toBe(200);
    const snapshot = stateRes.body;
    expect(snapshot.jobs).toHaveLength(1);
    expect(snapshot.jobs[0].state).toBe('done');
    expect(snapshot.jobs[0].outputs.length).toBeGreaterThan(0);

    // Outputs should include cdx.json and report.md
    const outputNames: string[] = snapshot.jobs[0].outputs.map((o: { name: string }) => o.name);
    const hasCdx = outputNames.some((n) => n.endsWith('.cdx.json'));
    const hasReport = outputNames.some((n) => n.endsWith('.report.md'));
    expect(hasCdx).toBe(true);
    expect(hasReport).toBe(true);

    // Download the cdx.json output
    const cdxName = outputNames.find((n) => n.endsWith('.cdx.json'))!;
    const downloadRes = await agent
      .get(`/api/download/${jobId}/${cdxName}`)
      .set('Sec-Fetch-Site', 'same-origin');
    expect(downloadRes.status).toBe(200);
    // The fake script writes {"bomFormat":"CycloneDX"}
    expect(downloadRes.body).toHaveProperty('bomFormat', 'CycloneDX');
  }, 10000);

  it('job state starts as queued/running immediately after enqueue', async () => {
    app = makeApp();
    const agent = request.agent(app.app);

    const loginRes = await agent.get('/');
    const setCookie = loginRes.headers['set-cookie'] as string[] | string;
    const cookieArr = Array.isArray(setCookie) ? setCookie : [setCookie as string];
    const sid = cookieArr.find((c) => c.startsWith('sid='))?.split(';')[0]?.split('=')[1];
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
    const snapshot = jobRes.body.snapshot;
    // Immediately after enqueue, state should be queued or running
    const jobSnap = snapshot.jobs.find((j: { id: string }) => j.id === jobId);
    expect(['queued', 'running']).toContain(jobSnap?.state);

    // Wait for completion
    await waitFor(() => {
      const s = app.sessions.get(sid!);
      const job = s?.jobs.find((j) => j.id === jobId);
      return job?.state === 'done' || job?.state === 'failed';
    }, 5000);
  }, 10000);

  it('GET /api/download returns 404 for nonexistent file name', async () => {
    app = makeApp();
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

    // Wait for job to complete
    await waitFor(() => {
      const s = app.sessions.get(sid!);
      const job = s?.jobs.find((j) => j.id === jobId);
      return job?.state === 'done' || job?.state === 'failed';
    }, 5000);

    const res = await agent
      .get(`/api/download/${jobId}/nonexistent-file.txt`)
      .set('Sec-Fetch-Site', 'same-origin');
    expect(res.status).toBe(404);
  }, 10000);

  it('POST /api/jobs returns 503 when draining', async () => {
    app = makeApp();
    const agent = request.agent(app.app);
    await agent.get('/');

    // Drain first (no jobs running)
    await app.drain();

    const res = await agent
      .post('/api/jobs')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Content-Type', 'application/json')
      .send({ passwords: '' });
    expect(res.status).toBe(503);
  });
});
