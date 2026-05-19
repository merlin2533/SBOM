import { describe, it, expect, afterEach } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import request from 'supertest';
import { makeApp, makeSpyExtractSbom, injectPendingUpload, waitFor } from './helpers';

describe('Password transport', () => {
  let app: ReturnType<typeof makeApp>;

  afterEach(async () => {
    await app.drain();
  });

  it('passwords without commas are passed via EXTRACT_SBOM_PASSWORDS env var', async () => {
    const spyBin = makeSpyExtractSbom();
    app = makeApp({ extractSbomBin: spyBin });
    const agent = request.agent(app.app);

    const loginRes = await agent.get('/');
    const setCookie = loginRes.headers['set-cookie'] as string[] | string;
    const cookieArr = Array.isArray(setCookie) ? setCookie : [setCookie as string];
    const sid = cookieArr.find((c) => c.startsWith('sid='))?.split(';')[0]?.split('=')[1];
    expect(sid).toBeDefined();

    const sess = app.sessions.get(sid!);
    expect(sess).toBeDefined();
    injectPendingUpload(sess!, 'test.zip');

    const jobRes = await agent
      .post('/api/jobs')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Content-Type', 'application/json')
      .send({ passwords: 'foo\nbar' });

    expect(jobRes.status).toBe(200);
    const jobId: string = jobRes.body.jobId;

    // Wait for the job to complete
    await waitFor(() => {
      const s = app.sessions.get(sid!);
      const job = s?.jobs.find((j) => j.id === jobId);
      return job?.state === 'done' || job?.state === 'failed';
    }, 5000);

    const s = app.sessions.get(sid!);
    const job = s?.jobs.find((j) => j.id === jobId);
    expect(job).toBeDefined();
    expect(job!.state).toBe('done');
    expect(job!.passwordTransport).toBe('env');

    // Read the spy output
    const spyFile = `${job!.outDir}/spy.txt`;
    expect(existsSync(spyFile)).toBe(true);
    const spyContent = readFileSync(spyFile, 'utf8');

    // env line should contain foo,bar
    expect(spyContent).toContain('env=foo,bar');
    // pwfile should be empty
    expect(spyContent).toContain('pwfile=');
  }, 10000);

  it('password containing a comma is passed via --password-file', async () => {
    const spyBin = makeSpyExtractSbom();
    app = makeApp({ extractSbomBin: spyBin });
    const agent = request.agent(app.app);

    const loginRes = await agent.get('/');
    const setCookie = loginRes.headers['set-cookie'] as string[] | string;
    const cookieArr = Array.isArray(setCookie) ? setCookie : [setCookie as string];
    const sid = cookieArr.find((c) => c.startsWith('sid='))?.split(';')[0]?.split('=')[1];
    expect(sid).toBeDefined();

    const sess = app.sessions.get(sid!);
    expect(sess).toBeDefined();
    injectPendingUpload(sess!, 'test.zip');

    const jobRes = await agent
      .post('/api/jobs')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Content-Type', 'application/json')
      .send({ passwords: 'foo,bar\nother' });

    expect(jobRes.status).toBe(200);
    const jobId: string = jobRes.body.jobId;

    // Wait for the job to complete
    await waitFor(() => {
      const s = app.sessions.get(sid!);
      const job = s?.jobs.find((j) => j.id === jobId);
      return job?.state === 'done' || job?.state === 'failed';
    }, 5000);

    const s = app.sessions.get(sid!);
    const job = s?.jobs.find((j) => j.id === jobId);
    expect(job).toBeDefined();
    expect(job!.state).toBe('done');
    expect(job!.passwordTransport).toBe('file');

    // Read the spy output
    const spyFile = `${job!.outDir}/spy.txt`;
    expect(existsSync(spyFile)).toBe(true);
    const spyContent = readFileSync(spyFile, 'utf8');

    // The spy should have recorded a pwfile path
    const pwfileMatch = spyContent.match(/^pwfile=(.+)$/m);
    expect(pwfileMatch).toBeTruthy();
    const pwfilePath = pwfileMatch![1].trim();
    expect(pwfilePath).not.toBe('');

    // The spy should have recorded the pwfile_contents
    expect(spyContent).toContain('pwfile_contents:');
    expect(spyContent).toContain('foo,bar');
    expect(spyContent).toContain('other');

    // After job completion, the password file must be shredded/deleted.
    // Shredding happens asynchronously after the child exits, so give it a
    // short grace period before asserting (the job state already flipped to
    // 'done' on the 'exit' event, but shred can race the test on slow CI).
    await waitFor(() => job!.passwordFile === null && !existsSync(pwfilePath), 2000);
    expect(job!.passwordFile).toBeNull();
    expect(existsSync(pwfilePath)).toBe(false);
  }, 10000);

  it('no passwords → passwordTransport is "none"', async () => {
    const spyBin = makeSpyExtractSbom();
    app = makeApp({ extractSbomBin: spyBin });
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
    await waitFor(() => {
      const s = app.sessions.get(sid!);
      const job = s?.jobs.find((j) => j.id === jobId);
      return job?.state === 'done' || job?.state === 'failed';
    }, 5000);

    const s = app.sessions.get(sid!);
    const job = s?.jobs.find((j) => j.id === jobId);
    expect(job!.passwordTransport).toBe('none');

    // spy.txt should show empty env
    const spyContent = readFileSync(`${job!.outDir}/spy.txt`, 'utf8');
    expect(spyContent).toContain('env=');
    // The env value should be empty (no passwords)
    const envMatch = spyContent.match(/^env=(.*)$/m);
    expect(envMatch![1].trim()).toBe('');
  }, 10000);
});
