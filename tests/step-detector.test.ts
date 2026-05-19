import { describe, it, expect } from 'vitest';
import { detectPhase } from '../src/step-detector';

describe('detectPhase', () => {
  it('"starting extraction" → phase "starting", progress 5', () => {
    const hit = detectPhase('starting extraction');
    expect(hit).not.toBeNull();
    expect(hit!.phase).toBe('starting');
    expect(hit!.progress).toBe(5);
  });

  it('"extracting archive foo.zip" → phase "extracting", progress 20', () => {
    const hit = detectPhase('extracting archive foo.zip');
    expect(hit).not.toBeNull();
    expect(hit!.phase).toBe('extracting');
    expect(hit!.progress).toBe(20);
  });

  it('"syft cataloging components" → phase "cataloging", progress 55', () => {
    const hit = detectPhase('syft cataloging components');
    expect(hit).not.toBeNull();
    expect(hit!.phase).toBe('cataloging');
    expect(hit!.progress).toBe(55);
  });

  it('"running grype vulnerability scan" → phase "vulnerability scan", progress 70', () => {
    const hit = detectPhase('running grype vulnerability scan');
    expect(hit).not.toBeNull();
    expect(hit!.phase).toBe('vulnerability scan');
    expect(hit!.progress).toBe(70);
  });

  it('"writing report" → phase "writing report", progress 85', () => {
    const hit = detectPhase('writing report');
    expect(hit).not.toBeNull();
    expect(hit!.phase).toBe('writing report');
    expect(hit!.progress).toBe(85);
  });

  it('"done." → phase "finishing", progress 95', () => {
    const hit = detectPhase('done.');
    expect(hit).not.toBeNull();
    expect(hit!.phase).toBe('finishing');
    expect(hit!.progress).toBe(95);
  });

  it('"no idea what this line means" → null', () => {
    const hit = detectPhase('no idea what this line means');
    expect(hit).toBeNull();
  });

  it('does not downgrade progress — same progress returns null', () => {
    const hit = detectPhase('starting extraction', 5);
    expect(hit).toBeNull();
  });

  it('does not downgrade progress — lower progress returns null', () => {
    const hit = detectPhase('starting extraction', 20);
    expect(hit).toBeNull();
  });

  it('upgrades when new progress is higher', () => {
    const hit = detectPhase('extracting archives', 5);
    expect(hit).not.toBeNull();
    expect(hit!.progress).toBe(20);
  });

  it('null currentProgress allows any match', () => {
    const hit = detectPhase('done', null);
    expect(hit).not.toBeNull();
    expect(hit!.phase).toBe('finishing');
  });

  it('empty line → null', () => {
    expect(detectPhase('')).toBeNull();
  });
});
