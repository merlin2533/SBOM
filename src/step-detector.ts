import type { PhaseHit } from './types';

interface PhaseRule {
  pattern: RegExp;
  phase: string;
  progress: number;
}

// Rules are evaluated in order. First match wins.
const RULES: PhaseRule[] = [
  { pattern: /^starting|^begin/i,                       phase: 'starting',            progress: 5  },
  { pattern: /extract|unpack|unzip/i,                   phase: 'extracting',          progress: 20 },
  { pattern: /catalog|syft|scanning components/i,       phase: 'cataloging',          progress: 55 },
  { pattern: /grype|vulnerab/i,                         phase: 'vulnerability scan',  progress: 70 },
  { pattern: /writing report|render|generate report/i,  phase: 'writing report',      progress: 85 },
  { pattern: /^done|^finished|^complete/i,              phase: 'finishing',            progress: 95 },
];

/**
 * Scan a log line for a phase transition.
 *
 * @param line       - Raw output line from the child process.
 * @param currentProgress - The progress value already recorded for the job
 *                          (null if no phase has been detected yet). Used to
 *                          prevent progress from going backwards.
 * @returns A PhaseHit if a new (non-downgrade) phase was matched, else null.
 */
export function detectPhase(
  line: string,
  currentProgress: number | null = null
): PhaseHit | null {
  for (const rule of RULES) {
    if (rule.pattern.test(line)) {
      // Don't downgrade: if the job has already reached a higher progress
      // percentage, ignore this match.
      if (currentProgress !== null && rule.progress <= currentProgress) {
        return null;
      }
      return { phase: rule.phase, progress: rule.progress };
    }
  }
  return null;
}
