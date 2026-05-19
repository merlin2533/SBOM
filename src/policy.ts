// ─────────────────────────────────────────────────────────────────────────────
// Policy Engine
//
// Evaluates a set of rules against job metrics. Config loaded from
// $POLICY_FILE or ${SCRATCH_DIR}/policy.json; falls back to built-in defaults.
// ─────────────────────────────────────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import os from 'os';

// ── Types ─────────────────────────────────────────────────────────────────────

export type PolicyAction = 'fail' | 'warn';

export interface PolicyCondition {
  criticalCount?: string;   // e.g. ">0"
  kevCount?: string;
  gradeBelow?: string;      // e.g. "C" → triggers when grade is D or F
  eolCount?: string;
  highCount?: string;
  typosquatCount?: string;
  score?: string;           // e.g. "<50"
}

export interface PolicyRule {
  id: string;
  when: PolicyCondition;
  action: PolicyAction;
  message?: string;
}

export interface PolicyConfig {
  rules: PolicyRule[];
}

export interface PolicyMetrics {
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  kevCount: number;
  eolCount: number;
  typosquatCount: number;
  grade: string;   // A+, A, B, C, D, F
  score: number;   // 0..100
}

export interface PolicyRuleResult {
  ruleId: string;
  action: PolicyAction;
  triggered: boolean;
  message: string;
}

export interface PolicyResult {
  passed: boolean;
  results: PolicyRuleResult[];
}

// ── Default policy ────────────────────────────────────────────────────────────

const DEFAULT_POLICY: PolicyConfig = {
  rules: [
    { id: 'no-critical', when: { criticalCount: '>0' }, action: 'fail', message: 'Critical CVEs found' },
    { id: 'no-kev',      when: { kevCount: '>0' },      action: 'fail', message: 'CISA KEV vulnerabilities present' },
    { id: 'min-grade',   when: { gradeBelow: 'C' },     action: 'warn', message: 'Quality score below grade C' },
    { id: 'no-eol',      when: { eolCount: '>0' },      action: 'warn', message: 'End-of-life components detected' },
  ],
};

// ── Config loading ────────────────────────────────────────────────────────────

function policyFilePath(): string {
  return (
    process.env['POLICY_FILE'] ??
    path.join(
      process.env['SCRATCH_DIR'] ?? path.join(os.tmpdir(), 'sbom-upload-app'),
      'policy.json'
    )
  );
}

let _cached: PolicyConfig | null = null;

export function loadPolicyConfig(forceReload = false): PolicyConfig {
  if (_cached && !forceReload) return _cached;

  const filePath = policyFilePath();
  try {
    const txt = fs.readFileSync(filePath, 'utf8');
    const raw = JSON.parse(txt) as unknown;
    if (
      typeof raw === 'object' && raw !== null &&
      'rules' in raw && Array.isArray((raw as { rules: unknown }).rules)
    ) {
      _cached = raw as PolicyConfig;
      return _cached;
    }
  } catch {
    // File missing or invalid → use defaults
  }
  _cached = DEFAULT_POLICY;
  return _cached;
}

/** For testing: reset config cache */
export function _resetPolicyConfig(): void {
  _cached = null;
}

// ── Condition evaluator ───────────────────────────────────────────────────────

const GRADE_RANK: Record<string, number> = {
  'A+': 0, 'A': 1, 'B': 2, 'C': 3, 'D': 4, 'F': 5,
};

function parseNumericCondition(cond: string, value: number): boolean {
  const m = cond.match(/^([<>]=?|==?)\s*(\d+(?:\.\d+)?)$/);
  if (!m) return false;
  const op = m[1]!;
  const threshold = parseFloat(m[2]!);
  if (op === '>'  || op === 'gt') return value > threshold;
  if (op === '>=' || op === 'gte') return value >= threshold;
  if (op === '<'  || op === 'lt') return value < threshold;
  if (op === '<=' || op === 'lte') return value <= threshold;
  if (op === '==' || op === '=') return value === threshold;
  return false;
}

function evaluateCondition(cond: PolicyCondition, metrics: PolicyMetrics): boolean {
  // All specified conditions must be true (AND)
  if (cond.criticalCount !== undefined) {
    if (!parseNumericCondition(cond.criticalCount, metrics.criticalCount)) return false;
  }
  if (cond.highCount !== undefined) {
    if (!parseNumericCondition(cond.highCount, metrics.highCount)) return false;
  }
  if (cond.kevCount !== undefined) {
    if (!parseNumericCondition(cond.kevCount, metrics.kevCount)) return false;
  }
  if (cond.eolCount !== undefined) {
    if (!parseNumericCondition(cond.eolCount, metrics.eolCount)) return false;
  }
  if (cond.typosquatCount !== undefined) {
    if (!parseNumericCondition(cond.typosquatCount, metrics.typosquatCount)) return false;
  }
  if (cond.score !== undefined) {
    if (!parseNumericCondition(cond.score, metrics.score)) return false;
  }
  if (cond.gradeBelow !== undefined) {
    const thresholdRank = GRADE_RANK[cond.gradeBelow];
    const actualRank = GRADE_RANK[metrics.grade];
    if (thresholdRank === undefined || actualRank === undefined) return false;
    // "gradeBelow C" triggers when actual grade rank > threshold rank
    if (!(actualRank > thresholdRank)) return false;
  }
  return true;
}

// ── Public API ────────────────────────────────────────────────────────────────

export function evaluatePolicy(metrics: PolicyMetrics): PolicyResult {
  const config = loadPolicyConfig();
  const results: PolicyRuleResult[] = [];
  let anyFail = false;

  for (const rule of config.rules) {
    const triggered = evaluateCondition(rule.when, metrics);
    if (triggered && rule.action === 'fail') anyFail = true;

    const message =
      rule.message ??
      (triggered
        ? `Rule "${rule.id}" condition met`
        : `Rule "${rule.id}" not triggered`);

    results.push({
      ruleId: rule.id,
      action: rule.action,
      triggered,
      message,
    });
  }

  return {
    passed: !anyFail,
    results,
  };
}
