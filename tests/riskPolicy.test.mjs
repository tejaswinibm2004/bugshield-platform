/**
 * Risk policy enforcement tests.
 *
 * The critical property: a low score must never override governance. Automatic
 * deployment is off unless the tenant explicitly enabled it, and thresholds are
 * per organisation.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import { RiskClassificationAgent } from '../platform/agents/riskAgent.js';

const detection = {
  targetFileRel: 'src/util/helper.js',   // shared module
  bugType: 'MISSING_AWAIT',             // lower-weight defect class
  confidence: 0.6
};
const issue = { title: 'order not saved', description: 'sometimes fails' };

test('with no policy, automatic deployment is disabled', async () => {
  const r = await new RiskClassificationAgent().classify(detection, issue);
  assert.equal(r.policy.autoDeploy, false, 'auto-deploy must default to off');
  assert.equal(r.requiresAdminApproval, true);
});

test('a low score still requires approval when auto-deploy is not enabled', async () => {
  const r = await new RiskClassificationAgent().classify(detection, issue, { high: 90, low: 10, autoDeploy: false, version: 2 });
  assert.ok(r.riskScore < 90, 'score should be below the tenant threshold');
  assert.equal(r.requiresAdminApproval, true, 'a low score must not grant automatic deployment');
  assert.match(r.logs.join('\n'), /automatic deployment is disabled/);
});

test('enabling auto-deploy below threshold permits automation', async () => {
  const r = await new RiskClassificationAgent().classify(detection, issue, { high: 90, low: 10, autoDeploy: true, version: 1 });
  assert.equal(r.requiresAdminApproval, false, 'explicit opt-in plus below threshold allows automation');
  assert.match(r.logs.join('\n'), /eligible for canary deployment/);
});

test('auto-deploy never overrides a score at or above the threshold', async () => {
  const r = await new RiskClassificationAgent().classify(detection, issue, { high: 10, low: 5, autoDeploy: true, version: 1 });
  assert.ok(r.riskScore >= 10);
  assert.equal(r.requiresAdminApproval, true, 'threshold must win even with auto-deploy on');
});

test('thresholds are read from the supplied policy, not global constants', async () => {
  const strict = await new RiskClassificationAgent().classify(detection, issue, { high: 30, low: 10, autoDeploy: false });
  const lenient = await new RiskClassificationAgent().classify(detection, issue, { high: 95, low: 80, autoDeploy: false });
  assert.notEqual(strict.riskLevel, lenient.riskLevel, 'different thresholds must produce different levels');
  assert.equal(strict.policy.high, 30);
  assert.equal(lenient.policy.high, 95);
});

test('the score itself is policy-independent, so tenants cannot inflate it', async () => {
  const a = await new RiskClassificationAgent().classify(detection, issue, { high: 30, low: 10, autoDeploy: false });
  const b = await new RiskClassificationAgent().classify(detection, issue, { high: 95, low: 80, autoDeploy: true });
  assert.equal(a.riskScore, b.riskScore, 'weighting must not depend on the tenant policy');
});

test('breakdown always sums to the clamped score and records the policy version', async () => {
  const r = await new RiskClassificationAgent().classify(
    { targetFileRel: 'src/payment/gateway.js', bugType: 'DIV_ZERO', confidence: 0.9 },
    { title: 'invoice total wrong', description: 'payment amount incorrect' },
    { id: 'RP-ORG-3', version: 3, high: 70, low: 40, autoDeploy: false }
  );
  const sum = r.breakdown.reduce((s, b) => s + b.points, 0);
  assert.equal(r.riskScore, Math.max(5, Math.min(100, sum)));
  assert.equal(r.policy.version, 3);
  assert.equal(r.policy.id, 'RP-ORG-3');
  assert.ok(r.breakdown.length >= 4);
});

test('security-critical paths cannot be classified LOW, even under a permissive policy', async () => {
  const r = await new RiskClassificationAgent().classify(
    { targetFileRel: 'src/auth/login.js', bugType: 'NULL_DEREF', confidence: 0.5 },
    { title: 'login broken', description: 'session error' },
    { high: 99, low: 90, autoDeploy: true, version: 1 }
  );
  // The tenant asked for everything to be LOW; the floor overrides that.
  assert.notEqual(r.riskLevel, 'LOW', 'security-critical code must never be LOW risk');
  assert.equal(r.riskLevel, 'MEDIUM');
  assert.equal(r.floorApplied, true, 'the override must be recorded, not silent');
  assert.equal(r.securitySensitive, true);
  assert.equal(r.requiresAdminApproval, true, 'security-critical changes always need a human');
});

test('the default policy still escalates security-critical paths to HIGH', async () => {
  const r = await new RiskClassificationAgent().classify(
    { targetFileRel: 'src/auth/login.js', bugType: 'NULL_DEREF', confidence: 0.5 },
    { title: 'login broken', description: 'session error' }
  );
  assert.equal(r.riskLevel, 'HIGH');
  assert.equal(r.requiresAdminApproval, true);
});