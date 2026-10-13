/**
 * Real automated tests. Run: npm test
 * Uses the built-in Node test runner (no external dependencies).
 *
 * These exercise actual code against actual files. Where an external provider
 * (GitHub, Jenkins, cloud) is required, the test asserts the adapter reports
 * "not configured" rather than fabricating success.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { analyzeFile, applyFinding, unifiedDiff, validateJs } from '../platform/services/analyzers.js';
import { BugDetectionAgent } from '../platform/agents/detectorAgent.js';
import { RiskClassificationAgent } from '../platform/agents/riskAgent.js';
import { PatchGenerationAgent } from '../platform/agents/patchAgent.js';
import { PipelineValidationAgent } from '../platform/agents/pipelineAgent.js';
import { HIGH_THRESHOLD, RISK_BASE_SCORE } from '../platform/services/riskConfig.js';
import { indexSourceFiles } from '../platform/services/workspace.js';

const BENCH = path.join(process.cwd(), 'benchmark', 'cases');
const cases = fs.existsSync(BENCH)
  ? fs.readdirSync(BENCH).filter(d => fs.statSync(path.join(BENCH, d)).isDirectory())
      .map(id => ({ id, ...JSON.parse(fs.readFileSync(path.join(BENCH, id, 'case.json'), 'utf-8')) }))
  : [];

// ---------------------------------------------------------------- analyzers

test('analyzer detects division by zero and produces a syntactically valid patch', () => {
  const code = 'export function f(a, b) {\n  const r = (a * b) / (100 - (b == 100 ? 100 : 0));\n  return r;\n}\n';
  const found = analyzeFile(code, 'src/x.js').filter(f => f.type === 'DIV_ZERO');
  assert.equal(found.length, 1, 'expected exactly one DIV_ZERO finding');
  const patched = applyFinding(code, found[0]);
  assert.ok(patched, 'patch should be produced');
  assert.ok(validateJs(patched).ok, 'patched code must parse');
  assert.match(patched, /__bugShieldSafeDiv/, 'guard helper should be injected');
});

test('analyzer detects un-awaited async persistence call', () => {
  const code = 'async function saveOrderToDatabase(o) { return o; }\nexport async function run(o) {\n  saveOrderToDatabase(o);\n  return true;\n}\n';
  const found = analyzeFile(code, 'src/y.js').filter(f => f.type === 'MISSING_AWAIT');
  assert.equal(found.length, 1);
  const patched = applyFinding(code, found[0]);
  assert.ok(patched.includes('await saveOrderToDatabase'), 'call must be awaited');
  assert.ok(patched.includes('catch'), 'error handling must be added');
});

test('analyzer detects dynamic key that can fall outside an object literal', () => {
  const code = 'const rates = { a: 1.0, b: 2.0 };\nexport function fee(d) {\n  let t = "a";\n  if (d > 10) t = "c";\n  return rates[t];\n}\n';
  const found = analyzeFile(code, 'src/z.js').filter(f => f.type === 'UNDEFINED_DYNAMIC_KEY');
  assert.equal(found.length, 1, 'conditional out-of-keys assignment must be detected');
  assert.ok(validateJs(applyFinding(code, found[0])).ok);
});

test('analyzer reports nothing on clean code (false-positive guard)', () => {
  const code = 'export function sum(xs) { return xs.reduce((a, b) => a + b, 0); }\n';
  assert.equal(analyzeFile(code, 'src/clean.js').length, 0);
});

test('unified diff is a real line diff, not a description stub', () => {
  const before = 'line1\nline2\nline3\n';
  const after = 'line1\nCHANGED\nline3\n';
  const d = unifiedDiff(before, after, 'src/a.js');
  assert.match(d, /^--- a\/src\/a\.js/m);
  assert.match(d, /^\+\+\+ b\/src\/a\.js/m);
  assert.match(d, /^@@ -\d+,\d+ \+\d+,\d+ @@/m);
  assert.ok(d.includes('-line2'));
  assert.ok(d.includes('+CHANGED'));
});

test('validateJs rejects genuinely broken syntax', () => {
  assert.equal(validateJs('function ( { ').ok, false);
  assert.equal(validateJs('const a = 1;').ok, true);
});

// ------------------------------------------------------- agent integration

test('detector resolves source, locates the real file and refuses to invent one', async () => {
  const agent = new BugDetectionAgent();
  const c = cases.find(x => x.id === 'c01-div-zero');
  assert.ok(c, 'corpus case c01 must exist');
  const projectRoot = path.join(BENCH, c.id, 'project');
  const application = { id: 'TEST-APP', name: c.id, repoUrl: '' };
  const issue = { id: 'T1', title: c.report.title, description: c.report.description, stackTrace: '' };

  const previous = process.env.BUGSHIELD_TEST_ROOT;
  // Bind the source root the same way a connected app would be bound.
  const { writeSource, clearSource } = await import('../platform/services/workspace.js');
  writeSource('TEST-APP', { localPath: projectRoot });
  const res = await agent.analyze(issue, application);
  clearSource('TEST-APP');
  if (previous) process.env.BUGSHIELD_TEST_ROOT = previous;

  assert.equal(res.isValidBug, true);
  assert.equal(res.targetFileRel, c.expect.file, 'must locate the ground-truth file');
  assert.equal(res.bugType, c.expect.type);
  assert.ok(res.fullFilePath.startsWith(projectRoot), 'full path must stay inside the authorized root');
});

test('detector reports no source rather than guessing a file', async () => {
  const agent = new BugDetectionAgent();
  const res = await agent.analyze(
    { id: 'T2', title: 'checkout broken', description: 'payment not working', stackTrace: '' },
    { id: 'NOSOURCE-APP', name: 'x', repoUrl: 'https://example.invalid/does-not-exist.git' }
  );
  assert.equal(res.isValidBug, false);
  assert.ok(res.noSource, 'must be flagged as source unavailable');
  assert.equal(res.targetFileRel, undefined, 'must not invent a target file');
});

// ------------------------------------------------------------------- risk

test('risk score is explainable and every factor is reported', async () => {
  const risk = await new RiskClassificationAgent().classify(
    { targetFileRel: 'src/paymentGateway.js', bugType: 'DIV_ZERO', confidence: 0.9 },
    { title: 'invoice total wrong', description: 'payment amount is incorrect' }
  );
  assert.ok(risk.breakdown.length >= 4, 'breakdown must list the contributing factors');
  assert.ok(risk.breakdown.every(b => typeof b.points === 'number' && b.why), 'each factor needs points and a reason');
  const sum = risk.breakdown.reduce((s, b) => s + b.points, 0);
  assert.equal(risk.riskScore, Math.max(5, Math.min(100, sum)), 'score must equal its factors, after clamping to [5,100]');
  assert.ok(risk.riskScore >= RISK_BASE_SCORE);
  assert.ok(risk.riskScore <= 100);
  assert.equal(risk.requiresAdminApproval, risk.riskScore >= HIGH_THRESHOLD, 'approval must follow the threshold');
});

test('a security-critical path always escalates', async () => {
  const risk = await new RiskClassificationAgent().classify(
    { targetFileRel: 'src/auth/login.js', bugType: 'NULL_DEREF', confidence: 0.6 },
    { title: 'login broken', description: 'session handling error' }
  );
  assert.equal(risk.riskLevel, 'HIGH');
  assert.equal(risk.requiresAdminApproval, true);
});

// ------------------------------------------------- validation (real tools)

test('validation runs a real parser and reports honest stage evidence', async () => {
  const sandboxProject = fs.mkdtempSync(path.join(os.tmpdir(), 'bs-val-test-'));
  const filePath = path.join(sandboxProject, 'src', 'calc.js');
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const original = 'export function calc(a, b) {\n  return (a * b) / (100 - (b == 100 ? 100 : 0));\n}\n';
  fs.writeFileSync(filePath, original);

  const { writeSource, clearSource } = await import('../platform/services/workspace.js');
  writeSource('VAL-APP', { localPath: sandboxProject });

  const res = await new PipelineValidationAgent().runPipeline({
    targetFileRel: 'src/calc.js',
    fullFilePath: filePath,
    sourceRoot: sandboxProject,
    originalCode: original,
    updatedCode: 'export function calc(a, b) {\n  return 1;\n}\n',
    syntaxValid: true
  }, { id: 'VAL-APP', name: 'x' });
  clearSource('VAL-APP');
  fs.rmSync(sandboxProject, { recursive: true, force: true });

  assert.equal(res.applyCheck.passed, true, 'patch application check must pass against the recorded original');
  assert.equal(res.syntaxCheck.passed, true, 'node --check must parse the candidate');
  assert.ok(res.evidence.commands.length > 0, 'must record the real commands it executed');
  assert.ok(res.evidence.commands.every(c => 'exitCode' in c), 'each command records an exit code');
  assert.equal(res.testCheck.ran, false, 'no test script exists, so tests must NOT be claimed as run');
  assert.equal(res.behaviourVerified, false, 'behaviour must not be claimed without tests');
  assert.ok(res.ci.configured === false, 'CI must not be claimed when unconfigured');
  assert.equal(res.jenkinsBuildId, null, 'no fabricated build id');
  assert.equal(res.dockerTag, null, 'no fabricated artifact');
});

test('validation actually executes a real test suite when one exists', async () => {
  const p = fs.mkdtempSync(path.join(os.tmpdir(), 'bs-val-test2-'));
  fs.mkdirSync(path.join(p, 'src'), { recursive: true });
  const original = 'export function add(a, b) { return a + b; }\n';
  fs.writeFileSync(path.join(p, 'src', 'add.js'), original);
  fs.writeFileSync(path.join(p, 'package.json'), JSON.stringify({
    name: 'fixture', type: 'module',
    scripts: { test: 'node --test' }
  }));
  fs.writeFileSync(path.join(p, 'src', 'add.test.js'), `
import test from 'node:test';
import assert from 'node:assert/strict';
import { add } from './add.js';
test('adds', () => assert.equal(add(1,2), 3));
`);

  const { writeSource, clearSource } = await import('../platform/services/workspace.js');
  writeSource('VAL-APP2', { localPath: p });
  const res = await new PipelineValidationAgent().runPipeline({
    targetFileRel: 'src/add.js',
    fullFilePath: path.join(p, 'src', 'add.js'),
    sourceRoot: p,
    originalCode: original,
    updatedCode: 'export function add(a, b) { return a + b; }\n',
    syntaxValid: true
  }, { id: 'VAL-APP2', name: 'x' });
  clearSource('VAL-APP2');
  fs.rmSync(p, { recursive: true, force: true });

  assert.equal(res.testCheck.ran, true, 'test suite must actually execute');
  assert.equal(res.testCheck.passed, true, 'the real suite must pass');
  assert.equal(res.behaviourVerified, true, 'behaviour may only be verified when tests ran');
  assert.ok(res.testCheck.counts && res.testCheck.counts.passed >= 1, 'real counts must be parsed');
});

test('validation reports failure when the real suite fails', async () => {
  const p = fs.mkdtempSync(path.join(os.tmpdir(), 'bs-val-test3-'));
  fs.mkdirSync(path.join(p, 'src'), { recursive: true });
  const original = 'export function add(a, b) { return a - b; }\n';
  fs.writeFileSync(path.join(p, 'src', 'add.js'), original);
  fs.writeFileSync(path.join(p, 'package.json'), JSON.stringify({ name: 'fixture', type: 'module', scripts: { test: 'node --test' } }));
  fs.writeFileSync(path.join(p, 'src', 'add.test.js'), `
import test from 'node:test';
import assert from 'node:assert/strict';
import { add } from './add.js';
test('adds', () => assert.equal(add(1,2), 3));
`);
  const { writeSource, clearSource } = await import('../platform/services/workspace.js');
  writeSource('VAL-APP3', { localPath: p });
  const res = await new PipelineValidationAgent().runPipeline({
    targetFileRel: 'src/add.js', fullFilePath: path.join(p, 'src', 'add.js'), sourceRoot: p,
    originalCode: original, updatedCode: 'export function add(a, b) { return a + b; }\n', syntaxValid: true
  }, { id: 'VAL-APP3', name: 'x' });
  clearSource('VAL-APP3');
  fs.rmSync(p, { recursive: true, force: true });

  assert.equal(res.testCheck.ran, true);
  assert.equal(res.testCheck.passed, false, 'a failing real suite must not be reported as passing');
  assert.equal(res.validationPassed, false, 'validation must fail and block deployment');
});

test('validation detects source drift so stale patches cannot deploy', async () => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'bs-val-drift-'));
  fs.mkdirSync(path.join(sandbox, 'src'), { recursive: true });
  const f = path.join(sandbox, 'src', 'd.js');
  fs.writeFileSync(f, 'export const v = 2; // drifted\n');
  const res = await new PipelineValidationAgent().runPipeline({
    targetFileRel: 'src/d.js', fullFilePath: f, sourceRoot: sandbox,
    originalCode: 'export const v = 1;\n', updatedCode: 'export const v = 3;\n', syntaxValid: true
  }, { id: 'DRIFT', name: 'x' });
  fs.rmSync(sandbox, { recursive: true, force: true });
  assert.equal(res.applyCheck.passed, false, 'drift must be detected');
});

// -------------------------------------------------------------- patch agent

test('patch agent refuses to emit a diff when the candidate does not parse', async () => {
  const original = 'export const a = 1;\n';
  const res = await new PatchGenerationAgent().generate({
    bugType: 'DIV_ZERO', targetFileRel: 'src/a.js', fullFilePath: '/tmp/a.js',
    sourceRoot: '/tmp', fileContent: original,
    finding: { type: 'DIV_ZERO', autoFixable: false, description: 'not auto-fixable' }
  }, { riskLevel: 'LOW' });
  assert.equal(res.syntaxValid, false);
  assert.equal(res.diff, '', 'no diff may be produced for an unvalidated candidate');
});

// --------------------------------------------------------------- traversal

test('source indexing ignores dependency and build directories', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bs-index-'));
  fs.mkdirSync(path.join(root, 'node_modules', 'pkg'), { recursive: true });
  fs.mkdirSync(path.join(root, 'dist'), { recursive: true });
  fs.mkdirSync(path.join(root, 'src'), { recursive: true });
  fs.writeFileSync(path.join(root, 'node_modules', 'pkg', 'index.js'), 'x');
  fs.writeFileSync(path.join(root, 'dist', 'bundle.js'), 'x');
  fs.writeFileSync(path.join(root, 'src', 'real.js'), 'x');
  const files = indexSourceFiles(root).map(f => f.rel);
  fs.rmSync(root, { recursive: true, force: true });
  assert.deepEqual(files, ['src/real.js']);
});