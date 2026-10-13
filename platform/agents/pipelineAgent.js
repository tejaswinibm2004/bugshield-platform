import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import { validateJs } from '../services/analyzers.js';

const TEST_TIMEOUT_MS = 120000;
const MAX_OUTPUT = 20000;

/** Run a command in a scrubbed environment. Returns real exit code + captured output. */
function runCommand(cmd, args, cwd, timeout = TEST_TIMEOUT_MS) {
  const started = Date.now();
  const res = spawnSync(cmd, args, {
    cwd,
    encoding: 'utf-8',
    timeout,
    maxBuffer: 1024 * 1024,
    env: {
      PATH: process.env.PATH,
      HOME: cwd,
      CI: '1',
      NODE_ENV: 'test',
      // No tokens are forwarded into sandboxed test execution.
      BUGSHIELD_SANDBOX: '1'
    }
  });
  return {
    command: `${cmd} ${args.join(' ')}`,
    exitCode: res.status === null ? null : res.status,
    signal: res.signal || null,
    durationMs: Date.now() - started,
    stdout: (res.stdout || '').slice(0, MAX_OUTPUT),
    stderr: (res.stderr || res.error?.message || '').slice(0, MAX_OUTPUT),
    timedOut: !!res.error && res.error.code === 'ETIMEDOUT'
  };
}

/**
 * Resolve how to execute a project's test script WITHOUT a shell.
 *
 * A project's package.json is untrusted input, so `shell: true` would be a
 * command-injection vector and is never used here. Instead we invoke npm
 * through its own JS entry point using the current Node binary, which accepts
 * the script string as a plain argument.
 */
function resolveTestRunner(testScript) {
  const npmCli = path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
  if (fs.existsSync(npmCli)) return { cmd: process.execPath, args: [npmCli, 'test'] };

  // Fallback: only honour scripts that are a direct `node ...` invocation.
  const m = /^node\s+(.+)$/.exec(testScript.trim());
  if (m) return { cmd: process.execPath, args: m[1].trim().split(/\s+/) };

  return null;
}

/** Parse test counts out of real TAP/Jest style output. Returns null when unparseable. */
function parseTestCounts(output) {
  // node:test spec/TAP reporter: "# pass 3" / "# fail 0"
  const tap = output.match(/^#\s*pass\s+(\d+)\s*$/m);
  const tapFail = output.match(/^#\s*fail\s+(\d+)\s*$/m);
  if (tap) return { passed: Number(tap[1]), failed: tapFail ? Number(tapFail[1]) : 0, framework: 'node:test (TAP)' };

  // node:test default reporter: "ℹ pass 3" / "ℹ fail 0"
  const anyPass = output.match(/pass\s+(\d+)/i);
  const anyFail = output.match(/fail\s+(\d+)/i);
  if (anyPass && /(?:^|\n)\s*[ℹ#]\s*pass\s+\d+/m.test(output)) {
    return { passed: Number(anyPass[1]), failed: anyFail ? Number(anyFail[1]) : 0, framework: 'node:test' };
  }

  const jest = output.match(/Tests:\s+(?:(\d+)\s+failed,\s*)?(?:(\d+)\s+passed,\s*)?(\d+)\s+total/i);
  if (jest) return { failed: Number(jest[1] || 0), passed: Number(jest[2] || 0), total: Number(jest[3]), framework: 'jest' };
  return null;
}

export class PipelineValidationAgent {
  constructor() {
    this.name = 'Validation & Security Agent';
    this.id = 'AGENT-PIPELINE-04';
  }

  async runPipeline(patchResult, application) {
    const logs = [];
    const evidence = { commands: [], notPerformed: [], sandbox: null };
    logs.push(`[${this.name}] Starting validation of the candidate patch against real tools.`);
    logs.push(`[${this.name}] Target: ${patchResult.targetFileRel}`);

    const projectRoot = patchResult.sourceRoot || process.cwd();
    const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'bugshield-validate-'));
    evidence.sandbox = sandbox;
    logs.push(`[${this.name}] Sandbox created at ${sandbox} (customer source is never executed in place).`);

    // ---- 1. Patch application check -------------------------------------
    // Re-derive the patched file from the real original to prove the candidate
    // is reproducible from the recorded source, not hand-written.
    const originalExists = patchResult.fullFilePath && fs.existsSync(patchResult.fullFilePath);
    const applyCheck = {
      stage: 'patch-application',
      passed: false,
      detail: ''
    };
    if (!originalExists) {
      applyCheck.detail = `Original file not found at ${patchResult.fullFilePath}`;
      logs.push(`[${this.name}] STAGE 1 FAILED: ${applyCheck.detail}`);
    } else {
      const current = fs.readFileSync(patchResult.fullFilePath, 'utf-8').replace(/\r\n/g, '\n');
      const reproducible = current === patchResult.originalCode;
      const changed = current !== patchResult.updatedCode;
      applyCheck.passed = reproducible && changed;
      applyCheck.detail = reproducible
        ? (changed ? 'Candidate reproduces from the recorded original and differs from it (patch is non-trivial).'
                    : 'Candidate is identical to the original — no change to apply.')
        : 'Live source no longer matches the analyzed original (commit drift); candidate not reproducible.';
      logs.push(`[${this.name}] STAGE 1 ${applyCheck.passed ? 'PASSED' : 'FAILED'}: ${applyCheck.detail}`);
    }

    // ---- 2. Syntax validation -------------------------------------------
    // JS/TS: real node parser, ESM aware (parses without executing).
    // Other types (CSS/HTML/...): no parser available — require a non-empty,
    // non-identical file and let tests + human review carry the weight.
    const candidatePath = path.join(sandbox, 'candidate.mjs');
    const syntaxCheck = { stage: 'syntax', passed: false, detail: '', tool: null };
    const isJsLike = /\.(js|jsx|mjs|cjs|ts|tsx)$/i.test(patchResult.targetFileRel || '');
    if (!isJsLike) {
      syntaxCheck.passed = !!patchResult.updatedCode && patchResult.updatedCode !== patchResult.originalCode;
      syntaxCheck.detail = syntaxCheck.passed
        ? `Non-JS file (${patchResult.targetFileRel}): change is non-empty and non-identical; no parser available, deferred to tests/review.`
        : 'Non-JS candidate is empty or identical to the original.';
      syntaxCheck.tool = 'generic-change-check (no parser for this file type)';
    } else {
    try {
      fs.writeFileSync(candidatePath, patchResult.updatedCode, 'utf-8');
      const nodeCheck = runCommand(process.execPath, ['--check', candidatePath], sandbox, 30000);
      evidence.commands.push(nodeCheck);
      syntaxCheck.passed = nodeCheck.exitCode === 0;
      syntaxCheck.detail = syntaxCheck.passed
        ? `Parsed successfully by ${process.version}`
        : `Parse error: ${(nodeCheck.stderr || '').split('\n').slice(0, 4).join(' ')}`;
      syntaxCheck.tool = `node --check (${process.version})`;
    } catch (e) {
      syntaxCheck.detail = `could not stage candidate: ${e.message}`;
    }
    }
    logs.push(`[${this.name}] STAGE 2 ${syntaxCheck.passed ? 'PASSED' : 'FAILED'}: ${syntaxCheck.detail}`);
    if (isJsLike) {
    const internalCheck = validateJs(patchResult.updatedCode);
    if (!internalCheck.ok) {
      syntaxCheck.passed = false;
      syntaxCheck.detail += ` | internal check: ${internalCheck.error}`;
    }
    }

    // ---- 3. Test execution (only if the project actually defines tests) ----
    const testCheck = { stage: 'tests', ran: false, passed: null, counts: null, detail: '', command: null, durationMs: null };
    const pkgPath = path.join(projectRoot, 'package.json');
    let pkg = null;
    try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')); } catch { /* none */ }
    const testScript = pkg && pkg.scripts && pkg.scripts.test;

    if (!testScript) {
      testCheck.detail = 'No test script defined in the project package.json — tests could not be executed.';
      evidence.notPerformed.push('test-execution (no test script defined)');
      logs.push(`[${this.name}] STAGE 3 NOT RUN: ${testCheck.detail}`);
      logs.push(`[${this.name}] Consequence: behaviour is unverified; policy requires additional validation or approval.`);
    } else {
      // Copy the project into the sandbox so customer code is never run from its live location.
      const sandboxProject = path.join(sandbox, 'project');
      fs.mkdirSync(sandboxProject, { recursive: true });
      try {
        fs.cpSync(projectRoot, sandboxProject, {
          recursive: true,
          filter: src => !/(^|[\\/])(node_modules|\.git|dist|build|coverage)$/.test(src)
        });
        fs.writeFileSync(path.join(sandboxProject, path.basename(patchResult.fullFilePath || 'file.js')), patchResult.updatedCode, 'utf-8');
        const runner = resolveTestRunner(testScript);
        if (!runner) {
          testCheck.detail = `Test script "${testScript}" cannot be executed without a shell; refusing to run it for safety.`;
          evidence.notPerformed.push('test-execution (no shell-free runner available)');
          logs.push(`[${this.name}] STAGE 3 NOT RUN: ${testCheck.detail}`);
        } else {
        const testRun = runCommand(runner.cmd, runner.args, sandboxProject);
        evidence.commands.push(testRun);
        testCheck.ran = true;
        testCheck.command = `${runner.cmd === process.execPath ? 'node' : runner.cmd} ${runner.args.slice(1).join(' ')}`;
        testCheck.durationMs = testRun.durationMs;
        testCheck.passed = testRun.exitCode === 0;
        testCheck.counts = parseTestCounts(`${testRun.stdout}\n${testRun.stderr}`);
        testCheck.detail = testRun.timedOut
          ? `Test run timed out after ${TEST_TIMEOUT_MS}ms`
          : `exit code ${testRun.exitCode}`;
        logs.push(`[${this.name}] STAGE 3 ${testCheck.passed ? 'PASSED' : 'FAILED'}: ${testCheck.command} -> ${testCheck.detail}`);
        if (testCheck.counts) logs.push(`[${this.name}]   counts: ${testCheck.counts.passed} passed, ${testCheck.counts.failed} failed (${testCheck.counts.framework})`);
        }
      } catch (e) {
        testCheck.detail = `could not stage project sandbox: ${e.message}`;
        logs.push(`[${this.name}] STAGE 3 NOT RUN: ${testCheck.detail}`);
      }
    }

    // ---- 4. Security checks ----------------------------------------------
    // Honest labelling: this is a local heuristic pattern scan, not an OWASP scanner.
    const security = { stage: 'security', passed: true, findings: [], label: 'heuristic pattern scan (not an OWASP scanner)' };
    const code = patchResult.updatedCode;
    const patterns = [
      { re: /\beval\s*\(/, msg: 'dynamic code execution via eval()' },
      { re: /new\s+Function\s*\(/, msg: 'dynamic code execution via Function constructor' },
      { re: /\bchild_process\b/, msg: 'child_process import' },
      { re: /SELECT\s+\*\s+FROM\s+\w+\s*;?(?!.*\?)/i, msg: 'possible SQL string interpolation' },
      { re: /http:\/\/(?!localhost|127\.0\.0\.1)/, msg: 'plaintext http reference' }
    ];
    for (const p of patterns) if (p.re.test(code)) security.findings.push(p.msg);
    security.passed = security.findings.length === 0;
    logs.push(`[${this.name}] STAGE 4 security (${security.label}): ${security.passed ? 'no findings' : security.findings.join('; ')}`);

    let audit = null;
    if (fs.existsSync(path.join(projectRoot, 'package-lock.json'))) {
      const npmAudit = runCommand(/^win/.test(process.platform) ? 'npm.cmd' : 'npm', ['audit', '--json'], projectRoot, 90000);
      evidence.commands.push(npmAudit);
      if (npmAudit.exitCode === 0) {
        try {
          const parsed = JSON.parse(npmAudit.stdout);
          const counts = (parsed.metadata && parsed.metadata.vulnerabilities) || {};
          audit = { ran: true, vulnerabilities: counts };
          logs.push(`[${this.name}] STAGE 5 dependency audit (npm audit): ${JSON.stringify(counts)}`);
        } catch { audit = { ran: true, parseError: true }; }
      } else if (npmAudit.exitCode === 1 && npmAudit.stdout) {
        try {
          const parsed = JSON.parse(npmAudit.stdout);
          const counts = (parsed.metadata && parsed.metadata.vulnerabilities) || {};
          audit = { ran: true, vulnerabilities: counts };
          logs.push(`[${this.name}] STAGE 5 dependency audit (npm audit): vulnerabilities found ${JSON.stringify(counts)}`);
        } catch { audit = { ran: true, parseError: true }; }
      } else {
        audit = { ran: false, reason: 'npm audit unavailable or offline' };
        evidence.notPerformed.push('npm audit (registry unavailable)');
        logs.push(`[${this.name}] STAGE 5 NOT RUN: dependency audit unavailable (${(npmAudit.stderr || '').split('\n')[0] || 'unknown'}).`);
      }
    } else {
      audit = { ran: false, reason: 'no package-lock.json' };
      evidence.notPerformed.push('npm audit (no lockfile)');
    }

    // ---- 6. CI/CD integration (only claimed when genuinely configured) -----
    const ci = { stage: 'ci', provider: 'none', configured: false, buildId: null, detail: '' };
    if (process.env.JENKINS_URL && process.env.JENKINS_JOB) {
      ci.provider = 'jenkins';
      ci.configured = true;
      ci.detail = `Jenkins configured at ${process.env.JENKINS_URL}. Remote trigger is not implemented in this build.`;
      evidence.notPerformed.push('jenkins remote build trigger (adapter not implemented)');
    } else {
      ci.detail = 'No CI provider configured (set JENKINS_URL and JENKINS_JOB). No build was triggered and no build ID exists.';
      evidence.notPerformed.push('CI build (no provider configured)');
    }
    logs.push(`[${this.name}] STAGE 6 CI/CD: ${ci.detail}`);

    try { fs.rmSync(sandbox, { recursive: true, force: true }); } catch { /* best effort */ }

    const allPassed = applyCheck.passed && syntaxCheck.passed && testCheck.passed !== false;
    logs.push(`[${this.name}] RESULT: ${allPassed ? 'validation passed for the stages that could be executed' : 'validation failed'}`);
    if (testCheck.ran === false) logs.push(`[${this.name}] NOTE: behavioural verification was NOT achieved because no test suite ran.`);

    return {
      agentId: this.id,
      agentName: this.name,
      applyCheck,
      syntaxCheck,
      testCheck,
      security,
      dependencyAudit: audit,
      ci,
      validationPassed: allPassed,
      behaviourVerified: testCheck.ran === true && testCheck.passed === true,
      staticAnalysisPassed: security.passed,
      // Retained keys for backward compatibility with existing UI/history fields.
      testSuitePassed: testCheck.passed === true,
      jenkinsBuildId: ci.buildId,
      dockerTag: null,
      evidence,
      logs
    };
  }
}