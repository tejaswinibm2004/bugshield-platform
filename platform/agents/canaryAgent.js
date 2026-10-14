import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import { validateJs } from '../services/analyzers.js';

const BACKUP_EXT = '.bugshield.bak';

function run(cmd, args, cwd) {
  return execFileSync(cmd, args, { cwd, stdio: 'pipe', encoding: 'utf-8', timeout: 120000 }).trim();
}
function safeRun(cmd, args, cwd) {
  try { return { ok: true, out: run(cmd, args, cwd) }; }
  catch (err) { return { ok: false, error: (err.stderr?.toString() || err.message || 'failed').split('\n').filter(Boolean).slice(-1)[0] }; }
}

export class CanaryDeploymentAgent {
  constructor() {
    this.name = 'Canary Testing & Deployment Agent';
    this.id = 'AGENT-CANARY-05';
  }

  async deploy(patchResult, pipelineResult, application) {
    const logs = [];
    logs.push(`[${this.name}] Initiating deployment for ${application.name} (${application.id})...`);
    if (pipelineResult.dockerTag) logs.push(`[${this.name}] Build artifact: ${pipelineResult.dockerTag}`);
    else logs.push(`[${this.name}] No container artifact was produced by the validation stage.`);
    logs.push(`[${this.name}] Target file: ${patchResult.targetFileRel}`);

    // 1. Health verification — performed only against a real, configured endpoint.
    const healthUrl = application.healthUrl || process.env.HEALTH_CHECK_URL || null;
    const health = { performed: false, url: null, checks: [], allOk: false, reason: null };
    if (healthUrl) {
      health.performed = true;
      health.url = healthUrl;
      logs.push(`[${this.name}] Step 1: Probing configured health endpoint ${healthUrl}...`);
      for (let i = 1; i <= 3; i++) {
        const started = Date.now();
        let ok = false, status = null, err = null;
        try {
          const ctrl = new AbortController();
          const t = setTimeout(() => ctrl.abort(), 5000);
          const res = await fetch(healthUrl, { signal: ctrl.signal });
          clearTimeout(t);
          status = res.status;
          ok = res.ok;
        } catch (e) { err = e.message; }
        const latency = Date.now() - started;
        health.checks.push({ attempt: i, status, latencyMs: latency, ok, error: err });
        logs.push(`[${this.name}] Probe #${i}: GET ${healthUrl} -> ${status !== null ? status + ' ' + (ok ? 'OK' : 'NOT OK') : 'ERROR ' + err} (${latency}ms)`);
      }
      health.allOk = health.checks.every(c => c.ok);
      logs.push(health.allOk
        ? `[${this.name}] Step 2: All ${health.checks.length} health probes succeeded.`
        : `[${this.name}] Step 2: ${health.checks.filter(c => !c.ok).length} of ${health.checks.length} health probes FAILED.`);
    } else {
      health.reason = 'No health endpoint configured for this application (set application.healthUrl or HEALTH_CHECK_URL).';
      logs.push(`[${this.name}] Step 1 SKIPPED: ${health.reason}`);
      logs.push(`[${this.name}] Consequence: deployment proceeds on validation evidence only; no live traffic verification was performed.`);
    }

    const target = patchResult.fullFilePath;
    const backup = target + BACKUP_EXT;
    let writeSuccess = false;
    let rolledBack = false;

    if (!patchResult.syntaxValid || !target || !fs.existsSync(target)) {
      logs.push(`[${this.name}] ❌ Refusing to deploy: ${!fs.existsSync(target) ? `target file missing (${target})` : 'patch did not pass syntax validation'}.`);
      return { agentId: this.id, agentName: this.name, canaryStatus: 'FAILED', deploymentStatus: 'FAILED', writeSuccess: false, rolledBack: false, logs };
    }

    // 2. Write with a real backup for rollback
    try {
      fs.copyFileSync(target, backup);
      logs.push(`[${this.name}] Step 4: Backed up original file to ${path.basename(backup)}.`);
      const lineEnding = patchResult.lineEnding || '\n';
      const expected = patchResult.updatedCode.replace(/\r?\n/g, '\n');
      fs.writeFileSync(target, patchResult.updatedCode.replace(/\r?\n/g, lineEnding), 'utf-8');
      // Integrity first (all file types): the bytes on disk must equal the
      // validated candidate. Syntax parsing second, JS-like files only —
      // running a JS parser over CSS/HTML always fails and false-rolls-back.
      const onDisk = fs.readFileSync(target, 'utf-8').replace(/\r\n/g, '\n');
      if (onDisk !== expected) throw new Error('post-write verification failed: disk content differs from the validated candidate.');
      if (/\.(js|jsx|mjs|cjs|ts|tsx)$/i.test(patchResult.targetFileRel || '')) {
        const v = validateJs(onDisk);
        if (!v.ok) throw new Error(`post-write validation failed: ${v.error}`);
      } else {
        logs.push(`[${this.name}] Non-JS target (${patchResult.targetFileRel}): byte-integrity verified, no parser available for this type.`);
      }
      writeSuccess = true;
      logs.push(`[${this.name}] ✅ Live source file updated and re-validated on disk.`);
    } catch (err) {
      logs.push(`[${this.name}] ❌ ERROR applying patch: ${err.message}`);
      try { if (fs.existsSync(backup)) { fs.copyFileSync(backup, target); rolledBack = true; logs.push(`[${this.name}] Restored original file from backup.`); } } catch { }
      return { agentId: this.id, agentName: this.name, canaryStatus: 'PASSED', deploymentStatus: 'ROLLED_BACK', writeSuccess: false, rolledBack: true, logs };
    }

    // 3. Commit & push to the CUSTOMER's repository only
    const fileDir = path.dirname(target);
    const toplevel = safeRun('git', ['-C', fileDir, 'rev-parse', '--show-toplevel']);
    if (!toplevel.ok) {
      logs.push(`[${this.name}] Git: ${fileDir} is not inside a Git repository — deployed to disk without a remote push.`);
    } else {
      const repoRoot = toplevel.out;
      const remote = safeRun('git', ['-C', repoRoot, 'remote', 'get-url', 'origin']);
      const appRepo = application.repoUrl || '';
      const norm = s => s.trim().replace(/\.git$/, '').toLowerCase();
      if (!remote.ok) {
        logs.push(`[${this.name}] Git: repository has no 'origin' remote — skipping remote push.`);
      } else if (appRepo && norm(remote.out) !== norm(appRepo)) {
        logs.push(`[${this.name}] Git: local origin (${remote.out}) does not match the connected repository (${appRepo}) — skipping push to avoid contaminating another repo.`);
      } else {
        const relFromRoot = path.relative(repoRoot, target).replace(/\\/g, '/');
        logs.push(`[${this.name}] Git: committing ${relFromRoot} to ${remote.out}`);
        const add = safeRun('git', ['-C', repoRoot, 'add', relFromRoot]);
        if (add.ok) {
          const commit = safeRun('git', ['-C', repoRoot, 'commit', '-m', `fix(bugshield): automated remediation for ${relFromRoot}`]);
          if (commit.ok) {
            const push = safeRun('git', ['-C', repoRoot, 'push', 'origin', 'HEAD']);
            logs.push(push.ok
              ? `[${this.name}] 🚀 GIT PUSH SUCCESS: fix pushed to ${remote.out}.`
              : `[${this.name}] Git: commit created locally; push skipped/failed — ${push.error}`);
          } else {
            logs.push(`[${this.name}] Git: nothing to commit or commit failed — ${commit.error}`);
          }
        } else {
          logs.push(`[${this.name}] Git: add failed — ${add.error}`);
        }
      }
    }

    // 4. Roll back when a configured health check proves the release is unhealthy
    if (writeSuccess && health.performed && !health.allOk) {
      try {
        fs.copyFileSync(backup, target);
        rolledBack = true;
        logs.push(`[${this.name}] Health verification FAILED — restoring the previous file from backup.`);
      } catch (e) {
        logs.push(`[${this.name}] CRITICAL: rollback failed: ${e.message}. Manual intervention required.`);
      }
    }

    const strategy = 'in-place source update';
    logs.push(`[${this.name}] Strategy: ${strategy}. This is NOT a zero-downtime strategy — no blue/green or rolling adapter is configured for this target.`);
    logs.push(`[${this.name}] Outcome: ${rolledBack ? 'rolled back to the previous file' : writeSuccess ? 'file updated on disk' : 'deployment failed'}.`);
    if (!health.performed) logs.push(`[${this.name}] Verification scope: disk write with byte-integrity check (plus syntax re-validation for JS targets) only. Live traffic health was NOT verified.`);

    return {
      agentId: this.id,
      agentName: this.name,
      canaryStatus: health.performed ? (health.allOk ? 'PASSED' : 'FAILED') : 'NOT_PERFORMED',
      deploymentStatus: rolledBack ? 'ROLLED_BACK' : (writeSuccess ? 'DEPLOYED' : 'FAILED'),
      strategy,
      zeroDowntime: false,
      health,
      promotedAt: new Date().toISOString(),
      writeSuccess,
      rolledBack,
      backupFile: fs.existsSync(backup) ? backup : null,
      logs
    };
  }
}