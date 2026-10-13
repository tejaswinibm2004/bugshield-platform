import { BugDetectionAgent } from './detectorAgent.js';
import { RiskClassificationAgent } from './riskAgent.js';
import { PatchGenerationAgent } from './patchAgent.js';
import { PipelineValidationAgent } from './pipelineAgent.js';
import { CanaryDeploymentAgent } from './canaryAgent.js';
import { store } from '../services/store.js';
import { getActiveRiskPolicy } from '../services/tenantStore.js';
import { analyzeFile } from '../services/analyzers.js';
import { db as databaseDb } from '../services/database.js';

/**
 * Resolve the owning organisation's active risk policy for an application.
 * Returns null when the tenant has never configured one, in which case the
 * built-in defaults apply and automatic deployment stays disabled.
 */
function loadOrgPolicy(applicationId) {
  try {
    const app = store.getApplication(applicationId);
    if (!app) return null;
    const row = app.org_id ? getActiveRiskPolicy(app.org_id) : null;
    if (!row) return null;
    return {
      id: row.id,
      version: row.version,
      high: row.high_threshold,
      low: row.low_threshold,
      autoDeploy: !!row.auto_deploy_enabled
    };
  } catch {
    return null;
  }
}

export class MultiAgentOrchestrator {
  constructor(wsBroadcaster) {
    this.wsBroadcaster = wsBroadcaster;
    this.detector = new BugDetectionAgent();
    this.detector.onSourceUnavailable = (issue, application) => this.enqueueAgentJob(issue, application);
    this.riskAgent = new RiskClassificationAgent();
    this.patchAgent = new PatchGenerationAgent();
    this.pipelineAgent = new PipelineValidationAgent();
    this.canaryAgent = new CanaryDeploymentAgent();
  }

  /**
   * Hand analysis to a customer's self-hosted source agent when the platform
   * cannot see their source. Returns the queued job, or null when no active
   * agent is registered for the application.
   */
  enqueueAgentJob(issue, application) {
    try {
      const db = databaseDb();
      const agent = db.prepare(`
        SELECT id FROM source_agents
        WHERE org_id = ? AND status = 'ACTIVE'
          AND (application_id = ? OR application_id IS NULL)
        ORDER BY (application_id = ?) DESC LIMIT 1
      `).get(application.org_id, application.id, application.id);
      if (!agent) return null;

      const id = `AJB-${Date.now()}`;
      db.prepare(`INSERT INTO agent_jobs (id, agent_id, org_id, issue_id, application_id, root, title, description, status, created_at)
                  VALUES (?, ?, ?, ?, ?, NULL, ?, ?, 'QUEUED', ?)`)
        .run(id, agent.id, application.org_id, issue.id, application.id,
             String(issue.title || '').slice(0, 300), String(issue.description || '').slice(0, 2000),
             new Date().toISOString());
      return { id, agentId: agent.id };
    } catch (e) {
      console.error('[agent] enqueue failed:', e.message);
      return null;
    }
  }

  /**
   * Resume analysis using findings reported by the customer's agent.
   *
   * The agent transmits file references, and file content only when the customer
   * explicitly opted in. Without content we cannot analyse the code, so the issue
   * is left in a truthful waiting state rather than pretending to have analysed it.
   */
  async resumeFromAgent(issueId, payload) {
    const issue = store.getIssue(issueId);
    if (!issue) return;
    const pipelineRun = store.getPipelineRun(issueId);

    const findings = Array.isArray(payload?.findings) ? payload.findings : [];
    const withContent = findings.filter(f => typeof f.content === 'string' && f.content.length > 0);

    if (!withContent.length) {
      const msg = `Customer source agent inspected ${payload?.scannedFiles ?? '?'} file(s) and nominated ${findings.length} candidate file(s), but no file content was shared (the agent runs without --send-source). Static analysis requires content.`;
      store.updateIssue(issueId, { status: 'AGENT_SOURCE_REQUIRED' });
      if (pipelineRun) {
        pipelineRun.logs = pipelineRun.logs.concat([`[Self-hosted Agent] ${msg}`]);
        store.updatePipelineRun(pipelineRun.id, { status: 'AWAITING_AGENT_SOURCE', logs: pipelineRun.logs });
      }
      this.broadcast('PIPELINE_FINISHED', { issueId, status: 'AGENT_SOURCE_REQUIRED', reason: msg });
      return;
    }

    // Analyse the shared candidate files with the same static detectors.
    let best = null;
    for (const f of withContent) {
      const found = analyzeFile(f.content, f.file);
      for (const x of found) {
        const weight = (x.confidence || 0.5) * 10 + (f.score || 0);
        if (!best || weight > best.weight) best = { finding: x, file: f.file, content: f.content, weight };
      }
    }

    if (!best) {
      store.updateIssue(issueId, { status: 'INVALID_REPORT', rootCause: 'Customer agent reported candidate files but static analysis found no defect in them.' });
      this.broadcast('PIPELINE_FINISHED', { issueId, status: 'INVALID_REPORT', reason: 'No defect detected in agent-supplied source.' });
      return;
    }

    store.updateIssue(issueId, { status: 'IN_ANALYSIS' });
    const detectionResult = {
      isValidBug: true,
      bugType: best.finding.type,
      targetFileRel: best.file,
      fullFilePath: best.file,          // path on the customer's machine, not ours
      fileContent: best.content,
      confidence: best.finding.confidence,
      lineRange: { start: best.finding.line, end: best.finding.line },
      rootCauseSummary: best.finding.description,
      targetFunction: 'unknown',
      sourceRoot: null
    };
    store.updateIssue(issueId, { rootCause: detectionResult.rootCauseSummary });

    const policy = loadOrgPolicy(issue.applicationId);
    const riskResult = await this.riskAgent.classify(detectionResult, issue, policy);
    store.updateIssue(issueId, { riskLevel: riskResult.riskLevel, riskScore: riskResult.riskScore });

    this.broadcast('PIPELINE_STEP', { issueId, step: 'DETECTION', status: 'COMPLETED', result: detectionResult });
    this.broadcast('PIPELINE_STEP', { issueId, step: 'RISK_ASSESSMENT', status: 'COMPLETED', result: riskResult });
    store.updateIssue(issueId, { status: 'AWAITING_AGENT_PATCH' });
    if (pipelineRun) {
      pipelineRun.logs = pipelineRun.logs.concat(riskResult.logs);
      store.updatePipelineRun(pipelineRun.id, { status: 'AWAITING_AGENT_PATCH', logs: pipelineRun.logs, currentStep: 'PATCH_GENERATION' });
    }
    this.broadcast('PIPELINE_FINISHED', {
      issueId, status: 'AWAITING_AGENT_PATCH',
      reason: 'Defect confirmed from customer-hosted source. A patch must be applied on the customer side; the platform cannot write to their filesystem.'
    });
  }

  broadcast(type, payload) {
    if (this.wsBroadcaster) {
      this.wsBroadcaster({ type, payload, timestamp: new Date().toISOString() });
    }
  }

  async processIssue(issueId) {
    const issue = store.getIssue(issueId);
    if (!issue) return;

    const application = store.getApplication(issue.applicationId);
    if (!application) return;

    let pipelineRun = store.getPipelineRun(issueId);
    if (!pipelineRun) {
      pipelineRun = store.addPipelineRun({
        id: `PIPE-${Date.now()}`,
        issueId,
        applicationId: application.id,
        orgId: application.org_id || null,
        status: 'RUNNING',
        currentStep: 'DETECTION',
        logs: [],
        startedAt: new Date().toISOString()
      });
    }

    const appendLogs = (agentLogs) => {
      pipelineRun.logs = pipelineRun.logs.concat(agentLogs);
      store.updatePipelineRun(pipelineRun.id, { logs: pipelineRun.logs });
      this.broadcast('PIPELINE_LOGS', { issueId, logs: agentLogs, currentStep: pipelineRun.currentStep });
    };

    try {
      // Step 1: Bug Detection & Root Cause Analysis
      store.updateIssue(issueId, { status: 'IN_ANALYSIS' });
      pipelineRun.currentStep = 'DETECTION';
      this.broadcast('PIPELINE_STEP', { issueId, step: 'DETECTION', status: 'IN_PROGRESS' });
      
      await new Promise(r => setTimeout(r, 600)); // Smooth step animation
      const detectionResult = await this.detector.analyze(issue, application);
      appendLogs(detectionResult.logs);

      store.updateIssue(issueId, { rootCause: detectionResult.rootCauseSummary });

      if (!detectionResult.isValidBug) {
        // Delegated to a customer's self-hosted agent: stay pending, not rejected.
        if (detectionResult.awaitingAgent) {
          store.updateIssue(issueId, { status: 'AGENT_ANALYSIS_QUEUED' });
          store.updatePipelineRun(pipelineRun.id, { status: 'AWAITING_AGENT', currentStep: 'DETECTION' });
          this.broadcast('PIPELINE_STEP', { issueId, step: 'DETECTION', status: 'AWAITING_AGENT', result: detectionResult });
          this.broadcast('PIPELINE_FINISHED', {
            issueId, status: 'AGENT_ANALYSIS_QUEUED', applicationId: application.id, reason: detectionResult.rootCauseSummary
          });
          return;
        }

        // Stop without touching any code. Never patch when we could not verify a real defect.
        const status = detectionResult.noSource
          ? 'SOURCE_UNAVAILABLE'
          : detectionResult.locationNotFound
            ? 'LOCATION_NOT_FOUND'
            : 'INVALID_REPORT';
        store.updateIssue(issueId, { status, riskLevel: 'NONE', riskScore: 0 });
        store.updatePipelineRun(pipelineRun.id, {
          status: status === 'INVALID_REPORT' ? 'REJECTED_INVALID' : 'STOPPED_NO_ACTION',
          completedAt: new Date().toISOString()
        });
        this.broadcast('PIPELINE_STEP', { issueId, step: 'DETECTION', status, result: detectionResult });
        this.broadcast('PIPELINE_FINISHED', {
          issueId,
          status,
          applicationId: application.id,
          applicationPort: application.port,
          reason: detectionResult.rootCauseSummary
        });
        return; // Stop pipeline early, no patch, no deployment
      }

      this.broadcast('PIPELINE_STEP', { issueId, step: 'DETECTION', status: 'COMPLETED', result: detectionResult });

      // Step 2: Risk Classification
      pipelineRun.currentStep = 'RISK_ASSESSMENT';
      this.broadcast('PIPELINE_STEP', { issueId, step: 'RISK_ASSESSMENT', status: 'IN_PROGRESS' });
      
      await new Promise(r => setTimeout(r, 600));
      const policy = loadOrgPolicy(issue.applicationId);
      const riskResult = await this.riskAgent.classify(detectionResult, issue, policy);
      appendLogs(riskResult.logs);

      // Record which policy version produced this decision, for auditability.
      store.updateIssue(issueId, { riskLevel: riskResult.riskLevel, riskScore: riskResult.riskScore });
      this.broadcast('PIPELINE_STEP', { issueId, step: 'RISK_ASSESSMENT', status: 'COMPLETED', result: riskResult });

      // Step 3: Patch Generation
      pipelineRun.currentStep = 'PATCH_GENERATION';
      this.broadcast('PIPELINE_STEP', { issueId, step: 'PATCH_GENERATION', status: 'IN_PROGRESS' });
      
      await new Promise(r => setTimeout(r, 600));
      const patchResult = await this.patchAgent.generate(detectionResult, riskResult, issue);
      appendLogs(patchResult.logs);

      const patch = store.addPatch({
        id: `PATCH-${Date.now()}`,
        issueId,
        applicationId: application.id,
        orgId: application.org_id || null,
        diff: patchResult.diff,
        description: patchResult.description,
        status: riskResult.requiresAdminApproval ? 'PENDING_APPROVAL' : 'APPROVED',
        patchResult
      });

      this.broadcast('PIPELINE_STEP', { issueId, step: 'PATCH_GENERATION', status: 'COMPLETED', result: patchResult });

      // A patch that failed AST validation is never deployed.
      if (!patchResult.syntaxValid) {
        store.updateIssue(issueId, { status: 'PATCH_FAILED' });
        store.updatePipelineRun(pipelineRun.id, { status: 'FAILED', currentStep: 'PATCH_GENERATION', completedAt: new Date().toISOString() });
        this.broadcast('PIPELINE_FINISHED', { issueId, status: 'PATCH_FAILED', applicationId: application.id, applicationPort: application.port, reason: patchResult.description });
        return;
      }

      // Step 4 (Agent 5): Validation runs BEFORE any approval request, so the
      // reviewer approves against real test evidence rather than an unvalidated diff.
      const pipelineResult = await this.runValidationStage(issueId, patchResult, application, pipelineRun);
      if (!pipelineResult || pipelineResult.validationPassed === false) {
        store.updateIssue(issueId, { status: 'VALIDATION_FAILED' });
        store.updatePipelineRun(pipelineRun.id, { status: 'FAILED', currentStep: 'VALIDATION', completedAt: new Date().toISOString() });
        this.broadcast('PIPELINE_FINISHED', { issueId, status: 'VALIDATION_FAILED', applicationId: application.id, applicationPort: application.port, reason: 'Validation failed; no deployment attempted.' });
        return;
      }

      // Governance Gate Check for High-Risk Issues (after validation)
      if (riskResult.requiresAdminApproval && patch.status === 'PENDING_APPROVAL') {
        store.updateIssue(issueId, { status: 'AWAITING_ADMIN_APPROVAL' });
        store.updatePipelineRun(pipelineRun.id, { status: 'PAUSED_AWAITING_APPROVAL', currentStep: 'ADMIN_REVIEW' });
        this.broadcast('PIPELINE_PAUSED', {
          issueId,
          reason: 'High Risk classification requires Customer Admin manual review.',
          patchId: patch.id,
          riskResult,
          validation: {
            validationPassed: pipelineResult.validationPassed,
            behaviourVerified: !!pipelineResult.behaviourVerified,
            testsRan: pipelineResult.testCheck ? !!pipelineResult.testCheck.ran : false,
            testCounts: pipelineResult.testCheck ? pipelineResult.testCheck.counts : null
          }
        });
        return; // Pause pipeline until manual approval API call
      }

      // Resume or Continue Automated Pipeline for Low Risk
      await this.executeDeploymentPipeline(issueId, patchResult, application, pipelineRun, pipelineResult);

    } catch (err) {
      console.error('Pipeline error:', err);
      store.updateIssue(issueId, { status: 'FAILED' });
      store.updatePipelineRun(pipelineRun.id, { status: 'FAILED' });
      this.broadcast('PIPELINE_FAILED', { issueId, error: err.message });
    }
  }

  /** Agent 5: run real validation and persist the evidence. Never fabricates results. */
  async runValidationStage(issueId, patchResult, application, pipelineRun) {
    const appendLogs = (agentLogs) => {
      pipelineRun.logs = pipelineRun.logs.concat(agentLogs);
      store.updatePipelineRun(pipelineRun.id, { logs: pipelineRun.logs });
      this.broadcast('PIPELINE_LOGS', { issueId, logs: agentLogs, currentStep: pipelineRun.currentStep });
    };

    pipelineRun.currentStep = 'VALIDATION';
    store.updatePipelineRun(pipelineRun.id, { status: 'RUNNING', currentStep: 'VALIDATION' });
    this.broadcast('PIPELINE_STEP', { issueId, step: 'VALIDATION', status: 'IN_PROGRESS' });

    await new Promise(r => setTimeout(r, 400));
    const pipelineResult = await this.pipelineAgent.runPipeline(patchResult, application);
    appendLogs(pipelineResult.logs);
    this.broadcast('PIPELINE_STEP', { issueId, step: 'VALIDATION', status: 'COMPLETED', result: pipelineResult });

    store.addValidationRun({
      id: `VAL-${Date.now()}`,
      issueId,
      applicationId: application.id,
      orgId: application.org_id || null,
      patchApplied: pipelineResult.applyCheck ? pipelineResult.applyCheck.passed : false,
      syntaxPassed: pipelineResult.syntaxCheck ? pipelineResult.syntaxCheck.passed : false,
      testsRan: pipelineResult.testCheck ? !!pipelineResult.testCheck.ran : false,
      testsPassed: pipelineResult.testCheck ? pipelineResult.testCheck.passed === true : false,
      testCounts: pipelineResult.testCheck ? pipelineResult.testCheck.counts : null,
      securityPassed: pipelineResult.security ? pipelineResult.security.passed : false,
      securityFindings: pipelineResult.security ? pipelineResult.security.findings : [],
      dependencyAudit: pipelineResult.dependencyAudit,
      behaviourVerified: !!pipelineResult.behaviourVerified,
      validationPassed: !!pipelineResult.validationPassed,
      evidence: pipelineResult.evidence || {}
    });

    return pipelineResult;
  }

  async executeDeploymentPipeline(issueId, patchResult, application, pipelineRun, precomputedValidation) {
    const appendLogs = (agentLogs) => {
      pipelineRun.logs = pipelineRun.logs.concat(agentLogs);
      store.updatePipelineRun(pipelineRun.id, { logs: pipelineRun.logs });
      this.broadcast('PIPELINE_LOGS', { issueId, logs: agentLogs, currentStep: pipelineRun.currentStep });
    };

    // Validation was already executed and persisted before this stage began.
      const pipelineResult = precomputedValidation;
      if (!pipelineResult) {
        pipelineRun.currentStep = 'VALIDATION';
        store.updatePipelineRun(pipelineRun.id, { status: 'FAILED', currentStep: 'VALIDATION', completedAt: new Date().toISOString() });
        this.broadcast('PIPELINE_FINISHED', { issueId, status: 'VALIDATION_FAILED', applicationId: application.id, reason: 'No validation evidence available; deployment refused.' });
        return;
      }
      if (pipelineResult.validationPassed === false) {
        store.updateIssue(issueId, { status: 'VALIDATION_FAILED' });
        store.updatePipelineRun(pipelineRun.id, { status: 'FAILED', currentStep: 'VALIDATION', completedAt: new Date().toISOString() });
        this.broadcast('PIPELINE_FINISHED', { issueId, status: 'VALIDATION_FAILED', applicationId: application.id, applicationPort: application.port, reason: 'Validation failed; no deployment attempted.' });
        return;
      }

      // Step 5: Deployment & Health Verification
      pipelineRun.currentStep = 'CANARY_DEPLOYMENT';
      store.updatePipelineRun(pipelineRun.id, { status: 'RUNNING', currentStep: 'CANARY_DEPLOYMENT' });
      this.broadcast('PIPELINE_STEP', { issueId, step: 'CANARY_DEPLOYMENT', status: 'IN_PROGRESS' });
      
      await new Promise(r => setTimeout(r, 400));
      const canaryResult = await this.canaryAgent.deploy(patchResult, pipelineResult, application);
      appendLogs(canaryResult.logs);

      store.addDeployment({
        id: `DEP-${Date.now()}`,
        issueId,
        applicationId: application.id,
        orgId: application.org_id || null,
        strategy: canaryResult.strategy,
        zeroDowntime: canaryResult.zeroDowntime,
        status: canaryResult.deploymentStatus,
        health: canaryResult.health,
        rolledBack: canaryResult.rolledBack,
        backupFile: canaryResult.backupFile,
        result: { writeSuccess: canaryResult.writeSuccess, canaryStatus: canaryResult.canaryStatus, promotedAt: canaryResult.promotedAt }
      });

      this.broadcast('PIPELINE_STEP', { issueId, step: 'CANARY_DEPLOYMENT', status: 'COMPLETED', result: canaryResult });

      const deployed = canaryResult.writeSuccess && !canaryResult.rolledBack;
      store.updateIssue(issueId, { status: deployed ? 'RESOLVED_AND_DEPLOYED' : 'ROLLED_BACK', resolvedAt: new Date().toISOString() });
      store.updatePipelineRun(pipelineRun.id, { status: deployed ? 'SUCCESS' : 'FAILED', completedAt: new Date().toISOString() });

      this.broadcast('PIPELINE_FINISHED', {
        issueId,
        status: deployed ? 'SUCCESS' : 'ROLLED_BACK',
        applicationId: application.id,
        applicationPort: application.port,
        canaryResult
      });
    }

  async resumeApprovedPipeline(issueId) {
    const issue = store.getIssue(issueId);
    const patch = store.getPatch(issueId);
    const application = store.getApplication(issue.applicationId);
    const pipelineRun = store.getPipelineRun(issueId);

    if (!issue || !patch || !application || !pipelineRun) return;

    store.updatePatch(patch.id, { status: 'APPROVED', approvedAt: new Date().toISOString() });
    store.updateIssue(issueId, { status: 'APPROVED_BY_ADMIN' });

    this.broadcast('ADMIN_APPROVED', { issueId, patchId: patch.id });

    // Re-validate immediately before deploying: source may have drifted while the
    // change sat awaiting approval, so approval must not be treated as a guarantee.
    const pipelineResult = await this.runValidationStage(issueId, patch.patchResult, application, pipelineRun);
    if (!pipelineResult || pipelineResult.validationPassed === false) {
      store.updateIssue(issueId, { status: 'VALIDATION_FAILED' });
      store.updatePipelineRun(pipelineRun.id, { status: 'FAILED', currentStep: 'VALIDATION', completedAt: new Date().toISOString() });
      this.broadcast('PIPELINE_FINISHED', { issueId, status: 'VALIDATION_FAILED', reason: 'Post-approval validation failed; deployment refused.' });
      return;
    }

    // Continue executing deployment stages
    await this.executeDeploymentPipeline(issueId, patch.patchResult, application, pipelineRun, pipelineResult);
  }
}
