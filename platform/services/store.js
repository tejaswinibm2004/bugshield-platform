import { db } from './database.js';

class Store {
  // Helper to parse JSON fields safely
  _parseJSON(jsonStr, fallback) {
    if (!jsonStr) return fallback;
    try {
      return JSON.parse(jsonStr);
    } catch {
      return fallback;
    }
  }

  // Mapper for application database row -> object
  _mapApp(row) {
    if (!row) return null;
    return {
      id: row.id,
      customerId: row.customer_id,
      org_id: row.org_id || row.customer_id || null,
      name: row.name,
      type: row.type,
      port: row.port,
      repoUrl: row.repo_url,
      branch: row.branch,
      status: row.status,
      sdkKey: row.sdk_key,
      permissions: this._parseJSON(row.permissions, {}),
      jenkinsStatus: row.jenkins_status,
      dockerStatus: row.docker_status,
      canaryThreshold: row.canary_threshold
    };
  }

  // Mapper for issue database row -> object
  _mapIssue(row) {
    if (!row) return null;
    return {
      id: row.id,
      applicationId: row.application_id,
      title: row.title,
      description: row.description || '',
      pageUrl: row.page_url || '/',
      stepsToReproduce: row.steps_to_reproduce || '',
      stackTrace: row.stack_trace || '',
      logs: this._parseJSON(row.logs, []),
      browserInfo: this._parseJSON(row.browser_info, {}),
      status: row.status,
      rootCause: row.root_cause || '',
      riskLevel: row.risk_level || '',
      riskScore: row.risk_score || 0,
      reportedAt: row.reported_at,
      resolvedAt: row.resolved_at || null
    };
  }

  // Mapper for patch database row -> object
  _mapPatch(row) {
    if (!row) return null;
    return {
      id: row.id,
      issueId: row.issue_id,
      applicationId: row.application_id,
      diff: row.diff || '',
      description: row.description || '',
      status: row.status,
      patchResult: this._parseJSON(row.patch_result, {}),
      createdAt: row.created_at,
      approvedAt: row.approved_at || null
    };
  }

  // Mapper for pipeline database row -> object
  _mapPipeline(row) {
    if (!row) return null;
    return {
      id: row.id,
      issueId: row.issue_id,
      applicationId: row.application_id,
      status: row.status,
      currentStep: row.current_step,
      logs: this._parseJSON(row.logs, []),
      startedAt: row.started_at,
      completedAt: row.completed_at || null
    };
  }

  getApplications() {
    const rows = db.prepare('SELECT * FROM applications').all();
    return rows.map(r => this._mapApp(r));
  }

  getApplication(id) {
    if (!id) return null;
    const row = db.prepare('SELECT * FROM applications WHERE id = ? OR sdk_key = ?').get(id, id);
    return this._mapApp(row);
  }

  addApplication(app) {
    const stmt = db.prepare(`
      INSERT INTO applications (id, customer_id, name, type, port, repo_url, branch, status, sdk_key, permissions, jenkins_status, docker_status, canary_threshold, org_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      app.id,
      app.customerId || 'CUST-001',
      app.name || 'Custom Application',
      app.type || 'Web Service',
      app.port || 3003,
      app.repoUrl || '',
      app.branch || 'main',
      app.status || 'Connected',
      app.sdkKey || `sdk_${app.id.toLowerCase()}_live`,
      JSON.stringify(app.permissions || { issueAccess: true, repoAccess: true, deploymentAccess: true }),
      app.jenkinsStatus || 'Connected & Verified',
      app.dockerStatus || 'Containerized (Active)',
      app.canaryThreshold || '99.5%',
      app.orgId || app.customerId || null
    );
    return this.getApplication(app.id);
  }

  getIssues() {
    const rows = db.prepare('SELECT * FROM issues ORDER BY reported_at DESC').all();
    return rows.map(r => this._mapIssue(r));
  }

  getIssue(id) {
    if (!id) return null;
    const row = db.prepare('SELECT * FROM issues WHERE id = ?').get(id);
    return this._mapIssue(row);
  }

  addIssue(issue) {
    const stmt = db.prepare(`
      INSERT INTO issues (id, application_id, title, description, page_url, steps_to_reproduce, stack_trace, logs, browser_info, status, root_cause, risk_level, risk_score, reported_at, resolved_at, org_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      issue.id,
      issue.applicationId,
      issue.title || 'Unspecified Error',
      issue.description || '',
      issue.pageUrl || '/',
      issue.stepsToReproduce || '',
      issue.stackTrace || '',
      JSON.stringify(issue.logs || []),
      JSON.stringify(issue.browserInfo || {}),
      issue.status || 'RECEIVED',
      issue.rootCause || '',
      issue.riskLevel || '',
      issue.riskScore || 0,
      issue.reportedAt || new Date().toISOString(),
      issue.resolvedAt || null,
      issue.orgId || null
    );
    return this.getIssue(issue.id);
  }

  updateIssue(id, updates) {
    const current = this.getIssue(id);
    if (!current) return null;
    const updated = { ...current, ...updates };

    const stmt = db.prepare(`
      UPDATE issues SET
        application_id = ?,
        title = ?,
        description = ?,
        page_url = ?,
        steps_to_reproduce = ?,
        stack_trace = ?,
        logs = ?,
        browser_info = ?,
        status = ?,
        root_cause = ?,
        risk_level = ?,
        risk_score = ?,
        resolved_at = ?
      WHERE id = ?
    `);

    stmt.run(
      updated.applicationId,
      updated.title,
      updated.description,
      updated.pageUrl,
      updated.stepsToReproduce,
      updated.stackTrace,
      JSON.stringify(updated.logs),
      JSON.stringify(updated.browserInfo),
      updated.status,
      updated.rootCause,
      updated.riskLevel,
      updated.riskScore,
      updated.resolvedAt || null,
      id
    );

    return this.getIssue(id);
  }

  addPatch(patch) {
    const stmt = db.prepare(`
      INSERT INTO patches (id, issue_id, application_id, diff, description, status, patch_result, created_at, approved_at, org_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      patch.id,
      patch.issueId,
      patch.applicationId,
      patch.diff || '',
      patch.description || '',
      patch.status || 'PENDING_APPROVAL',
      JSON.stringify(patch.patchResult || {}),
      patch.createdAt || new Date().toISOString(),
      patch.approvedAt || null,
      patch.orgId || null
    );
    return this.getPatch(patch.id);
  }

  getPatch(id) {
    if (!id) return null;
    const row = db.prepare('SELECT * FROM patches WHERE id = ? OR issue_id = ?').get(id, id);
    return this._mapPatch(row);
  }

  updatePatch(id, updates) {
    const current = this.getPatch(id);
    if (!current) return null;
    const updated = { ...current, ...updates };

    const stmt = db.prepare(`
      UPDATE patches SET
        status = ?,
        patch_result = ?,
        approved_at = ?
      WHERE id = ? OR issue_id = ?
    `);

    stmt.run(
      updated.status,
      JSON.stringify(updated.patchResult || {}),
      updated.approvedAt || null,
      id,
      id
    );

    return this.getPatch(id);
  }

  addPipelineRun(run) {
    const stmt = db.prepare(`
      INSERT INTO pipelines (id, issue_id, application_id, status, current_step, logs, started_at, completed_at, org_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      run.id,
      run.issueId,
      run.applicationId,
      run.status || 'RUNNING',
      run.currentStep || 'DETECTION',
      JSON.stringify(run.logs || []),
      run.startedAt || new Date().toISOString(),
      run.completedAt || null,
      run.orgId || null
    );
    return this.getPipelineRun(run.id);
  }

  updatePipelineRun(id, updates) {
    const current = this.getPipelineRun(id);
    if (!current) return null;
    const updated = { ...current, ...updates };

    const stmt = db.prepare(`
      UPDATE pipelines SET
        status = ?,
        current_step = ?,
        logs = ?,
        completed_at = ?
      WHERE id = ? OR issue_id = ?
    `);

    stmt.run(
      updated.status,
      updated.currentStep,
      JSON.stringify(updated.logs || []),
      updated.completedAt || null,
      id,
      id
    );

    return this.getPipelineRun(id);
  }

  getPipelineRun(id) {
    if (!id) return null;
    const row = db.prepare('SELECT * FROM pipelines WHERE id = ? OR issue_id = ?').get(id, id);
    return this._mapPipeline(row);
  }

  getPipelines() {
    const rows = db.prepare('SELECT * FROM pipelines ORDER BY started_at DESC').all();
    return rows.map(r => this._mapPipeline(r));
  }

  // ---- Validation evidence (real tool output, never fabricated) ----
  addValidationRun(run) {
    const stmt = db.prepare(`
      INSERT INTO validation_runs (id, issue_id, application_id, patch_applied, syntax_passed, tests_ran, tests_passed, test_counts, security_passed, security_findings, dependency_audit, behaviour_verified, validation_passed, evidence, created_at, org_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      run.id,
      run.issueId,
      run.applicationId,
      run.patchApplied ? 1 : 0,
      run.syntaxPassed ? 1 : 0,
      run.testsRan ? 1 : 0,
      run.testsPassed ? 1 : 0,
      JSON.stringify(run.testCounts || null),
      run.securityPassed ? 1 : 0,
      JSON.stringify(run.securityFindings || []),
      JSON.stringify(run.dependencyAudit || null),
      run.behaviourVerified ? 1 : 0,
      run.validationPassed ? 1 : 0,
      JSON.stringify(run.evidence || {}),
      run.createdAt || new Date().toISOString(),
      run.orgId || null
    );
    return run;
  }

  getValidationRuns(issueId) {
    const rows = issueId
      ? db.prepare('SELECT * FROM validation_runs WHERE issue_id = ? ORDER BY created_at DESC').all(issueId)
      : db.prepare('SELECT * FROM validation_runs ORDER BY created_at DESC').all();
    return rows.map(r => ({
      id: r.id,
      issueId: r.issue_id,
      applicationId: r.application_id,
      patchApplied: !!r.patch_applied,
      syntaxPassed: !!r.syntax_passed,
      testsRan: !!r.tests_ran,
      testsPassed: !!r.tests_passed,
      testCounts: this._parseJSON(r.test_counts, null),
      securityPassed: !!r.security_passed,
      securityFindings: this._parseJSON(r.security_findings, []),
      dependencyAudit: this._parseJSON(r.dependency_audit, null),
      behaviourVerified: !!r.behaviour_verified,
      validationPassed: !!r.validation_passed,
      evidence: this._parseJSON(r.evidence, {}),
      createdAt: r.created_at
    }));
  }

  // ---- Deployment records ----
  addDeployment(dep) {
    const stmt = db.prepare(`
      INSERT INTO deployments (id, issue_id, application_id, strategy, zero_downtime, status, health, rolled_back, backup_file, result, created_at, org_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      dep.id, dep.issueId, dep.applicationId, dep.strategy || null,
      dep.zeroDowntime ? 1 : 0, dep.status || 'UNKNOWN',
      JSON.stringify(dep.health || null), dep.rolledBack ? 1 : 0,
      dep.backupFile || null, JSON.stringify(dep.result || null),
      dep.createdAt || new Date().toISOString(), dep.orgId || null
    );
    return dep;
  }

  getDeployments(issueId) {
    const rows = issueId
      ? db.prepare('SELECT * FROM deployments WHERE issue_id = ? ORDER BY created_at DESC').all(issueId)
      : db.prepare('SELECT * FROM deployments ORDER BY created_at DESC').all();
    return rows.map(r => ({
      id: r.id, issueId: r.issue_id, applicationId: r.application_id,
      strategy: r.strategy, zeroDowntime: !!r.zero_downtime, status: r.status,
      health: this._parseJSON(r.health, null), rolledBack: !!r.rolled_back,
      backupFile: r.backup_file, result: this._parseJSON(r.result, null), createdAt: r.created_at
    }));
  }
}

export const store = new Store();
