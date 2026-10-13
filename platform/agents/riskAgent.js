import {
  RISK_BASE_SCORE, PATH_CRITICAL_MARKERS, PATH_WEIGHT_FIRST_HIT, PATH_WEIGHT_PER_EXTRA_HIT,
  PATH_WEIGHT_CAP, DEFECT_CLASS_WEIGHTS, MONEY_TOKENS, MONEY_WEIGHT, SHARED_MODULE_PATTERN,
  SHARED_MODULE_WEIGHT, CONFIDENCE_WEIGHT, HIGH_THRESHOLD, LOW_THRESHOLD,
  RISK_SCORE_MIN, RISK_SCORE_MAX
} from '../services/riskConfig.js';

/**
 * Paths whose classification and approval requirement are never relaxed by tenant
 * configuration. Modifying authentication, session handling or money handling is
 * always treated as sensitive.
 */
const SECURITY_CRITICAL_MARKERS = [
  'auth', 'login', 'session', 'token', 'password', 'crypto', 'security', 'permission', 'admin',
  'payment', 'billing', 'checkout', 'invoice', 'pricing', 'wallet'
];

export class RiskClassificationAgent {
  constructor() {
    this.name = 'Risk Classification & Governance Agent';
    this.id = 'AGENT-RISK-02';
  }

  /**
   * @param detectionResult  static-analysis output from the detection agent
   * @param issue            normalised bug report
   * @param policy           the organisation's versioned policy. When omitted the
   *                         built-in defaults are used, and automatic deployment
   *                         stays disabled.
   */
  async classify(detectionResult, issue, policy = {}) {
    const logs = [];
    // Callers may legitimately pass null (no tenant policy configured); a
    // default parameter only covers undefined, so normalise explicitly.
    const p = policy || {};
    const activePolicy = {
      high: Number.isFinite(p.high) ? p.high : HIGH_THRESHOLD,
      low: Number.isFinite(p.low) ? p.low : LOW_THRESHOLD,
      // Safe default: a tenant must explicitly enable automatic deployment.
      autoDeploy: p.autoDeploy === true,
      version: Number.isFinite(p.version) ? p.version : 0,
      id: p.id || 'default'
    };
    logs.push(`[${this.name}] Policy ${activePolicy.id} (v${activePolicy.version}): escalate >= ${activePolicy.high}, low < ${activePolicy.low}, autoDeploy=${activePolicy.autoDeploy}`);

    const rel = (detectionResult.targetFileRel || '').toLowerCase();
    const type = detectionResult.bugType || '';
    const confidence = detectionResult.confidence ?? 0.5;
    const text = `${issue.title} ${issue.description}`.toLowerCase();

    const reasons = [];
    const breakdown = [];
    // Start at zero: the base score is contributed through add() so that the
    // breakdown always sums exactly to the final score (no double counting).
    let score = 0;
    const add = (factor, points, why) => { score += points; breakdown.push({ factor, points, why }); reasons.push(why); };

    add('Base score', RISK_BASE_SCORE, `Every unreviewed issue starts at ${RISK_BASE_SCORE} so a score is always defined.`);

    const hits = PATH_CRITICAL_MARKERS.filter(p => rel.includes(p));
    if (hits.length) {
      const pts = Math.min(PATH_WEIGHT_CAP, PATH_WEIGHT_FIRST_HIT + (hits.length - 1) * PATH_WEIGHT_PER_EXTRA_HIT);
      add('Critical path exposure', pts, `Target file matches critical module markers: ${hits.join(', ')}.`);
    }

    const classWeight = DEFECT_CLASS_WEIGHTS[type] ?? (type && type !== '' && !['NONE'].includes(type) ? DEFECT_CLASS_WEIGHTS.AI_GENERAL : undefined);
    if (classWeight) {
      const why = {
        DIV_ZERO: 'Produces NaN/Infinity that silently propagate into stored results.',
        UNDEFINED_DYNAMIC_KEY: 'Produces NaN via an undefined object lookup.',
        NULL_DEREF: 'Throws a runtime TypeError and can take the request down.',
        MISSING_AWAIT: 'A swallowed asynchronous failure leaves data in an inconsistent state.'
      }[type] || `AI-confirmed ${type} defect; treated as a general code fault pending class-specific calibration.`;
      add('Defect class', classWeight, `${type}: ${why}`);
    }

    const moneyHits = MONEY_TOKENS.filter(t => text.includes(t) || rel.includes(t));
    if (moneyHits.length) {
      add('Monetary exposure', MONEY_WEIGHT, `Affects monetary values (${moneyHits.slice(0, 4).join(', ')}) — incorrect output has financial impact.`);
    }

    if (SHARED_MODULE_PATTERN.test(rel)) {
      add('Shared module', SHARED_MODULE_WEIGHT, 'Target is a shared utility/helper module imported across the application.');
    }

    const confPts = Math.round(confidence * CONFIDENCE_WEIGHT);
    add('Detection confidence', confPts, `Static evidence confidence ${Math.round(confidence * 100)}% (weight ${confPts}/${CONFIDENCE_WEIGHT}).`);

    score = Math.max(RISK_SCORE_MIN, Math.min(RISK_SCORE_MAX, score));
    let riskLevel = score >= activePolicy.high ? 'HIGH' : score >= activePolicy.low ? 'MEDIUM' : 'LOW';

    // Mandatory floor: a tenant may not configure thresholds that classify
    // security- or money-critical code as low risk, nor auto-deploy it.
    const securitySensitive = SECURITY_CRITICAL_MARKERS.some(m => rel.includes(m));
    let floorApplied = false;
    if (securitySensitive && riskLevel === 'LOW') {
      riskLevel = 'MEDIUM';
      floorApplied = true;
      logs.push(`[${this.name}] Policy floor applied: ${rel} is security/money critical, so the classification cannot be lowered to LOW by tenant thresholds.`);
    }

    // A low score never overrides governance. Automatic deployment requires the
    // tenant to have opted in AND the change to sit below their threshold.
    // Security-critical paths always require a human.
    const belowThreshold = score < activePolicy.high;
    const requiresAdminApproval = securitySensitive || !activePolicy.autoDeploy || !belowThreshold;

    logs.push(`[${this.name}] Calculated Risk Score: ${score}/100 -> [${riskLevel} RISK]`);
    reasons.forEach(r => logs.push(`[${this.name}] Reason: ${r}`));
    if (securitySensitive) logs.push(`[${this.name}] Decision: security/money-critical target always requires human approval.`);
    else if (!activePolicy.autoDeploy) logs.push(`[${this.name}] Decision: automatic deployment is disabled by policy ${activePolicy.id}; human approval required.`);
    else if (!belowThreshold) logs.push(`[${this.name}] Decision: score >= ${activePolicy.high} (${activePolicy.id}); human approval required.`);
    else logs.push(`[${this.name}] Decision: score ${score} < ${activePolicy.high} and autoDeploy enabled (${activePolicy.id}); eligible for canary deployment with automatic rollback.`);

    return {
      agentId: this.id,
      agentName: this.name,
      riskLevel,
      riskScore: score,
      reasons,
      breakdown,
      requiresAdminApproval,
      securitySensitive,
      floorApplied,
      policy: activePolicy,
      logs
    };
  }
}