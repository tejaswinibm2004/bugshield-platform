import { applyFinding, unifiedDiff, validateJs } from '../services/analyzers.js';
import { getAiStatus, aiPatch, applyAiEdits } from '../services/aiProvider.js';

function isJsLike(relPath) {
  return /\.(js|jsx|mjs|cjs|ts|tsx)$/i.test(relPath || '');
}

export class PatchGenerationAgent {
  constructor() {
    this.name = 'Patch Generation & Remediation Agent';
    this.id = 'AGENT-PATCH-03';
  }

  async generate(detectionResult, riskResult, issue = {}) {
    const logs = [];
    const { bugType, fullFilePath, fileContent, targetFileRel } = detectionResult;
    const finding = detectionResult.finding;

    logs.push(`[${this.name}] Synthesising a code fix for ${targetFileRel} (${bugType})...`);

    let updatedCode = fileContent;
    let description = '';
    let syntaxValid = false;
    let validationError = '';

    if (!finding || !finding.autoFixable) {
      description = finding
        ? `A ${bugType} defect was detected but cannot be auto-remediated safely. Manual engineering review required.`
        : 'No auto-remediable defect identified.';
      logs.push(`[${this.name}] ⚠️ ${description}`);
    } else {
      const patched = applyFinding(fileContent, finding);
      if (patched == null) {
        // Pattern fix does not cover this shape (e.g. AI-confirmed cosmetic or
        // novel bug): fall through to the universal AI patcher below.
        logs.push(`[${this.name}] Pattern fix does not cover this shape. Trying universal AI patch...`);
      } else {
        const v = this.checkSyntax(patched, targetFileRel);
        syntaxValid = v.ok;
        if (!v.ok) validationError = v.error;
        if (v.ok) {
          updatedCode = patched;
          description = `${finding.description} Guard applied at line ${finding.line}.`;
          logs.push(`[${this.name}] Applied remediation derived from the live source: ${finding.evidence}`);
        } else {
          description = 'Generated patch failed syntax validation and was discarded.';
          logs.push(`[${this.name}] ❌ Syntax Check FAILED, patch discarded: ${v.error}`);
        }
      }
    }

    // Universal fallback: any validated defect gets an AI-synthesised fix.
    if (!syntaxValid && finding && finding.autoFixable) {
      const ai = await this.tryAiPatch(detectionResult, issue, logs);
      if (ai) {
        updatedCode = ai.updatedCode;
        description = ai.description;
        syntaxValid = true;
      } else if (!description) {
        description = 'Unable to synthesise a patch for this code shape.';
      }
    }

    logs.push(`[${this.name}] Running syntax validation on the generated patch...`);
    if (syntaxValid) logs.push(`[${this.name}] Syntax Check PASSED for ${targetFileRel}.`);

    const diff = syntaxValid ? unifiedDiff(fileContent, updatedCode, targetFileRel) : '';
    if (diff) logs.push(`[${this.name}] Unified diff produced (${diff.split('\n').filter(l => /^[+-][^+-]/.test(l)).length} changed line(s)).`);
    logs.push(`[${this.name}] ${syntaxValid ? 'Code patch generated successfully.' : 'No deployable patch produced.'}`);

    return {
      agentId: this.id,
      agentName: this.name,
      targetFileRel,
      fullFilePath,
      sourceRoot: detectionResult.sourceRoot,
      originalCode: fileContent,
      updatedCode,
      diff,
      description,
      bugType,
      syntaxValid,
      validationError,
      riskLevel: riskResult ? riskResult.riskLevel : null,
      lineEnding: detectionResult.lineEnding || '\n',
      logs
    };
  }

  checkSyntax(code, relPath) {
    if (!isJsLike(relPath)) {
      if (!code || !String(code).trim()) return { ok: false, error: 'AI returned an empty file.' };
      return { ok: true };
    }
    return validateJs(code);
  }

  async tryAiPatch(detectionResult, issue, logs) {
    const status = getAiStatus();
    if (!status.configured) {
      logs.push(`[${this.name}] Universal AI patch skipped: ${status.reason}`);
      return null;
    }
    logs.push(`[${this.name}] Asking ${status.model} to synthesise a fix for ${detectionResult.targetFileRel}...`);
    let out;
    try {
      out = await aiPatch({
        issue: { title: issue?.title || '', description: issue?.description || '' },
        targetFileRel: detectionResult.targetFileRel,
        fileContent: detectionResult.fileContent,
        rootCause: detectionResult.rootCauseSummary || detectionResult.finding?.description || ''
      });
    } catch (e) {
      logs.push(`[${this.name}] AI patch failed honestly: ${e.message}`);
      return null;
    }
    let updated;
    try {
      updated = String(applyAiEdits(detectionResult.fileContent, out.edits)).replace(/\r\n/g, '\n');
    } catch (e) {
      logs.push(`[${this.name}] AI edits rejected for safety: ${e.message}`);
      return null;
    }
    if (!updated.trim() || updated === detectionResult.fileContent) {
      logs.push(`[${this.name}] AI returned no change; discarding.`);
      return null;
    }
    if (updated.length > detectionResult.fileContent.length * 4 + 5000) {
      logs.push(`[${this.name}] AI returned a suspiciously large rewrite; discarding for safety.`);
      return null;
    }
    const v = this.checkSyntax(updated, detectionResult.targetFileRel);
    if (!v.ok) {
      logs.push(`[${this.name}] AI patch failed syntax validation and was discarded: ${v.error}`);
      return null;
    }
    logs.push(`[${this.name}] Universal AI patch accepted.`);
    return { updatedCode: updated, description: String(out.description || 'AI-synthesised fix.') };
  }
}