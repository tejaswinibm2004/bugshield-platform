import fs from 'fs';
import path from 'path';
import { analyzeFile } from '../services/analyzers.js';
import { getAiStatus, aiAssess } from '../services/aiProvider.js';
import { indexSourceFiles, resolveSourceRoot } from '../services/workspace.js';

const STOPWORDS = new Set(['the','and','for','with','that','this','from','have','has','was','were','are','but','not','you','your','when','what','where','which','while','into','out','get','set','use','using','used','can','could','would','should','there','their','them','then','than','they','been','being','does','did','doing','also','just','like','about','after','before','because','some','more','most','only','other','such','own','same','too','very','will','may','one','two','bug','issue','error','problem','page','user','users','please','help','report','failing','fails','fail','failed','broken','not','working','work','works','happens','happening','clicked','click','tried','trying']);

function keywords(text) {
  const words = String(text || '').toLowerCase().match(/[a-z][a-z0-9_]{2,}/g) || [];
  const seen = new Set();
  for (const w of words) if (!STOPWORDS.has(w)) seen.add(w);
  return [...seen];
}

/** Best-effort: name of the function enclosing a given line. */
function enclosingFunction(lines, lineNo) {
  for (let i = Math.min(lineNo, lines.length) - 1; i >= 0; i--) {
    const m = lines[i].match(/(?:function\s+([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s*)?(?:function|\([^)]*\)\s*=>))/);
    if (m) return m[1] || m[2] || 'anonymous';
  }
  return 'unknown';
}

export class BugDetectionAgent {
  constructor() {
    this.name = 'Bug Detection & Root Cause Agent';
    this.id = 'AGENT-DETECTOR-01';
    // Set by the orchestrator: returns a queued agent job when the platform
    // cannot see the customer's source and a self-hosted agent exists.
    this.onSourceUnavailable = null;
  }

  async analyze(issue, application) {
    const logs = [];
    logs.push(`[${this.name}] Starting Root Cause Analysis & Code Verification for Issue #${issue.id}...`);

    // 1. Resolve the customer's ACTUAL source code for this application
    const src = resolveSourceRoot(application);
    if (!src.root) {
      logs.push(`[${this.name}] Source code unavailable for ${application.name} (${application.id}).`);
      logs.push(`[${this.name}] ${src.error}`);
      if (this.onSourceUnavailable) {
        // Delegate to the customer's self-hosted agent when one is registered.
        const job = this.onSourceUnavailable(issue, application);
        if (job) {
          logs.push(`[${this.name}] Delegated to self-hosted source agent, job ${job.id}. Analysis will resume when it reports back.`);
          return {
            agentId: this.id, agentName: this.name, isValidBug: false,
            awaitingAgent: true, agentJobId: job.id,
            rootCauseSummary: `Source code is not visible to the platform. Analysis delegated to the customer's self-hosted source agent (job ${job.id}).`,
            logs
          };
        }
      }
      logs.push(`[${this.name}] No self-hosted source agent is registered for this application.`);
      return {
        agentId: this.id, agentName: this.name, isValidBug: false,
        noSource: true, rootCauseSummary: `Source code unavailable: ${src.error}`,
        logs
      };
    }
    logs.push(`[${this.name}] Source code resolved via ${src.via}: ${src.root}`);

    const files = indexSourceFiles(src.root);
    if (!files.length) {
      logs.push(`[${this.name}] ❌ No analysable source files found under ${src.root}.`);
      return { agentId: this.id, agentName: this.name, isValidBug: false, noSource: true, rootCauseSummary: `No source files found at ${src.root}`, logs };
    }
    logs.push(`[${this.name}] Indexed ${files.length} analysable source file(s) from the customer's repository.`);

    // 2. Rank candidate files using the user's own words + any stack trace
    const terms = keywords(`${issue.title} ${issue.description} ${issue.stackTrace || ''}`);
    const stackPaths = [...String(issue.stackTrace || '').matchAll(/([\w./-]+\.(?:js|jsx|mjs|cjs|ts|tsx|html|css|php|py|go|java))/g)].map(m => m[1]);
    logs.push(`[${this.name}] Extracted ${terms.length} analysis keyword(s) from the report${stackPaths.length ? ` and ${stackPaths.length} stack-trace file reference(s)` : ''}.`);

    const scored = [];
    for (const f of files) {
      let score = 0;
      const relLower = f.rel.toLowerCase();
      for (const sp of stackPaths) if (relLower.includes(sp.toLowerCase().split('/').pop())) score += 25;
      if (score === 0) {
        let content;
        try { content = fs.readFileSync(f.abs, 'utf-8'); } catch { continue; }
        const lower = content.toLowerCase();
        for (const t of terms) {
          if (relLower.includes(t)) score += 4;
          if (lower.includes(t)) score += 1;
        }
      }
      if (score > 0) scored.push({ ...f, score });
    }
    scored.sort((a, b) => b.score - a.score);
    const candidates = scored.filter(c => c.score >= 2).slice(0, 8);

    if (!candidates.length) {
      logs.push(`[${this.name}] ⚠️ Could not map the report onto any file by keyword. Trying universal AI assessment...`);
      const aiResult = await this.tryAiAssessment(issue, application, files.slice(0, 12), src, logs);
      if (aiResult) return aiResult;
      logs.push(`[${this.name}] ⚠️ Could not map the report onto any file in this repository. No code was modified.`);
      return {
        agentId: this.id, agentName: this.name, isValidBug: false,
        locationNotFound: true, sourceRoot: src.root,
        rootCauseSummary: `Report could not be mapped to any source file in ${application.name} (searched ${files.length} files for: ${terms.slice(0, 8).join(', ')}). No code was changed.`,
        logs
      };
    }
    logs.push(`[${this.name}] Candidate files: ${candidates.map(c => `${c.rel} (score ${c.score})`).join(', ')}`);

    // 3. Run static detectors over the candidates
    let best = null;
    for (const c of candidates) {
      let raw;
      try { raw = fs.readFileSync(c.abs, 'utf-8'); } catch { continue; }
      // Analyse with normalised line endings so diffs stay truthful; remember the
      // original ending so deployment writes the file back byte-consistently.
      const lineEnding = raw.includes('\r\n') ? '\r\n' : '\n';
      const code = raw.replace(/\r\n/g, '\n');
      const findings = analyzeFile(code, c.rel);
      if (!findings.length) continue;
      for (const f of findings) {
        const weighted = (f.confidence || 0.5) * 10 + Math.min(c.score, 20);
        if (!best || weighted > best.weighted) best = { finding: f, file: c, code, raw, lineEnding, weighted };
      }
    }

    if (!best) {
      logs.push(`[${this.name}] Deterministic detectors found no defect in the matched file(s). Trying universal AI assessment...`);
      const aiResult = await this.tryAiAssessment(issue, application, candidates, src, logs);
      if (aiResult) return aiResult;
      logs.push(`[${this.name}] ❌ VERIFICATION FAILED: static analysis found no genuine defect in the matched file(s).`);
      logs.push(`[${this.name}] Either the behaviour is already handled in code, or the report needs more detail. No patch generated.`);
      return {
        agentId: this.id, agentName: this.name, isValidBug: false,
        sourceRoot: src.root, targetFileRel: candidates[0].rel,
        rootCauseSummary: `No code defect reproduced by static analysis in ${candidates.slice(0, 3).map(c => c.rel).join(', ')}. The reported behaviour is not backed by a detectable code fault, so no patch was created.`,
        logs
      };
    }

    const { finding, file, code, lineEnding } = best;
    const lines = code.split('\n');
    logs.push(`[${this.name}] VERIFICATION PASSED: genuine defect detected in '${file.rel}' (${finding.type} / ${finding.detector}).`);
    logs.push(`[${this.name}] Evidence: ${finding.evidence}`);
    logs.push(`[${this.name}] Root Cause Summary: ${finding.description}`);

    return {
      agentId: this.id,
      agentName: this.name,
      isValidBug: true,
      bugType: finding.type,
      detector: finding.detector,
      finding,
      sourceRoot: src.root,
      sourceVia: src.via,
      targetFileRel: file.rel,
      fullFilePath: file.abs,
      targetFunction: enclosingFunction(lines, finding.line),
      lineRange: { start: Math.max(1, finding.line - 4), end: finding.line + 4 },
      rootCauseSummary: `${finding.description} (${file.rel}:${finding.line}, function ${enclosingFunction(lines, finding.line)})`,
      fileContent: code,
      confidence: finding.confidence,
      lineEnding,
      logs
    };
  }

  /**
   * Universal fallback: ask the configured LLM to assess any report class
   * (cosmetic, HTML/CSS, novel JS) against real file snippets. Returns a
   * detection result on success, or null to let the caller keep its honest
   * INVALID / NOT_FOUND outcome. Never throws.
   */
  async tryAiAssessment(issue, application, files, src, logs) {
    const status = getAiStatus();
    if (!status.configured) {
      logs.push(`[${this.name}] Universal AI assessment skipped: ${status.reason}`);
      return null;
    }
    const withSnippets = [];
    for (const f of files.slice(0, 6)) {
      try {
        const raw = fs.readFileSync(f.abs, 'utf-8');
        withSnippets.push({ rel: f.rel, abs: f.abs, snippet: raw.replace(/\r\n/g, '\n').slice(0, 8000) });
      } catch { /* unreadable */ }
    }
    if (!withSnippets.length) return null;
    logs.push(`[${this.name}] Asking ${status.model} to assess ${withSnippets.length} file(s) for any defect class...`);
    let verdict;
    try {
      verdict = await aiAssess({ issue, candidates: withSnippets });
    } catch (e) {
      logs.push(`[${this.name}] AI assessment failed honestly: ${e.message}`);
      return null;
    }
    if (!verdict || verdict.isValidBug !== true || !verdict.targetFile) {
      logs.push(`[${this.name}] AI assessment: no genuine defect in the shown code.`);
      return null;
    }
    const match = withSnippets.find(f => f.rel === verdict.targetFile)
      || [...files].find(f => f.rel === verdict.targetFile);
    if (!match || !match.abs) {
      logs.push(`[${this.name}] AI nominated an unknown file (${verdict.targetFile}); discarding to avoid inventing code.`);
      return null;
    }
    let raw;
    try { raw = fs.readFileSync(match.abs, 'utf-8'); } catch { return null; }
    const lineEnding = raw.includes('\r\n') ? '\r\n' : '\n';
    const code = raw.replace(/\r\n/g, '\n');
    const lines = code.split('\n');
    const line = Math.min(Math.max(1, Number(verdict.line) || 1), lines.length);
    const bugType = String(verdict.bugType || 'AI_GENERAL').toUpperCase().replace(/[^A-Z0-9_]/g, '_').slice(0, 40) || 'AI_GENERAL';
    const confidence = Math.min(0.95, Math.max(0.3, Number(verdict.confidence) || 0.6));
    const description = String(verdict.rootCause || 'AI-confirmed defect');
    logs.push(`[${this.name}] VERIFICATION PASSED (universal AI): genuine defect in '${match.rel}' (${bugType}).`);
    logs.push(`[${this.name}] Evidence: ${description}`);
    const finding = {
      type: bugType, detector: 'AiGeneralist', line,
      evidence: description, targetExpr: lines[line - 1]?.trim().slice(0, 200) || '',
      description, fix: null, confidence, autoFixable: true, aiGenerated: true
    };
    return {
      agentId: this.id, agentName: this.name, isValidBug: true,
      bugType, detector: 'AiGeneralist', finding,
      sourceRoot: src.root, sourceVia: src.via,
      targetFileRel: match.rel, fullFilePath: match.abs,
      targetFunction: enclosingFunction(lines, line),
      lineRange: { start: Math.max(1, line - 4), end: line + 4 },
      rootCauseSummary: `${description} (${match.rel}:${line})`,
      fileContent: code, confidence, lineEnding, logs
    };
  }
}