/**
 * Reproducible evaluation harness.
 *
 * Runs three systems over the labeled corpus and records real measurements:
 *   S1  keyword-only baseline   — rank files by report keywords, patch top hit (no static analysis)
 *   S2  static-analysis-only    — rank + analyse, take first finding, no risk gate / no AST gate
 *   S3  BugShield full pipeline — detector + risk governance gate + patch + AST validation
 *
 * Nothing is written to the corpus: patches are produced and validated in memory.
 * Run: node benchmark/run-eval.mjs
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { BugDetectionAgent } from '../platform/agents/detectorAgent.js';
import { RiskClassificationAgent } from '../platform/agents/riskAgent.js';
import { PatchGenerationAgent } from '../platform/agents/patchAgent.js';
import { analyzeFile, validateJs } from '../platform/services/analyzers.js';
import { writeSource, clearSource, indexSourceFiles } from '../platform/services/workspace.js';
import { HIGH_THRESHOLD } from '../platform/services/riskConfig.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const CASES_DIR = path.join(ROOT, 'benchmark', 'cases');
const BENCH_APP_ID = 'BENCHHARNESS';

const STOP = new Set(['the','and','for','with','that','this','from','have','has','was','were','are','but','not','you','your','when','what','where','which','while','into','out','get','set','use','using','used','can','could','would','should','there','their','them','then','than','they','been','being','does','did','doing','also','just','like','about','after','before','because','some','more','most','only','other','such','own','same','too','very','will','may','one','two','bug','issue','error','problem','page','user','users','please','help','report','failing','fails','fail','failed','broken','working','work','works','happens','happening','clicked','click','tried','trying']);

function keywords(text) {
  const words = String(text || '').toLowerCase().match(/[a-z][a-z0-9_]{2,}/g) || [];
  return [...new Set(words.filter(w => !STOP.has(w)))];
}

/** S1: naive keyword ranking, no code inspection at all. */
function runKeywordBaseline(caseObj, projectRoot) {
  const t0 = performance.now();
  const files = indexSourceFiles(projectRoot);
  const terms = keywords(`${caseObj.report.title} ${caseObj.report.description}`);
  let best = null;
  for (const f of files) {
    let score = 0;
    let content = '';
    try { content = fs.readFileSync(f.abs, 'utf-8').toLowerCase(); } catch {}
    for (const t of terms) { if (f.rel.toLowerCase().includes(t)) score += 4; if (content.includes(t)) score += 1; }
    if (!best || score > best.score) best = { rel: f.rel, score };
  }
  const selected = best && best.score > 0 ? best.rel : null;
  return {
    system: 'S1-keyword-only',
    selectedFile: selected,
    detectedType: null,
    verdictValid: !!selected,
    patchGenerated: !!selected,      // naive system always "fixes" its top match
    patchSyntaxValid: null,
    escalatedByRisk: false,
    riskScore: null,
    timeMs: +(performance.now() - t0).toFixed(2)
  };
}

/** S2: static analysis without governance or validation. */
function runStaticOnlyBaseline(caseObj, projectRoot) {
  const t0 = performance.now();
  const files = indexSourceFiles(projectRoot);
  const terms = keywords(`${caseObj.report.title} ${caseObj.report.description}`);
  const ranked = files.map(f => {
    let score = 0;
    let content = '';
    try { content = fs.readFileSync(f.abs, 'utf-8').toLowerCase(); } catch {}
    for (const t of terms) { if (f.rel.toLowerCase().includes(t)) score += 4; if (content.includes(t)) score += 1; }
    return { ...f, score };
  }).sort((a, b) => b.score - a.score);

  for (const f of ranked) {
    const code = fs.readFileSync(f.abs, 'utf-8').replace(/\r\n/g, '\n');
    const findings = analyzeFile(code, f.rel);
    if (findings.length) {
      return {
        system: 'S2-static-only',
        selectedFile: f.rel,
        detectedType: findings[0].type,
        verdictValid: true,
        patchGenerated: true,        // no AST validation performed
        patchSyntaxValid: null,
        escalatedByRisk: false,      // no governance gate
        riskScore: null,
        timeMs: +(performance.now() - t0).toFixed(2)
      };
    }
  }
  return { system: 'S2-static-only', selectedFile: null, detectedType: null, verdictValid: false, patchGenerated: false, patchSyntaxValid: null, escalatedByRisk: false, riskScore: null, timeMs: +(performance.now() - t0).toFixed(2) };
}

/** S3: the real multi-agent path. */
async function runFullPipeline(caseObj, projectRoot) {
  const t0 = performance.now();
  writeSource(BENCH_APP_ID, { localPath: projectRoot });
  const application = { id: BENCH_APP_ID, name: caseObj.id, type: 'benchmark', repoUrl: '', branch: 'main' };
  const issue = { id: `BENCH-${caseObj.id}`, title: caseObj.report.title, description: caseObj.report.description, stackTrace: '', status: 'RECEIVED' };

  const detection = await new BugDetectionAgent().analyze(issue, application);
  if (!detection.isValidBug) {
    return {
      system: 'S3-bugshield',
      selectedFile: null,
      detectedType: null,
      verdictValid: false,
      patchGenerated: false,
      patchSyntaxValid: null,
      escalatedByRisk: false,
      riskScore: 0,
      stopReason: detection.noSource ? 'SOURCE_UNAVAILABLE' : detection.locationNotFound ? 'LOCATION_NOT_FOUND' : 'INVALID_REPORT',
      timeMs: +(performance.now() - t0).toFixed(2)
    };
  }
  const risk = await new RiskClassificationAgent().classify(detection, issue);
  const patch = await new PatchGenerationAgent().generate(detection, risk);
  return {
    system: 'S3-bugshield',
    selectedFile: detection.targetFileRel,
    detectedType: detection.bugType,
    verdictValid: true,
    patchGenerated: !!patch.diff,
    patchSyntaxValid: patch.syntaxValid,
    escalatedByRisk: risk.riskScore >= HIGH_THRESHOLD,
    riskScore: risk.riskScore,
    riskLevel: risk.riskLevel,
    timeMs: +(performance.now() - t0).toFixed(2)
  };
}

/** Only the full pipeline performs AST validation; for the baselines this metric
 *  is reported as null ("not validated") rather than as 0%, so the comparison
 *  does not credit or penalise a stage those systems simply do not have. */
const VALIDATES = { 'S1-keyword-only': false, 'S2-static-only': false, 'S3-bugshield': true };

function score(runs, cases) {
  const positives = cases.filter(c => c.expect.validBug);
  const negatives = cases.filter(c => !c.expect.validBug);
  const detectedPos = runs.filter(r => r.positive && r.verdictValid && r.selectedFile === r.expectFile);
  const fileOk = runs.filter(r => r.positive && r.selectedFile === r.expectFile);
  const falsePatches = runs.filter(r => !r.positive && r.patchGenerated);
  const patches = runs.filter(r => r.patchGenerated);
  const validPatches = patches.filter(r => r.patchSyntaxValid === true);
  const typeOk = runs.filter(r => r.positive && r.detectedType === r.expectType);
  const system = runs[0]?.system;
  const validates = VALIDATES[system];
  const round = (n, d = 4) => (n === undefined || d === 0 ? null : +(n * 100 / d).toFixed(1));
  return {
    cases: cases.length,
    positives: positives.length,
    negatives: negatives.length,
    fileIdentificationAccuracyPct: round(fileOk.length, positives.length),
    defectDetectionRecallPct: round(detectedPos.length, positives.length),
    bugTypeAccuracyPct: round(typeOk.length, positives.length),
    falsePositiveRatePct: round(falsePatches.length, negatives.length),
    patchGenerated: patches.length,
    validatesPatches: validates,
    patchSyntaxValidityPct: !validates ? null : (patches.length ? round(validPatches.length, patches.length) : null),
    escalatedByGovernance: runs.filter(r => r.escalatedByRisk).length,
    wouldAutoDeploy: positives.length ? positives.length - runs.filter(r => r.positive && r.escalatedByRisk).length : 0,
    meanDecisionTimeMs: +(runs.reduce((s, r) => s + r.timeMs, 0) / runs.length).toFixed(2),
    meanTimeToValidatedPatchMs: validPatches.length
      ? +(validPatches.reduce((s, r) => s + r.timeMs, 0) / validPatches.length).toFixed(2)
      : null
  };
}

const caseIds = fs.readdirSync(CASES_DIR).filter(d => fs.statSync(path.join(CASES_DIR, d)).isDirectory()).sort();
const cases = caseIds.map(id => ({ id, ...JSON.parse(fs.readFileSync(path.join(CASES_DIR, id, 'case.json'), 'utf-8')) }));

const allRuns = { 'S1-keyword-only': [], 'S2-static-only': [], 'S3-bugshield': [] };
for (const c of cases) {
  const projectRoot = path.join(CASES_DIR, c.id, 'project');
  const runs = [
    runKeywordBaseline(c, projectRoot),
    runStaticOnlyBaseline(c, projectRoot),
    await runFullPipeline(c, projectRoot)
  ];
  for (const r of runs) {
    allRuns[r.system].push({ case: c.id, positive: c.expect.validBug, expectFile: c.expect.file, expectType: c.expect.type, ...r });
  }
}
clearSource(BENCH_APP_ID);

const results = {
  generatedAt: new Date().toISOString(),
  corpusPath: 'benchmark/cases',
  corpusSize: cases.length,
  riskHighThreshold: HIGH_THRESHOLD,
  systems: Object.fromEntries(Object.entries(allRuns).map(([k, v]) => [k, score(v, cases)])),
  detail: allRuns
};

fs.writeFileSync(path.join(ROOT, 'benchmark', 'results.json'), JSON.stringify(results, null, 2));

console.log(`\nCorpus: ${cases.length} labelled cases (${cases.filter(c => c.expect.validBug).length} with genuine defects, ${cases.filter(c => !c.expect.validBug).length} negative controls)\n`);
for (const [name, m] of Object.entries(results.systems)) {
  console.log(`--- ${name} ---`);
  console.log(`  file identification accuracy : ${m.fileIdentificationAccuracyPct}%`);
  console.log(`  defect detection recall     : ${m.defectDetectionRecallPct}%`);
  console.log(`  bug-type accuracy           : ${m.bugTypeAccuracyPct}%`);
  console.log(`  false-positive rate         : ${m.falsePositiveRatePct}%`);
  console.log(`  patch syntax validity       : ${m.patchSyntaxValidityPct === null ? 'not validated (no AST stage in this baseline)' : m.patchSyntaxValidityPct + '%'}`);
  console.log(`  escalated by governance     : ${m.escalatedByGovernance} of ${m.positives} genuine defects`);
  console.log(`  mean decision time          : ${m.meanDecisionTimeMs} ms`);
  console.log(`  mean time to validated patch: ${m.meanTimeToValidatedPatchMs === null ? 'n/a' : m.meanTimeToValidatedPatchMs + ' ms'}\n`);
}
console.log('Per-case results written to benchmark/results.json');