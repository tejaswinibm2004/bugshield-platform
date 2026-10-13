import test from 'node:test';
import assert from 'node:assert/strict';

import { getAiStatus, isAiConfigured } from '../platform/services/aiProvider.js';
import { RiskClassificationAgent } from '../platform/agents/riskAgent.js';
import { PatchGenerationAgent } from '../platform/agents/patchAgent.js';

delete process.env.AI_API_KEY;
delete process.env.OPENAI_API_KEY;

test('AI provider honestly reports unconfigured when no key is set', () => {
  const s = getAiStatus();
  assert.equal(s.configured, false);
  assert.equal(isAiConfigured(), false);
  assert.match(s.reason, /AI_API_KEY/);
});

test('risk agent scores a generic AI defect class without crashing', async () => {
  const agent = new RiskClassificationAgent();
  const r = await agent.classify(
    { targetFileRel: 'src/banner.css', bugType: 'CSS_LAYOUT', confidence: 0.7 },
    { title: 'banner overlaps on mobile', description: 'cosmetic' },
    null
  );
  assert.ok(['LOW', 'MEDIUM', 'HIGH'].includes(r.riskLevel));
  assert.ok(r.riskScore >= 5 && r.riskScore <= 100);
  assert.equal(r.requiresAdminApproval, true); // autoDeploy off by default
});

test('patch agent without AI configured produces no fake diff for novel shapes', async () => {
  const agent = new PatchGenerationAgent();
  const out = await agent.generate({
    bugType: 'COSMETIC_TEXT',
    targetFileRel: 'src/banner.html',
    fullFilePath: '/nonexistent/banner.html',
    fileContent: '<h1>Totle</h1>\n',
    finding: { type: 'COSMETIC_TEXT', detector: 'AiGeneralist', line: 1, evidence: 'typo', description: 'typo', fix: null, confidence: 0.6, autoFixable: true, aiGenerated: true },
    sourceRoot: null,
    lineEnding: '\n'
  }, { riskLevel: 'LOW' }, { title: 'typo', description: 'Totle should be Title' });
  assert.equal(out.syntaxValid, false);
  assert.equal(out.diff, '');
});
