import fs from 'fs';
import path from 'path';
import { analyzeFile, applyFinding, unifiedDiff, validateJs } from '../platform/services/analyzers.js';

const ROOT = process.cwd();
const targets = [
  'demo-apps/quickshop/src/couponService.js',
  'demo-apps/bitedash/src/deliveryService.js',
  'demo-apps/quickshop/src/checkoutService.js'
];

for (const rel of targets) {
  const abs = path.join(ROOT, rel);
  const code = fs.readFileSync(abs, 'utf-8');
  console.log('\n================ ' + rel + ' ================');
  const findings = analyzeFile(code, rel);
  if (!findings.length) { console.log('  !! NO FINDINGS'); continue; }
  for (const f of findings) {
    console.log(`  [${f.type}] line ${f.line} conf=${f.confidence} auto=${f.autoFixable}`);
    console.log(`     evidence: ${f.evidence}`);
    if (!f.autoFixable) continue;
    const patched = applyFinding(code, f);
    if (patched == null) { console.log('     !! applyFinding returned null'); continue; }
    const v = validateJs(patched);
    console.log(`     applied + syntax ${v.ok ? 'VALID' : 'INVALID: ' + v.error}`);
    console.log('     ' + unifiedDiff(code, patched, rel).split('\n').filter(l => l.startsWith('+') || l.startsWith('-')).filter(l => !l.startsWith('+++') && !l.startsWith('---')).join('\n     '));
  }
}