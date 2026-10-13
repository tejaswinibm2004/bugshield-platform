/**
 * Generic (file-agnostic) bug analysis + remediation.
 *
 * Nothing here is keyed to a demo app or a fixed file list: the detectors look at
 * whatever source the connected website actually ships, and every remediation is
 * synthesised from the code that was read (never a stored/hardcoded diff).
 */

export const PERSIST_CALL = /^(save|insert|create|store|write|persist|submit|add|update|delete|upsert|remove|send|upload|post)[A-Za-z0-9_$]*$/;
export const PERSIST_SUFFIX = /(ToDatabase|ToDb|ToStore|Record|Records|Persistence|Repository)$/;

const SAFE_DIV_FN = `__bugShieldSafeDiv`;
const MEDIAN_FN = `__bugShieldMedian`;

const HELPERS = {
  [SAFE_DIV_FN]: `function ${SAFE_DIV_FN}(numerator, denominator, fallback = 0) {
  if (typeof denominator !== 'number' || !Number.isFinite(denominator) || denominator === 0) return fallback;
  const result = numerator / denominator;
  return Number.isFinite(result) ? result : fallback;
}`,
  [MEDIAN_FN]: `function ${MEDIAN_FN}(values) {
  const nums = (values || []).filter(v => typeof v === 'number' && Number.isFinite(v)).sort((a, b) => a - b);
  if (!nums.length) return 1;
  const mid = Math.floor(nums.length / 2);
  return nums.length % 2 ? nums[mid] : (nums[mid - 1] + nums[mid]) / 2;
}`
};

/** Remove // and block comments while preserving line structure. */
export function stripComments(code) {
  return code
    .replace(/\/\*[\s\S]*?\*\//g, m => m.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:])\/\/[^\n]*/g, (m, p1) => p1 + ' '.repeat(Math.max(0, m.length - p1.length)));
}

function isJsPath(rel) {
  return /\.(js|jsx|mjs|cjs)$/i.test(rel);
}

/** Runtime syntax validation, same technique the platform already used. */
export function validateJs(code) {
  try {
    const check = code
      .replace(/^\s*import[\s\S]*?;$/gm, '')
      .replace(/export\s+default\s+/g, 'const __default = ')
      .replace(/export\s+/g, '');
    new Function(`(async () => { ${check} })`);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/** Index of the first division slash that is not part of a comment or regex. */
function findTopLevelDivision(expr) {
  let depth = 0, inStr = null;
  for (let i = 0; i < expr.length; i++) {
    const c = expr[i];
    if (inStr) { if (c === inStr && expr[i - 1] !== '\\') inStr = null; continue; }
    if (c === '"' || c === "'" || c === '`') { inStr = c; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (c === '/' && depth === 0) {
      const prev = expr[i - 1], next = expr[i + 1];
      if (prev === '/' || prev === '*' || next === '/') continue;
      if (next === '*') continue;
      return i;
    }
  }
  return -1;
}

/** Split `a / b` respecting nested parens. */
function splitDivision(expr) {
  const idx = findTopLevelDivision(expr);
  if (idx === -1) return null;
  let numer = expr.slice(0, idx).trim();
  let denom = expr.slice(idx + 1).trim();
  const stripOuter = s => {
    s = s.trim();
    while (s.startsWith('(') && s.endsWith(')')) {
      let d = 0, wraps = true;
      for (let i = 0; i < s.length; i++) {
        if (s[i] === '(') d++;
        else if (s[i] === ')') { d--; if (d === 0 && i < s.length - 1) { wraps = false; break; } }
      }
      if (!wraps) break;
      s = s.slice(1, -1).trim();
    }
    return s;
  };
  return { numer: stripOuter(numer), denom: stripOuter(denom) };
}

const GUARD_TOKENS = ['??', '||', '=== 0', '!== 0', 'Number.isFinite', 'isFinite', 'Math.abs', '> 0', '!= 0'];
const isGuarded = stmt => GUARD_TOKENS.some(t => stmt.includes(t));

/** Detector 1: division whose denominator can evaluate to zero. */
function detectDivisionByZero(code) {
  const clean = stripComments(code);
  const findings = [];

  // Two shapes cover almost all real code:
  //   const total = a / b;      (declaration)
  //   return a / b;            (direct return)
  const shapes = [
    { re: /(^[ \t]*)(const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+);/gm, kind: 'assign' },
    { re: /(^[ \t]*)return\s+([^;\n]+);/gm, kind: 'return' }
  ];

  for (const shape of shapes) {
    let m;
    shape.re.lastIndex = 0;
    while ((m = shape.re.exec(clean))) {
      const expr = shape.kind === 'assign' ? m[4] : m[2];
      const name = shape.kind === 'assign' ? m[3] : null;
      const parts = splitDivision(expr);
      if (!parts) continue;
      const { numer, denom } = parts;
      if (!numer || !denom) continue;
      if (/^[-+]?[\d.]+$/.test(denom) && denom !== '0') continue; // safe literal divisor
      if (isGuarded(m[0])) continue;
      const risky = /[-+*/%]/.test(denom) || /^[A-Za-z_$][\w$.]*$/.test(denom) || /[?:]/.test(denom);
      if (!risky) continue;

      findings.push({
        type: 'DIV_ZERO',
        detector: 'DenominatorCanBeZero',
        line: clean.slice(0, m.index).split('\n').length,
        evidence: name ? `${name} = ${numer} / ${denom}` : `return ${numer} / ${denom}`,
        targetExpr: expr.trim(),
        description: `Division in \`${name || 'returned value'}\` uses \`${denom}\` as denominator without a zero/NaN guard, which yields Infinity or NaN when that value is 0.`,
        fix: { kind: 'safe-div', name, numer, denom, returnForm: shape.kind === 'return' },
        confidence: 0.9,
        autoFixable: true
      });
    }
  }
  return findings;
}

/** Detector 2: object literal indexed by a dynamic key that is not one of its keys. */
function detectUndefinedDynamicKey(code) {
  const clean = stripComments(code);
  const findings = [];

  const literals = [];
  const litRe = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{([\s\S]*?)\}\s*[;,)]/g;
  let lm;
  while ((lm = litRe.exec(clean))) {
    const keys = [...lm[2].matchAll(/([A-Za-z_$][\w$]*)\s*:/g)].map(k => k[1]);
    const nums = [...lm[2].matchAll(/:\s*(-?[\d.]+)/g)].map(k => Number(k[1])).filter(Number.isFinite);
    if (keys.length) literals.push({ name: lm[1], keys, nums, index: lm.index });
  }
  if (!literals.length) return findings;

  for (const lit of literals) {
    const useRe = new RegExp(`${lit.name}\\s*\\[\\s*([A-Za-z_$][\\w$]*)\\s*\\]`, 'g');
    let um;
    while ((um = useRe.exec(clean))) {
      const keyVar = um[1];
      if (lit.keys.includes(keyVar)) continue;
      if (/^(length|length\s*-\s*\d+)$/.test(keyVar)) continue;
      if (isGuarded(um[0])) continue;
      // Collect EVERY literal the key variable can hold, including conditional re-assignments
      // like `if (cond) tier = 'extended';` which are the real source of the undefined lookup.
      const assignRe = new RegExp(`(?:\\b(?:const|let|var)\\s+)?${keyVar}\\s*=\\s*['"\`]([^'"\`]+)['"\`]`, 'g');
      const knownValues = [...clean.matchAll(assignRe)].map(a => a[1]);
      const outOfKeys = knownValues.filter(v => !lit.keys.includes(v));
      if (knownValues.length && !outOfKeys.length) continue; // provably limited to known keys
      findings.push({
        type: 'UNDEFINED_DYNAMIC_KEY',
        detector: 'DynamicKeyNotInObject',
        line: clean.slice(0, um.index).split('\n').length,
        evidence: outOfKeys.length
          ? `${lit.name}[${keyVar}] but keys are [${lit.keys.join(', ')}] and ${keyVar} may be '${outOfKeys[0]}'`
          : `${lit.name}[${keyVar}] but keys are [${lit.keys.join(', ')}]`,
        targetExpr: um[0],
        description: `\`${lit.name}\` is indexed with \`${keyVar}\` which can be a value outside its defined keys (${lit.keys.join(', ')}), producing \`undefined\` and a NaN result.`,
        fix: { kind: 'dynamic-key', objName: lit.name, keyVar, fullExpr: um[0], siblingNums: lit.nums },
        confidence: outOfKeys.length ? 0.9 : 0.6,
        autoFixable: true
      });
    }
  }
  return findings;
}

/** Detector 3: async persistence call that is neither awaited nor wrapped in try/catch. */
function detectMissingAwait(code) {
  const clean = stripComments(code);
  const findings = [];
  const fnRe = /async\s+function\s+([A-Za-z_$][\w$]*)?\s*\([^)]*\)\s*\{/g;
  let fm;
  while ((fm = fnRe.exec(clean))) {
    const bodyStart = fm.index + fm[0].length;
    let depth = 1, i = bodyStart;
    while (i < clean.length && depth > 0) { if (clean[i] === '{') depth++; else if (clean[i] === '}') depth--; i++; }
    const body = clean.slice(bodyStart, i - 1);
    const bodyOffsetLine = clean.slice(0, bodyStart).split('\n').length - 1;

    const callRe = /^[ \t]*([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*;[ \t]*$/gm;
    let cm;
    while ((cm = callRe.exec(body))) {
      const fnName = cm[1];
      const isPersist = PERSIST_CALL.test(fnName) || PERSIST_SUFFIX.test(fnName);
      if (!isPersist) continue;
      if (/await|void|\.then\(|return\s/.test(cm[0])) continue;
      if (/^[ \t]*async\s+function\s+/.test(cm[0])) continue;
      const before = body.slice(0, cm.index);
      if (/\btry\s*\{[^}]*$/.test(before)) continue; // inside a try block
      findings.push({
        type: 'MISSING_AWAIT',
        detector: 'AsyncPersistenceNotAwaited',
        line: bodyOffsetLine + body.slice(0, cm.index).split('\n').length,
        evidence: `${fnName}(...) called without await inside an async function`,
        targetExpr: cm[0].trim(),
        indent: cm[0].match(/^[ \t]*/)[0],
        description: `\`${fnName}\` is asynchronous but is called without \`await\` and without error handling, so a rejection is swallowed and the caller continues as if the write succeeded.`,
        fix: { kind: 'missing-await', fnName, args: cm[2], indent: cm[0].match(/^[ \t]*/)[0] },
        confidence: 0.85,
        autoFixable: true
      });
    }
  }
  return findings;
}

/** Detector 4 (detect only): dereference of a variable explicitly set to null. */
function detectNullDereference(code) {
  const clean = stripComments(code);
  const findings = [];
  const declRe = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*null\s*;/g;
  let m;
  while ((m = declRe.exec(clean))) {
    const name = m[1];
    const useRe = new RegExp(`${name}\\s*\\.\\s*[A-Za-z_$][\\w$]*`, 'g');
    let um;
    while ((um = useRe.exec(clean))) {
      const beforeLine = clean.slice(clean.lastIndexOf('\n', um.index) + 1, um.index);
      if (/if\s*\(|\?\?|\?\.|\|\|/.test(beforeLine)) continue;
      findings.push({
        type: 'NULL_DEREF',
        detector: 'DereferenceOfNullValue',
        line: clean.slice(0, um.index).split('\n').length,
        evidence: `${name} is initialised to null then dereferenced as ${um[0].trim()}`,
        description: `\`${name}\` is set to \`null\` and later dereferenced without a guard, which throws a TypeError at runtime.`,
        fix: null,
        confidence: 0.7,
        autoFixable: false
      });
    }
  }
  return findings;
}

const DETECTORS = [detectDivisionByZero, detectMissingAwait, detectUndefinedDynamicKey, detectNullDereference];

/** Run every detector against one file's source. */
export function analyzeFile(code, relPath) {
  if (!isJsPath(relPath)) return [];
  const out = [];
  for (const d of DETECTORS) {
    try { out.push(...d(code)); } catch { /* detector safety */ }
  }
  return out.sort((a, b) => a.line - b.line);
}

/** Apply one finding, returning the new full file content. */
export function applyFinding(code, finding) {
  const f = finding.fix;
  if (!f) return null;

  if (f.kind === 'safe-div') {
    const call = `${SAFE_DIV_FN}(${f.numer}, ${f.denom}, 0)`;
    if (f.returnForm) {
      const re = /return\s+[^;\n]+;/;
      const lines = code.split('\n');
      const idx = lines.findIndex(l => l.includes(f.targetExpr));
      if (idx === -1) return null;
      lines[idx] = lines[idx].replace(f.targetExpr, `return ${call};`);
      return appendHelpers(lines.join('\n'), [SAFE_DIV_FN]);
    }
    const re = new RegExp(`((?:const|let|var)\\s+${f.name}\\s*=\\s*)([^;\\n]+);`);
    if (!re.test(code)) return null;
    const next = code.replace(re, `$1${call};`);
    return appendHelpers(next, [SAFE_DIV_FN]);
  }

  if (f.kind === 'dynamic-key') {
    const nums = f.siblingNums.length ? f.siblingNums : [];
    const fallback = `${MEDIAN_FN}([${nums.join(', ')}])`;
    const guarded = `(${f.fullExpr} ?? ${fallback})`;
    // replace only the occurrence on the detected line
    const lines = code.split('\n');
    const idx = lines.findIndex(l => l.includes(f.fullExpr));
    if (idx === -1) return null;
    lines[idx] = lines[idx].split(f.fullExpr).join(guarded);
    return appendHelpers(lines.join('\n'), [MEDIAN_FN]);
  }

  if (f.kind === 'missing-await') {
    const call = `${f.fnName}(${f.args});`;
    const lines = code.split('\n');
    const idx = lines.findIndex(l => l.trim() === call);
    if (idx === -1) return null;
    const ind = f.indent || '';
    const block = [
      `${ind}try {`,
      `${ind}  await ${f.fnName}(${f.args});`,
      `${ind}} catch (err) {`,
      `${ind}  console.error('${f.fnName} failed:', err);`,
      `${ind}}`
    ];
    lines.splice(idx, 1, ...block);
    return lines.join('\n');
  }
  return null;
}

function appendHelpers(code, names) {
  const missing = names.filter(n => !code.includes(`function ${n}(`));
  if (!missing.length) return code;
  const helpers = missing.map(n => `// Added by BugShield static-analysis guard\n${HELPERS[n]}`).join('\n\n');
  return `${code.replace(/\s*$/, '')}\n\n${helpers}\n`;
}

/** Real line-based unified diff (LCS), replacing the previous description-only stub. */
export function unifiedDiff(oldCode, newCode, relPath) {
  const a = oldCode.split('\n');
  const b = newCode.split('\n');
  const n = a.length, m = b.length;
  if (n * m > 4000000) return `--- a/${relPath}\n+++ b/${relPath}\n@@ file too large for inline diff @@`;

  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const ops = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { ops.push({ t: ' ', s: a[i] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { ops.push({ t: '-', s: a[i] }); i++; }
    else { ops.push({ t: '+', s: b[j] }); j++; }
  }
  while (i < n) { ops.push({ t: '-', s: a[i] }); i++; }
  while (j < m) { ops.push({ t: '+', s: b[j] }); j++; }

  const changed = ops.some(o => o.t !== ' ');
  if (!changed) return '';

  const hunks = [];
  const CONTEXT = 3;
  let idx = 0;
  while (idx < ops.length) {
    if (ops[idx].t === ' ') { idx++; continue; }
    let start = idx, end = idx;
    while (end < ops.length) {
      if (ops[end].t !== ' ') {
        end++;
        continue;
      }
      let run = 0, k = end;
      while (k < ops.length && ops[k].t === ' ') { run++; k++; }
      if (run > CONTEXT * 2 || k >= ops.length) break;
      end = k;
    }
    const from = Math.max(0, start - CONTEXT);
    const to = Math.min(ops.length, end + CONTEXT);
    let aStart = 0, bStart = 0, aCount = 0, bCount = 0;
    for (let k = 0; k < from; k++) { if (ops[k].t !== '+') aStart++; if (ops[k].t !== '-') bStart++; }
    for (let k = from; k < to; k++) { if (ops[k].t !== '+') aCount++; if (ops[k].t !== '-') bCount++; }
    const body = ops.slice(from, to).map(o => `${o.t}${o.s}`).join('\n');
    hunks.push(`@@ -${aStart + 1},${aCount} +${bStart + 1},${bCount} @@\n${body}`);
    idx = end;
  }
  return `--- a/${relPath}\n+++ b/${relPath}\n${hunks.join('\n')}\n`;
}