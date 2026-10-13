/**
 * Universal AI provider — Gemini 3.8 Flash by OpenCode (default).
 *
 * Why this exists: deterministic detectors cover 4 JS defect classes. Every
 * other report (cosmetic text/CSS, HTML, novel JS bugs) needs a generalist.
 * This module is the single place that talks to an LLM.
 *
 * Default route — OpenRouter, model `openrouter/free`:
 *   model    openrouter/free
 *   endpoint POST https://openrouter.ai/api/v1/chat/completions (OpenAI-compatible)
 *   key      AI_API_KEY (OpenRouter key)
 *
 * Other routes: Gemini models use the Google generateContent shape (direct
 * Google or the OpenCode gateway); Muse Spark / GPT-style models on opencode
 * use the OpenAI Responses API ({base}/responses). The shape is picked from
 * the configured model/provider, never guessed per call.
 *
 * Honesty rule: when no key is configured, callers keep their current
 * INVALID_REPORT / manual-review behaviour. Nothing pretends to be AI.
 */

const DEFAULT_BASE_URL = 'https://openrouter.ai/api/v1';
const DEFAULT_MODEL = 'openrouter/free';
const DEFAULT_PROVIDER = 'openrouter';

function getApiKey() {
  return process.env.AI_API_KEY
    || process.env.OPENROUTER_API_KEY
    || process.env.OPENCODE_API_KEY
    || process.env.GEMINI_API_KEY
    || process.env.GOOGLE_API_KEY
    || '';
}

export function getAiStatus() {
  const provider = process.env.AI_PROVIDER || DEFAULT_PROVIDER;
  const baseUrl = process.env.AI_BASE_URL || DEFAULT_BASE_URL;
  const model = process.env.AI_MODEL || DEFAULT_MODEL;
  if (!getApiKey()) {
    return {
      configured: false,
      provider,
      model,
      baseUrl,
      reason: 'Set AI_API_KEY (an OpenRouter key from https://openrouter.ai/keys) to enable universal assessment and patching with openrouter/free.'
    };
  }
  return { configured: true, provider, model, baseUrl, reason: null };
}

export function isAiConfigured() {
  return getAiStatus().configured;
}

/** Gemini models speak the Google generateContent shape, including via opencode. */
function isGemini(status) {
  return /^gemini-/i.test(status.model || '');
}

/** True when the configured endpoint speaks the OpenAI Responses API. */
function isResponsesEndpoint(status) {
  if (isGemini(status)) return false;
  return status.provider === 'opencode' || /opencode\.ai/.test(status.baseUrl || '');
}

function timeoutFetch(url, opts, ms = 60000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  return fetch(url, { ...opts, signal: ctrl.signal }).finally(() => clearTimeout(t));
}

/**
 * Bounded retry for transient provider pressure. 429s back off briefly;
 * 503 capacity crunches get longer waits. Fixed attempt counts — pipelines
 * never hang or loop.
 */
async function fetchWithRetry(url, opts, ms) {
  const schedules = { 429: [2000, 5000], 503: [10000, 30000, 60000], network: [2000, 5000] };
  for (let attempt = 0; ; attempt++) {
    let res;
    try {
      res = await timeoutFetch(url, opts, ms);
    } catch (e) {
      const delays = schedules.network;
      if (attempt >= delays.length) throw e;
      await new Promise(r => setTimeout(r, delays[attempt]));
      continue;
    }
    const delays = schedules[res.status];
    if (delays && attempt < delays.length) {
      await res.text().catch(() => {});
      await new Promise(r => setTimeout(r, delays[attempt]));
      continue;
    }
    if (!res.ok) return res; // fail fast on real errors (auth, bad request)
    return res;
  }
}

function extractJson(content) {
  try {
    return JSON.parse(content);
  } catch {
    // Some models wrap JSON in fences — strip and retry once.
    const stripped = String(content).replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();
    return JSON.parse(stripped);
  }
}

async function readError(res) {
  try { return (await res.text()).slice(0, 300); }
  catch { return ''; }
}

/** Google-compatible generateContent (direct Google or opencode gateway). */
async function callGemini({ status, apiKey, system, user, maxTokens, temperature }) {
  const base = status.baseUrl.replace(/\/$/, '');
  const url = /\/models\/[^/]+$/.test(base)
    ? `${base}:generateContent`
    : `${base}/models/${status.model}:generateContent`;
  // NOTE: key header only. Adding `Authorization: Bearer <api-key>` makes
  // Google validate it as OAuth2 and reject an otherwise valid key (401).
  const headers = { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey };
  if (status.provider === 'opencode') headers['Authorization'] = `Bearer ${apiKey}`;
  const res = await fetchWithRetry(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: system }] },
      contents: [{ role: 'user', parts: [{ text: user }] }],
      generationConfig: {
        responseMimeType: 'application/json',
        maxOutputTokens: maxTokens,
        ...(temperature !== undefined ? { temperature } : {})
      }
    })
  }, Number(process.env.AI_TIMEOUT_MS) || 60000);
  if (!res.ok) {
    throw new Error(`AI provider rejected the request (${res.status}): ${await readError(res)}`);
  }
  const data = await res.json();
  const parts = data?.candidates?.[0]?.content?.parts || [];
  const content = parts.map(p => (typeof p.text === 'string' ? p.text : '')).join('');
  if (!content) throw new Error('AI provider returned no content.');
  return extractJson(content);
}

/** Pull the assistant's text out of an OpenAI Responses API payload. */
function responsesText(data) {
  if (typeof data?.output_text === 'string' && data.output_text) return data.output_text;
  const chunks = [];
  for (const item of data?.output || []) {
    if (item?.type === 'message') {
      for (const part of item.content || []) {
        if ((part?.type === 'output_text' || part?.type === 'text') && typeof part.text === 'string') {
          chunks.push(part.text);
        }
      }
    }
  }
  return chunks.join('');
}

async function callResponses({ status, apiKey, system, user, maxTokens, temperature }) {
  const url = `${status.baseUrl.replace(/\/$/, '')}/responses`;
  const body = {
    model: status.model,
    input: [
      { role: 'system', content: system },
      { role: 'user', content: user }
    ],
    max_output_tokens: maxTokens,
    text: { format: { type: 'json_object' } }
  };
  if (temperature !== undefined) body.temperature = temperature;
  const res = await fetchWithRetry(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify(body)
  }, Number(process.env.AI_TIMEOUT_MS) || 60000);
  if (!res.ok) {
    throw new Error(`AI provider rejected the request (${res.status}): ${await readError(res)}`);
  }
  const data = await res.json();
  const content = responsesText(data);
  if (!content) throw new Error('AI provider returned no content.');
  return extractJson(content);
}

async function callChatCompletions({ status, apiKey, system, user, maxTokens, temperature }) {
  const url = `${status.baseUrl.replace(/\/$/, '')}/chat/completions`;
  const body = {
    model: status.model,
    max_tokens: maxTokens,
    response_format: { type: 'json_object' },
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: user }
    ]
  };
  if (temperature !== undefined) body.temperature = temperature;
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${apiKey}`
  };
  // OpenRouter attribution (optional per docs; identifies usage on dashboards).
  if (status.provider === 'openrouter') {
    headers['HTTP-Referer'] = process.env.AI_REFERER || 'http://localhost:3000';
    headers['X-Title'] = process.env.AI_TITLE || 'BugShield';
  }
  const res = await fetchWithRetry(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body)
  }, Number(process.env.AI_TIMEOUT_MS) || 60000);
  if (!res.ok) {
    throw new Error(`AI provider rejected the request (${res.status}): ${await readError(res)}`);
  }
  const data = await res.json();
  const content = data?.choices?.[0]?.message?.content;
  if (!content) throw new Error('AI provider returned no content.');
  return extractJson(content);
}

/**
 * Call the model and parse a JSON object from its reply.
 * Throws on network, auth, or parse failure — callers fall back honestly.
 */
export async function chatJson({ system, user, maxTokens = 2000, temperature }) {
  const status = getAiStatus();
  if (!status.configured) throw new Error('AI provider not configured (AI_API_KEY unset).');
  const apiKey = getApiKey();
  const params = {
    status, apiKey, system, user, maxTokens,
    temperature: temperature ?? (process.env.AI_TEMPERATURE !== undefined ? Number(process.env.AI_TEMPERATURE) : 0.2)
  };
  if (isGemini(status)) return callGemini(params);
  if (isResponsesEndpoint(status)) return callResponses(params);
  return callChatCompletions(params);
}

/** Assessment prompt: map any user report onto a real file. */
export async function aiAssess({ issue, candidates }) {
  const filesBlock = candidates
    .map(c => `--- ${c.rel} (first ${c.snippet.length} chars) ---\n${c.snippet}`)
    .join('\n\n')
    .slice(0, 24000);
  return chatJson({
    system: 'You are BugShield, a precise code reviewer. Given a user bug report and file snippets, decide whether a genuine defect exists in the shown code. Reply with JSON only: {"isValidBug": boolean, "targetFile": string (exact rel path from the list, or ""), "line": number, "bugType": string (SHORT_SNAKE like COSMETIC_TEXT or CSS_LAYOUT), "rootCause": string (one sentence, quotes the faulty code), "confidence": number 0-1}. Never invent files. If the report does not match the shown code, set isValidBug false.',
    user: `REPORT title: ${issue.title}\ndescription: ${issue.description || ''}\npage: ${issue.pageUrl || issue.page_url || ''}\nstack: ${(issue.stackTrace || issue.stack_trace || '').slice(0, 2000)}\n\nFILES:\n${filesBlock}`,
    // Reasoning models spend tokens thinking; keep headroom so content survives.
    maxTokens: 2000
  });
}

/** Patch prompt: return minimal search/replace edits, not the whole file. */
export async function aiPatch({ issue, targetFileRel, fileContent, rootCause }) {
  const content = await chatJson({
    system: 'You are BugShield, a careful patch generator. Fix the confirmed defect with the smallest possible change. Reply with JSON only: {"edits": [{"find": string (exact snippet copied verbatim from the original file, 1-6 lines, enough to be unique), "replace": string (fixed snippet)}], "description": string (one sentence, what changed and where)}. Rules: copy "find" character-for-character from the original (whitespace included); keep each edit minimal; never reformat unrelated code; at most 5 edits.',
    user: `REPORT: ${issue.title} — ${issue.description || ''}\nFILE: ${targetFileRel}\nROOT CAUSE: ${rootCause}\n\nORIGINAL FILE:\n${String(fileContent).slice(0, 30000)}`,
    maxTokens: 2000
  });
  if (!content || !Array.isArray(content.edits) || !content.edits.length) {
    throw new Error('AI patch reply had no edits.');
  }
  return content;
}

/** Apply search/replace edits exactly; throws when any edit is not unique. */
export function applyAiEdits(fileContent, edits) {
  let updated = fileContent;
  const list = Array.isArray(edits) ? edits.slice(0, 5) : [];
  if (!list.length) throw new Error('No edits to apply.');
  for (const e of list) {
    const find = String(e?.find || '');
    const replace = String(e?.replace ?? '');
    if (!find || find === replace) throw new Error('AI returned an empty or no-op edit.');
    const occurrences = updated.split(find).length - 1;
    if (occurrences !== 1) throw new Error(`AI edit target is not unique (found ${occurrences}x); refusing to guess.`);
    updated = updated.replace(find, replace);
  }
  if (updated === fileContent) throw new Error('AI edits produced no change.');
  return updated;
}
