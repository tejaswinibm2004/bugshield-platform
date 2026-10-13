/**
 * Risk Scoring Model — declarative and auditable.
 *
 * Every weight below is declared once, in one place, with the reason it exists.
 * The UI and the benchmark both read this object, so the published numbers and the
 * running system can never drift apart. Scores are additive; the final score is
 * clamped to [RISK_SCORE_MIN, RISK_SCORE_MAX].
 */

// ---------------------------------------------------------------------------
// 1. Base score: every unclassified issue starts here so that a score is always
//    produced, and 0 is never accidentally achievable for an unreviewed issue.
// ---------------------------------------------------------------------------
export const RISK_BASE_SCORE = 25;

// ---------------------------------------------------------------------------
// 2. Path exposure. A defect in a business-critical file has a larger blast
//    radius than the same defect in an isolated feature file.
//    Weight rises with the number of distinct critical markers matched, then is
//    capped so a path containing many keywords cannot dominate the total.
// ---------------------------------------------------------------------------
export const PATH_CRITICAL_MARKERS = [
  'payment', 'billing', 'checkout', 'order', 'invoice', 'pricing', 'price',
  'auth', 'login', 'session', 'token', 'password', 'crypto', 'security',
  'permission', 'admin', 'database', 'db', 'schema', 'migration'
];
export const PATH_WEIGHT_FIRST_HIT = 15;   // first critical marker
export const PATH_WEIGHT_PER_EXTRA_HIT = 8; // each additional distinct marker
export const PATH_WEIGHT_CAP = 35;          // upper bound for this factor

// ---------------------------------------------------------------------------
// 3. Consequence of the defect class. This is the dominant technical factor:
//    a silent NaN corrupts data, an un-awaited write loses data silently, a
//    null dereference throws. Values are additive on top of the path factor.
// ---------------------------------------------------------------------------
export const DEFECT_CLASS_WEIGHTS = {
  DIV_ZERO: 20,                // produces NaN/Infinity that silently propagate
  UNDEFINED_DYNAMIC_KEY: 20,   // produces NaN via undefined -> arithmetic
  NULL_DEREF: 18,              // throws a runtime TypeError
  MISSING_AWAIT: 12,           // swallowed async failure -> inconsistent state
  AI_GENERAL: 15               // universal AI-confirmed defect of any other class
};

// ---------------------------------------------------------------------------
// 4. Monetary exposure. If the code path or the report concerns money, an
//    incorrect result has financial rather than cosmetic impact.
// ---------------------------------------------------------------------------
export const MONEY_TOKENS = [
  'payment', 'money', 'price', 'cost', 'total', 'amount', 'currency',
  'revenue', 'charge', 'discount', 'fee', 'refund', 'balance', 'tax'
];
export const MONEY_WEIGHT = 20;

// ---------------------------------------------------------------------------
// 5. Blast radius. Shared utility modules are imported across the application,
//    so a regression there disables many features at once.
// ---------------------------------------------------------------------------
export const SHARED_MODULE_PATTERN = /\/(util|utils|helper|helpers|common|shared|lib|core)\b/;
export const SHARED_MODULE_WEIGHT = 12;

// ---------------------------------------------------------------------------
// 6. Evidence confidence. The detector reports a confidence derived from how
//    specific the static signal was (e.g. a key provably outside an object's
//    keys scores higher than a suspected pattern). Scaled to [0,10].
// ---------------------------------------------------------------------------
export const CONFIDENCE_WEIGHT = 10;

// ---------------------------------------------------------------------------
// Thresholds. A score at or above HIGH_THRESHOLD cannot be auto-deployed and is
// escalated to a human. Below LOW_THRESHOLD it is low risk. The band in between
// is reported as MEDIUM for reporting purposes but does not block automation.
// ---------------------------------------------------------------------------
export const HIGH_THRESHOLD = 70;
export const LOW_THRESHOLD = 40;
export const RISK_SCORE_MIN = 5;
export const RISK_SCORE_MAX = 100;

/** Readable description of the model, surfaced in the dashboard. */
export const RISK_MODEL_SUMMARY = {
  base: RISK_BASE_SCORE,
  factors: [
    { factor: 'Critical path exposure', weight: `${PATH_WEIGHT_FIRST_HIT} + ${PATH_WEIGHT_PER_EXTRA_HIT}/extra marker (cap ${PATH_WEIGHT_CAP})`, rationale: 'Business-critical modules have a larger blast radius.' },
    { factor: 'Defect class', weight: '12-20', rationale: 'Silent NaN and lost writes cause data corruption; null dereference causes outages.' },
    { factor: 'Monetary exposure', weight: MONEY_WEIGHT, rationale: 'Incorrect monetary output has financial impact, not cosmetic impact.' },
    { factor: 'Shared module', weight: SHARED_MODULE_WEIGHT, rationale: 'Utility/helper modules are imported application-wide.' },
    { factor: 'Detection confidence', weight: `0-${CONFIDENCE_WEIGHT}`, rationale: 'Rewards specific static evidence over suspected patterns.' }
  ],
  thresholds: { high: HIGH_THRESHOLD, low: LOW_THRESHOLD, note: 'Score >= high threshold requires human approval before deployment.' }
};