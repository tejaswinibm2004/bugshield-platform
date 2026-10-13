/**
 * Builds the labeled benchmark corpus under benchmark/cases/<case-id>/.
 * Each case is a real (small) project containing either a genuine defect or
 * deliberately clean/already-fixed code, plus case.json declaring ground truth.
 * Run: node benchmark/seed-corpus.mjs
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const CASES = path.join(ROOT, 'benchmark', 'cases');

const cases = [
  {
    id: 'c01-div-zero',
    note: 'Guaranteed division by zero on a 100% discount.',
    files: {
      'src/pricing.js': `// Pricing engine
export function priceWithDiscount(subtotal, discountPercent) {
  // denominator becomes 0 when discountPercent === 100
  const amount = (subtotal * discountPercent) / (100 - (discountPercent == 100 ? 100 : 0));
  return subtotal - amount;
}
`
    },
    report: { title: 'Checkout total wrong with full discount', description: 'checkout total calculation error when a 100 percent discount code is applied', page_url: '/checkout' },
    expect: { file: 'src/pricing.js', type: 'DIV_ZERO', validBug: true, patchable: true }
  },
  {
    id: 'c02-missing-await',
    note: 'Async persistence call is not awaited and has no error handling.',
    files: {
      'src/orderStore.js': `// Order persistence layer
let orders = [];

async function saveOrderToDatabase(order) {
  await new Promise(r => setTimeout(r, 10));
  orders.push(order);
  return true;
}

export async function submitOrder(order) {
  // persistence call is fire-and-forget: a rejection is swallowed
  saveOrderToDatabase(order);
  return { ok: true };
}
`
    },
    report: { title: 'Order sometimes not saved after payment', description: 'submitting an order reports success but the record is missing in the database', page_url: '/orders' },
    expect: { file: 'src/orderStore.js', type: 'MISSING_AWAIT', validBug: true, patchable: true }
  },
  {
    id: 'c03-dynamic-key',
    note: 'Object indexed by a key that can hold a value outside the defined keys.',
    files: {
      'src/shipping.js': `// Shipping rate table
const rateTable = {
  economy: 1.1,
  standard: 1.6,
  express: 2.4
};

export function shippingFee(km, serviceName) {
  let tier = 'economy';
  if (km > 5 && km <= 20) tier = 'standard';
  if (km > 20) tier = 'overnight';
  const rate = rateTable[tier];
  return Number((3 + km * rate).toFixed(2));
}
`
    },
    report: { title: 'Shipping fee returns NaN for long distances', description: 'the delivery shipping fee calculation becomes NaN for distances over 20 km', page_url: '/shipping' },
    expect: { file: 'src/shipping.js', type: 'UNDEFINED_DYNAMIC_KEY', validBug: true, patchable: true }
  },
  {
    id: 'c04-null-deref',
    note: 'Variable initialised to null then dereferenced (detected, not auto-fixable).',
    files: {
      'src/profile.js': `// Profile loader
export function loadProfile(session) {
  let user = null;
  if (session && session.token) {
    user = session.user;
  }
  return user.name;
}
`
    },
    report: { title: 'User profile page crashes for guests', description: 'loading the user profile without signing in throws a runtime error', page_url: '/profile' },
    expect: { file: 'src/profile.js', type: 'NULL_DEREF', validBug: true, patchable: false }
  },
  {
    id: 'c05-no-defect',
    note: 'Report claims a bug but the code is correct — a false-positive probe.',
    files: {
      'src/cartTotals.js': `// Cart totals
export function cartTotal(items) {
  return items.reduce((sum, i) => sum + i.price * (i.qty || 1), 0);
}
`
    },
    report: { title: 'Cart total calculation is broken', description: 'the cart total page shows a wrong total and the calculation is not working', page_url: '/cart' },
    expect: { file: null, type: null, validBug: false, patchable: false }
  },
  {
    id: 'c06-already-fixed',
    note: 'The defect described is already guarded in the current code.',
    files: {
      'src/discountFixed.js': `// Discount service (already hardened)
export function applyDiscount(subtotal, percent) {
  if (!percent || percent <= 0) return subtotal;
  const safePercent = Math.min(Math.max(percent, 0), 100);
  const discountAmount = (subtotal * safePercent) / 100;
  return Math.max(0, subtotal - discountAmount);
}
`
    },
    report: { title: 'Discount code missing discount calculation', description: 'the discount calculation error returns NaN when a coupon is applied', page_url: '/checkout' },
    expect: { file: null, type: null, validBug: false, patchable: false }
  },
  {
    id: 'c07-non-technical',
    note: 'Non-defect report with no code signal at all.',
    files: {
      'src/about.js': `export const about = { name: 'Acme', founded: 2019 };
`
    },
    report: { title: 'Landing page hero looks outdated', description: 'a design remark about colours and spacing, no malfunction was observed', page_url: '/' },
    expect: { file: null, type: null, validBug: false, patchable: false }
  },
  {
    id: 'c08-decoy-file',
    note: 'Keywords match a decoy file that is correct; the real defect is elsewhere.',
    files: {
      'src/checkoutPage.js': `// Checkout page helpers — mentioned by the user, but correct
export function formatCheckoutTotal(total) {
  return '$' + Number(total || 0).toFixed(2);
}
export function checkoutLabel() {
  return 'Checkout';
}
`,
      'src/taxCalculator.js': `// Tax engine
export function taxOn(amount, ratePercent) {
  // guard missing when ratePercent is 100
  const tax = (amount * ratePercent) / (100 - (ratePercent == 100 ? 100 : 0));
  return tax;
}
`
    },
    report: { title: 'Checkout total is wrong after tax is applied', description: 'the checkout total calculation is not working and shows an incorrect tax amount', page_url: '/checkout' },
    expect: { file: 'src/taxCalculator.js', type: 'DIV_ZERO', validBug: true, patchable: true }
  }
];

fs.rmSync(CASES, { recursive: true, force: true });
fs.mkdirSync(CASES, { recursive: true });

for (const c of cases) {
  const dir = path.join(CASES, c.id);
  for (const [rel, content] of Object.entries(c.files)) {
    const f = path.join(dir, 'project', rel);
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, content);
  }
  fs.writeFileSync(path.join(dir, 'case.json'), JSON.stringify({
    id: c.id, note: c.note, report: c.report, expect: c.expect
  }, null, 2));
  console.log(`seeded ${c.id} (${Object.keys(c.files).length} file(s))`);
}
console.log(`\n${cases.length} cases written to ${CASES}`);