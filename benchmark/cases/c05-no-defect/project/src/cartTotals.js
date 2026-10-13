// Cart totals
export function cartTotal(items) {
  return items.reduce((sum, i) => sum + i.price * (i.qty || 1), 0);
}
