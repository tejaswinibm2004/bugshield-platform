// Discount service (already hardened)
export function applyDiscount(subtotal, percent) {
  if (!percent || percent <= 0) return subtotal;
  const safePercent = Math.min(Math.max(percent, 0), 100);
  const discountAmount = (subtotal * safePercent) / 100;
  return Math.max(0, subtotal - discountAmount);
}
