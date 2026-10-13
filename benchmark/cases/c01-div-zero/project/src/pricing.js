// Pricing engine
export function priceWithDiscount(subtotal, discountPercent) {
  // denominator becomes 0 when discountPercent === 100
  const amount = (subtotal * discountPercent) / (100 - (discountPercent == 100 ? 100 : 0));
  return subtotal - amount;
}
