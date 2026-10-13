// Checkout page helpers — mentioned by the user, but correct
export function formatCheckoutTotal(total) {
  return '$' + Number(total || 0).toFixed(2);
}
export function checkoutLabel() {
  return 'Checkout';
}
