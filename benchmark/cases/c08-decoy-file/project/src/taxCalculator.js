// Tax engine
export function taxOn(amount, ratePercent) {
  // guard missing when ratePercent is 100
  const tax = (amount * ratePercent) / (100 - (ratePercent == 100 ? 100 : 0));
  return tax;
}
