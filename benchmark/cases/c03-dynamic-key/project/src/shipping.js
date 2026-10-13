// Shipping rate table
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
