// Order persistence layer
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
