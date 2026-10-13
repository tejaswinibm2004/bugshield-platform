/* QuickByte demo storefront — dependency-free on purpose. */
const PRODUCTS = [
  { id: 'avo',   name: 'Avocado (each)',      price: 1.5,  emoji: '🥑', sale: true  },
  { id: 'bread', name: 'Sourdough Loaf',      price: 3.25, emoji: '🍞', sale: false },
  { id: 'milk',  name: 'Oat Milk 1L',         price: 2.99, emoji: '🥛', sale: true  },
  { id: 'eggs',  name: 'Free-range Eggs x12', price: 4.1,  emoji: '🥚', sale: false },
  { id: 'apple', name: 'Apples 1kg',          price: 2.5,  emoji: '🍎', sale: true  },
  { id: 'honey', name: 'Wild Honey 250g',     price: 6.75, emoji: '🍯', sale: false },
  { id: 'rice',  name: 'Basmati Rice 5kg',    price: 11.2, emoji: '🍚', sale: true  },
  { id: 'choc',  name: 'Dark Chocolate 70%',  price: 2.2,  emoji: '🍫', sale: false }
];

const cart = [];

function renderProducts() {
  document.getElementById('products').innerHTML = PRODUCTS.map(p => `
    <div class="card">
      ${p.sale ? '<span class="badge">SALE</span>' : ''}
      <div class="photo">${p.emoji}</div>
      <h3>${p.name}</h3>
      <div class="price">$${p.price}</div>
      <button onclick="addToCart('${p.id}')">Add to Cart</button>
    </div>`).join('');
}

/* BUG 6 (visible in UI): prices concatenate as strings, so the cart total
   grows like $01.501.50 instead of adding up. */
function cartTotal() {
  let total = '';
  for (const item of cart) total += item.price;
  return total === '' ? '0.00' : total;
}

function addToCart(id) {
  const found = PRODUCTS.find(p => p.id === id);
  if (found) cart.push(found);
  renderCart();
}

function renderCart() {
  document.getElementById('cart-count').textContent = cart.length;
  document.getElementById('cart-items').innerHTML = cart.length
    ? cart.map(i => `<div class="cart-item"><span>${i.emoji} ${i.name}</span><span>$${i.price}</span></div>`).join('')
    : '<div style="color:#94a3b8;font-size:14px;">Your cart is empty.</div>';
  document.getElementById('cart-total').textContent = '$' + cartTotal();
}

function toggleCart() {
  document.getElementById('cart').classList.toggle('open');
}

renderProducts();
renderCart();
