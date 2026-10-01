(() => {
  'use strict';

  const checkoutForm = document.getElementById('checkout-form');
  const checkoutStatus = document.getElementById('checkout-status');
  const subscribeBtn = document.getElementById('subscribe');
  const keyCard = document.getElementById('key-card');
  const keyValue = document.getElementById('key-value');
  const keyCopy = document.getElementById('key-copy');
  const keyPending = document.getElementById('key-pending');
  const keyError = document.getElementById('key-error');

  checkoutForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    subscribeBtn.disabled = true;
    checkoutStatus.textContent = 'Starting checkout…';
    try {
      const email = document.getElementById('email').value.trim();
      const res = await fetch('/api/checkout', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.url) throw new Error(data.error || `Checkout failed (${res.status}).`);
      window.location.href = data.url;
    } catch (err) {
      checkoutStatus.textContent = '';
      subscribeBtn.disabled = false;
      keyError.hidden = false;
      keyError.textContent = err.message || 'Something went wrong starting checkout.';
    }
  });

  async function tryClaimKey(sessionId, attemptsLeft) {
    try {
      const res = await fetch(`/api/session-key?session_id=${encodeURIComponent(sessionId)}`);
      if (res.status === 404 && attemptsLeft > 0) {
        keyPending.hidden = false;
        setTimeout(() => tryClaimKey(sessionId, attemptsLeft - 1), 2500);
        return;
      }
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.key) throw new Error(data.error || 'Could not retrieve your key.');
      keyPending.hidden = true;
      keyCard.hidden = false;
      keyValue.textContent = data.key;
      keyCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
    } catch (err) {
      keyPending.hidden = true;
      keyError.hidden = false;
      keyError.textContent = err.message || 'Could not retrieve your key.';
    }
  }

  keyCopy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(keyValue.textContent);
      keyCopy.textContent = 'Copied';
      setTimeout(() => { keyCopy.textContent = 'Copy'; }, 1500);
    } catch {
      /* clipboard access denied; the key is still selectable text */
    }
  });

  const sessionId = new URLSearchParams(window.location.search).get('session_id');
  if (sessionId) tryClaimKey(sessionId, 12);
})();
