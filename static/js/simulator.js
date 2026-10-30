document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('simForm');
  if (!form) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form).entries());
    ['new_browser', 'unfamiliar_location', 'failed_logins', 'unusual_access_time', 'rapid_requests'].forEach(k => {
      data[k] = form.elements[k].checked;
    });
    const panel = document.getElementById('simResult');
    panel.innerHTML = '<p class="muted">Evaluating scenario…</p>';
    try {
      const response = await fetch('/api/simulate', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not evaluate scenario');
      const signals = Object.entries(result.signals || {}).map(([key, value]) =>
        `<div class="signal-row"><span>${key.replaceAll('_',' ')}</span><b class="${value ? 'text-danger' : 'text-success'}">${value ? 'Triggered' : 'Clear'}</b></div>`
      ).join('');
      panel.innerHTML = `<div class="eyebrow">ADMIN SECURITY OUTPUT</div><h3>${result.score}/100 · ${result.tier} risk</h3><p><strong>${result.decision.replaceAll('_',' ')}</strong> — ${result.reason}</p><hr>${signals}`;
    } catch (error) {
      panel.innerHTML = `<p class="text-danger">${error.message}</p>`;
    }
  });
});
