// static/app.js
(function () {
  // theme toggle
  const btn = document.querySelector('[data-theme-toggle]');
  const stored = localStorage.getItem('theme') || 'light';
  document.documentElement.dataset.bsTheme = stored;
  if (btn) btn.addEventListener('click', () => {
    const cur = document.documentElement.dataset.bsTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.bsTheme = cur;
    localStorage.setItem('theme', cur);
  });

  // copy permalink
  document.querySelectorAll('[data-copy]').forEach(el => {
    el.addEventListener('click', async () => {
      const target = el.getAttribute('data-copy');
      const txt = (document.querySelector(target)?.textContent || '').trim();
      try { await navigator.clipboard.writeText(txt); el.textContent = 'Скопировано!'; setTimeout(()=>el.textContent='Копировать',1400);} catch(e){}
    });
  });

  // submit spinners
  document.querySelectorAll('form[data-loading]').forEach(form => {
    form.addEventListener('submit', () => {
      const btn = form.querySelector('button[type=submit]');
      if (btn) { btn.disabled = true; btn.dataset.prev = btn.innerHTML; btn.innerHTML = '⌛ Выполняю...'; }
    });
  });
})();
<script>
(function () {
  const root = document.documentElement;
  function setTheme(mode) {
    root.setAttribute('data-bs-theme', mode);
    try { localStorage.setItem('theme', mode); } catch (e) {}
  }
  document.addEventListener('click', function (e) {
    const t = e.target.closest('[data-theme-toggle]');
    if (!t) return;
    e.preventDefault();
    const cur = root.getAttribute('data-bs-theme') === 'dark' ? 'dark' : 'light';
    setTheme(cur === 'dark' ? 'light' : 'dark');
  });
})();
</script>
