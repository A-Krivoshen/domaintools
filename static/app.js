// static/app.js
(function () {
  // Копирование по кнопкам: <button data-copy="#selector">...</button>
  document.querySelectorAll('[data-copy]').forEach(el => {
    el.addEventListener('click', async () => {
      const target = el.getAttribute('data-copy');
      const txt = (document.querySelector(target)?.textContent || '').trim();
      try {
        await navigator.clipboard.writeText(txt);
        const prev = el.textContent;
        el.textContent = 'Скопировано!';
        setTimeout(() => (el.textContent = prev || 'Копировать'), 1200);
      } catch (_) {}
    });
  });

  // Спиннеры на формах (если форма помечена data-loading)
  document.querySelectorAll('form[data-loading]').forEach(form => {
    form.addEventListener('submit', () => {
      const btn = form.querySelector('button[type=submit]');
      if (btn) {
        btn.disabled = true;
        btn.dataset.prev = btn.innerHTML;
        btn.innerHTML = '⌛ Выполняю...';
      }
    });
  });
})();
