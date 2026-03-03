// static/app.js
(function () {
  // ===== Copy by selector: <button data-copy="#selector">...</button>
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

  // ===== Form spinner (if form has data-loading)
  document.querySelectorAll('form[data-loading]').forEach(form => {
    form.addEventListener('submit', () => {
      const btn = form.querySelector('button[type=submit], input[type=submit]');
      if (btn && !btn.disabled) {
        btn.disabled = true;
        btn.dataset.prev = btn.innerHTML;
        btn.innerHTML = '⌛ Выполняю...';
      }
    });
  });

  // ===== Theme toggle (persist in localStorage)
  const root = document.documentElement;
  function updateThemeToggleIcon() {
    const btn = document.querySelector('[data-theme-toggle]');
    if (!btn) return;
    const isDark = getTheme() === 'dark';
    const icon = isDark ? 'fa-sun' : 'fa-moon';
    btn.innerHTML = `<i class="fa-solid ${icon}" aria-hidden="true"></i>`;
    btn.setAttribute('aria-label', isDark ? 'Включить светлую тему' : 'Включить тёмную тему');
    btn.setAttribute('title', isDark ? 'Включить светлую тему' : 'Включить тёмную тему');
  }

  function setTheme(mode) {
    root.setAttribute('data-bs-theme', mode);
    try { localStorage.setItem('theme', mode); } catch (e) {}
    updateThemeToggleIcon();
  }
  function getTheme() {
    return root.getAttribute('data-bs-theme') === 'dark' ? 'dark' : 'light';
  }
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-theme-toggle]');
    if (!t) return;
    e.preventDefault();
    setTheme(getTheme() === 'dark' ? 'light' : 'dark');
    closeNav(); // свернуть бургер после нажатия на кнопку темы
  });

  updateThemeToggleIcon();

  // ===== Collapse helpers: auto-close menu after click
  function closeNav() {
    const nav = document.getElementById('mainNav');
    if (!nav) return;
    if (nav.classList.contains('show')) {
      if (window.bootstrap?.Collapse) {
        new bootstrap.Collapse(nav, { toggle: false }).hide();
      } else {
        // Fallback: просто убираем класс
        nav.classList.remove('show');
      }
    }
  }

  document.addEventListener('click', (e) => {
    const link = e.target.closest('.navbar .nav-link');
    if (link) closeNav();
  });
})();
