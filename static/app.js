// static/app.js
(function () {
  const body = document.body;
  const i18n = {
    copyDone: body?.dataset.i18nCopyDone || 'Copied!',
    copyDefault: body?.dataset.i18nCopyDefault || 'Copy',
    loading: body?.dataset.i18nLoading || '⌛ Working...',
    themeLight: body?.dataset.i18nThemeLight || 'Switch to light theme',
    themeDark: body?.dataset.i18nThemeDark || 'Switch to dark theme',
    themeAutoTip: body?.dataset.i18nThemeAutoTip || 'Auto mode: theme follows time of day (RU — Moscow time, EN — local time).',
  };

  // ===== Copy by selector: <button data-copy="#selector">...</button>
  document.querySelectorAll('[data-copy]').forEach(el => {
    el.addEventListener('click', async () => {
      const target = el.getAttribute('data-copy');
      const txt = (document.querySelector(target)?.textContent || '').trim();
      try {
        await navigator.clipboard.writeText(txt);
        const prev = el.textContent;
        el.textContent = i18n.copyDone;
        setTimeout(() => (el.textContent = prev || i18n.copyDefault), 1200);
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
        btn.innerHTML = i18n.loading;
      }
    });
  });

  // ===== Domains search progress =====
  document.querySelectorAll('form[data-domain-progress]').forEach(form => {
    form.addEventListener('submit', () => {
      if (form.dataset.progressStarted === '1') return;
      const wrap = form.querySelector('[data-domain-progress-wrap]');
      const bar = form.querySelector('[data-domain-progress-bar]');
      const percent = form.querySelector('[data-domain-progress-percent]');
      if (!wrap || !bar || !percent) return;

      form.dataset.progressStarted = '1';
      wrap.classList.remove('d-none');

      let value = 12;
      const step = () => {
        value = Math.min(90, value + (value < 50 ? 8 : (value < 75 ? 4 : 2)));
        bar.style.width = `${value}%`;
        bar.parentElement?.setAttribute('aria-valuenow', String(value));
        percent.textContent = `${value}%`;
        if (value >= 90) clearInterval(timer);
      };
      const timer = setInterval(step, 220);
      step();
    });
  });

  // ===== Theme toggle (persist in localStorage)
  const root = document.documentElement;
  function autoThemeByTime() {
    const lang = (document.documentElement.getAttribute('lang') || '').toLowerCase();
    let hour;
    try {
      if (lang.startsWith('ru')) {
        const parts = new Intl.DateTimeFormat('en-GB', {
          timeZone: 'Europe/Moscow',
          hour: '2-digit',
          hour12: false,
        }).formatToParts(new Date());
        const hh = parts.find((p) => p.type === 'hour')?.value;
        hour = Number(hh);
      } else {
        hour = new Date().getHours();
      }
    } catch (e) {
      hour = new Date().getHours();
    }
    return (hour >= 20 || hour < 7) ? 'dark' : 'light';
  }

  function getThemeMode() {
    const mode = root.getAttribute('data-theme-mode');
    if (mode === 'dark' || mode === 'light' || mode === 'auto') return mode;
    try {
      const savedMode = localStorage.getItem('theme_mode');
      if (savedMode === 'dark' || savedMode === 'light' || savedMode === 'auto') return savedMode;
      const legacy = localStorage.getItem('theme');
      if (legacy === 'dark' || legacy === 'light') return legacy;
    } catch (e) {}
    return 'auto';
  }

  function getEffectiveTheme(mode = getThemeMode()) {
    return mode === 'auto' ? autoThemeByTime() : mode;
  }

  function updateThemeToggleIcon() {
    const btn = document.querySelector('[data-theme-toggle]');
    if (!btn) return;
    const mode = getThemeMode();
    const isDark = getEffectiveTheme(mode) === 'dark';
    const icon = isDark ? 'fa-sun' : 'fa-moon';
    btn.innerHTML = `<i class="fa-solid ${icon}" aria-hidden="true"></i>`;
    const title = isDark ? i18n.themeLight : i18n.themeDark;
    btn.setAttribute('aria-label', title);
    btn.setAttribute('title', title);
  }

  function showAutoThemeHintOnce() {
    const btn = document.querySelector('[data-theme-toggle]');
    if (!btn) return;
    if (getThemeMode() !== 'auto') return;
    try {
      if (localStorage.getItem('theme_auto_hint_seen') === '1') return;
      localStorage.setItem('theme_auto_hint_seen', '1');
    } catch (e) {}

    const prevTitle = btn.getAttribute('title') || '';
    btn.setAttribute('title', i18n.themeAutoTip);
    btn.setAttribute('aria-label', i18n.themeAutoTip);

    if (window.bootstrap?.Tooltip) {
      const tip = new bootstrap.Tooltip(btn, {
        title: i18n.themeAutoTip,
        trigger: 'manual',
        placement: 'bottom',
      });
      tip.show();
      setTimeout(() => {
        tip.dispose();
        btn.setAttribute('title', prevTitle);
        updateThemeToggleIcon();
      }, 4200);
    } else {
      setTimeout(() => {
        btn.setAttribute('title', prevTitle);
        updateThemeToggleIcon();
      }, 4200);
    }
  }

  function setThemeMode(mode, persist = true) {
    const next = (mode === 'dark' || mode === 'light' || mode === 'auto') ? mode : 'auto';
    const effective = getEffectiveTheme(next);
    root.setAttribute('data-theme-mode', next);
    root.setAttribute('data-bs-theme', effective);
    if (persist) {
      try {
        localStorage.setItem('theme_mode', next);
        if (next === 'dark' || next === 'light') localStorage.setItem('theme', next);
        else localStorage.removeItem('theme');
      } catch (e) {}
    }
    updateThemeToggleIcon();
  }

  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-theme-toggle]');
    if (!t) return;
    e.preventDefault();
    const mode = getThemeMode();
    const effective = getEffectiveTheme(mode);
    const nextMode = effective === 'dark' ? 'light' : 'dark';
    setThemeMode(nextMode, true);
    closeNav();
  });

  setThemeMode(getThemeMode(), false);
  setInterval(() => {
    if (getThemeMode() === 'auto') setThemeMode('auto', false);
  }, 60 * 1000);

  updateThemeToggleIcon();
  showAutoThemeHintOnce();

  // ===== Domains zones controls =====
  document.querySelectorAll('form[data-zones-controls]').forEach(form => {
    const zoneInputs = () => Array.from(form.querySelectorAll('input[name="zones"]'));
    const list = form.querySelector('[data-zones-list]');
    const defaults = new Set((list?.dataset.defaultZones || '').split(',').map(s => s.trim()).filter(Boolean));
    const groupRu = new Set((list?.dataset.groupRu || '').split(',').map(s => s.trim()).filter(Boolean));
    const groupGlobal = new Set((list?.dataset.groupGlobal || '').split(',').map(s => s.trim()).filter(Boolean));
    const groupNew = new Set((list?.dataset.groupNew || '').split(',').map(s => s.trim()).filter(Boolean));
    const maxZones = Number(list?.dataset.maxZones || 0) || 0;
    const counter = form.querySelector('[data-zone-count]');

    function updateZonesCounter() {
      if (!counter) return;
      const selected = zoneInputs().filter(i => i.checked && !i.disabled).length;
      const limit = maxZones > 0 ? maxZones : 0;
      const lang = (document.documentElement.getAttribute('lang') || '').toLowerCase();
      const isEn = lang.startsWith('en');
      const selectedLabel = (isEn ? counter.dataset.selectedLabelEn : counter.dataset.selectedLabelRu) || 'Selected';
      const limitLabel = (isEn ? counter.dataset.limitLabelEn : counter.dataset.limitLabelRu) || 'Recommended limit';
      const overLimitText = (isEn ? counter.dataset.overLimitEn : counter.dataset.overLimitRu) || 'Too many zones selected — search may be slower.';
      counter.textContent = `${selectedLabel}: ${selected}${limit ? ` / ${limitLabel}: ${limit}` : ''}`;
      if (limit && selected > limit) {
        counter.classList.remove('text-muted');
        counter.classList.add('text-danger');
        counter.setAttribute('title', overLimitText);
      } else {
        counter.classList.remove('text-danger');
        counter.classList.add('text-muted');
        counter.removeAttribute('title');
      }
    }

    form.querySelectorAll('[data-zone-action]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const action = btn.getAttribute('data-zone-action');
        const inputs = zoneInputs();
        if (action === 'all') {
          inputs.forEach(i => { if (!i.disabled) i.checked = true; });
        } else if (action === 'none') {
          inputs.forEach(i => { if (!i.disabled) i.checked = false; });
        } else if (action === 'defaults') {
          inputs.forEach(i => { if (!i.disabled) i.checked = defaults.has(i.value); });
        } else if (action === 'ru') {
          inputs.forEach(i => { if (!i.disabled) i.checked = groupRu.has(i.value); });
        } else if (action === 'global') {
          inputs.forEach(i => { if (!i.disabled) i.checked = groupGlobal.has(i.value); });
        } else if (action === 'new' || action === 'newgtld') {
          inputs.forEach(i => { if (!i.disabled) i.checked = groupNew.has(i.value); });
        }
        updateZonesCounter();
      });
    });

    zoneInputs().forEach(input => {
      input.addEventListener('change', updateZonesCounter);
    });
    updateZonesCounter();
  });

  // ===== Domain buy-flow analytics (no PII)
  document.querySelectorAll('[data-buy-track]').forEach((link) => {
    link.addEventListener('click', () => {
      const domain = (link.getAttribute('data-buy-domain') || '').toLowerCase();
      const locale = (link.getAttribute('data-buy-locale') || '').toLowerCase();
      const tld = domain.includes('.') ? domain.split('.').slice(-1)[0] : '';
      if (!tld) return;
      const payload = JSON.stringify({ tld, locale: (locale === 'en' ? 'en' : 'ru') });
      try {
        if (navigator.sendBeacon) {
          navigator.sendBeacon('/track/buy-click', new Blob([payload], { type: 'application/json' }));
        } else {
          fetch('/track/buy-click', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: payload,
            keepalive: true,
          }).catch(() => {});
        }
      } catch (e) {}
    });
  });

  // ===== Security quick-set ports (client-side only; no extra GET requests)
  document.querySelectorAll('[data-security-quick-port]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const form = btn.closest('form.security-form');
      if (!form) return;
      const portsInput = form.querySelector('input[name="ports"]');
      if (!portsInput) return;
      portsInput.value = btn.getAttribute('data-security-quick-port') || '';
      portsInput.focus();
      portsInput.select();
    });
  });

  setThemeMode(getThemeMode(), false);
  setInterval(() => {
    if (getThemeMode() === 'auto') setThemeMode('auto', false);
  }, 60 * 1000);

  updateThemeToggleIcon();
  showAutoThemeHintOnce();

  // ===== Domains zones controls =====
  document.querySelectorAll('form[data-zones-controls]').forEach(form => {
    const zoneInputs = () => Array.from(form.querySelectorAll('input[name="zones"]'));
    const list = form.querySelector('[data-zones-list]');
    const defaults = new Set((list?.dataset.defaultZones || '').split(',').map(s => s.trim()).filter(Boolean));
    const groupRu = new Set((list?.dataset.groupRu || '').split(',').map(s => s.trim()).filter(Boolean));
    const groupGlobal = new Set((list?.dataset.groupGlobal || '').split(',').map(s => s.trim()).filter(Boolean));
    const groupNew = new Set((list?.dataset.groupNew || '').split(',').map(s => s.trim()).filter(Boolean));
    const maxZones = Number(list?.dataset.maxZones || 0) || 0;
    const counter = form.querySelector('[data-zone-count]');

    function updateZonesCounter() {
      if (!counter) return;
      const selected = zoneInputs().filter(i => i.checked && !i.disabled).length;
      const limit = maxZones > 0 ? maxZones : 0;
      const lang = (document.documentElement.getAttribute('lang') || '').toLowerCase();
      const isEn = lang.startsWith('en');
      const selectedLabel = (isEn ? counter.dataset.selectedLabelEn : counter.dataset.selectedLabelRu) || 'Selected';
      const limitLabel = (isEn ? counter.dataset.limitLabelEn : counter.dataset.limitLabelRu) || 'Recommended limit';
      const overLimitText = (isEn ? counter.dataset.overLimitEn : counter.dataset.overLimitRu) || 'Too many zones selected — search may be slower.';
      counter.textContent = `${selectedLabel}: ${selected}${limit ? ` / ${limitLabel}: ${limit}` : ''}`;
      if (limit && selected > limit) {
        counter.classList.remove('text-muted');
        counter.classList.add('text-danger');
        counter.setAttribute('title', overLimitText);
      } else {
        counter.classList.remove('text-danger');
        counter.classList.add('text-muted');
        counter.removeAttribute('title');
      }
    }

    form.querySelectorAll('[data-zone-action]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const action = btn.getAttribute('data-zone-action');
        const inputs = zoneInputs();
        if (action === 'all') {
          inputs.forEach(i => { if (!i.disabled) i.checked = true; });
        } else if (action === 'none') {
          inputs.forEach(i => { if (!i.disabled) i.checked = false; });
        } else if (action === 'defaults') {
          inputs.forEach(i => { if (!i.disabled) i.checked = defaults.has(i.value); });
        } else if (action === 'ru') {
          inputs.forEach(i => { if (!i.disabled) i.checked = groupRu.has(i.value); });
        } else if (action === 'global') {
          inputs.forEach(i => { if (!i.disabled) i.checked = groupGlobal.has(i.value); });
        } else if (action === 'new' || action === 'newgtld') {
          inputs.forEach(i => { if (!i.disabled) i.checked = groupNew.has(i.value); });
        }
        updateZonesCounter();
      });
    });

    zoneInputs().forEach(input => {
      input.addEventListener('change', updateZonesCounter);
    });
    updateZonesCounter();
  });

  // ===== Domain buy-flow analytics (no PII)
  document.querySelectorAll('[data-buy-track]').forEach((link) => {
    link.addEventListener('click', () => {
      const domain = (link.getAttribute('data-buy-domain') || '').toLowerCase();
      const locale = (link.getAttribute('data-buy-locale') || '').toLowerCase();
      const tld = domain.includes('.') ? domain.split('.').slice(-1)[0] : '';
      if (!tld) return;
      const payload = JSON.stringify({ tld, locale: (locale === 'en' ? 'en' : 'ru') });
      try {
        if (navigator.sendBeacon) {
          navigator.sendBeacon('/track/buy-click', new Blob([payload], { type: 'application/json' }));
        } else {
          fetch('/track/buy-click', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: payload,
            keepalive: true,
          }).catch(() => {});
        }
      } catch (e) {}
    });
  });

  // ===== Security quick-set ports (client-side only; no extra GET requests)
  document.querySelectorAll('[data-security-quick-port]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const form = btn.closest('form.security-form');
      if (!form) return;
      const portsInput = form.querySelector('input[name="ports"]');
      if (!portsInput) return;
      portsInput.value = btn.getAttribute('data-security-quick-port') || '';
      portsInput.focus();
      portsInput.select();
    });
  });

  // ===== Domain buy-flow analytics (no PII)
  document.querySelectorAll('[data-buy-track]').forEach((link) => {
    link.addEventListener('click', () => {
      const domain = (link.getAttribute('data-buy-domain') || '').toLowerCase();
      const locale = (link.getAttribute('data-buy-locale') || '').toLowerCase();
      const tld = domain.includes('.') ? domain.split('.').slice(-1)[0] : '';
      if (!tld) return;
      const payload = JSON.stringify({ tld, locale: (locale === 'en' ? 'en' : 'ru') });
      try {
        if (navigator.sendBeacon) {
          navigator.sendBeacon('/track/buy-click', new Blob([payload], { type: 'application/json' }));
        } else {
          fetch('/track/buy-click', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: payload,
            keepalive: true,
          }).catch(() => {});
        }
      } catch (e) {}
    });
  });

  // ===== Security quick-set ports (client-side only; no extra GET requests)
  document.querySelectorAll('[data-security-quick-port]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const form = btn.closest('form.security-form');
      if (!form) return;
      const portsInput = form.querySelector('input[name="ports"]');
      if (!portsInput) return;
      portsInput.value = btn.getAttribute('data-security-quick-port') || '';
      portsInput.focus();
      portsInput.select();
    });
  });

  setThemeMode(getThemeMode(), false);
  setInterval(() => {
    if (getThemeMode() === 'auto') setThemeMode('auto', false);
  }, 60 * 1000);

  updateThemeToggleIcon();
  showAutoThemeHintOnce();

  // ===== Domains zones controls =====
  document.querySelectorAll('form[data-zones-controls]').forEach(form => {
    const zoneInputs = () => Array.from(form.querySelectorAll('input[name="zones"]'));
    const list = form.querySelector('[data-zones-list]');
    const defaults = new Set((list?.dataset.defaultZones || '').split(',').map(s => s.trim()).filter(Boolean));
    const groupRu = new Set((list?.dataset.groupRu || '').split(',').map(s => s.trim()).filter(Boolean));
    const groupGlobal = new Set((list?.dataset.groupGlobal || '').split(',').map(s => s.trim()).filter(Boolean));
    const groupNew = new Set((list?.dataset.groupNew || '').split(',').map(s => s.trim()).filter(Boolean));
    const maxZones = Number(list?.dataset.maxZones || 0) || 0;
    const counter = form.querySelector('[data-zone-count]');

    function updateZonesCounter() {
      if (!counter) return;
      const selected = zoneInputs().filter(i => i.checked && !i.disabled).length;
      const limit = maxZones > 0 ? maxZones : 0;
      const lang = (document.documentElement.getAttribute('lang') || '').toLowerCase();
      const isEn = lang.startsWith('en');
      const selectedLabel = (isEn ? counter.dataset.selectedLabelEn : counter.dataset.selectedLabelRu) || 'Selected';
      const limitLabel = (isEn ? counter.dataset.limitLabelEn : counter.dataset.limitLabelRu) || 'Recommended limit';
      const overLimitText = (isEn ? counter.dataset.overLimitEn : counter.dataset.overLimitRu) || 'Too many zones selected — search may be slower.';
      counter.textContent = `${selectedLabel}: ${selected}${limit ? ` / ${limitLabel}: ${limit}` : ''}`;
      if (limit && selected > limit) {
        counter.classList.remove('text-muted');
        counter.classList.add('text-danger');
        counter.setAttribute('title', overLimitText);
      } else {
        counter.classList.remove('text-danger');
        counter.classList.add('text-muted');
        counter.removeAttribute('title');
      }
    }

    form.querySelectorAll('[data-zone-action]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const action = btn.getAttribute('data-zone-action');
        const inputs = zoneInputs();
        if (action === 'all') {
          inputs.forEach(i => { if (!i.disabled) i.checked = true; });
        } else if (action === 'none') {
          inputs.forEach(i => { if (!i.disabled) i.checked = false; });
        } else if (action === 'defaults') {
          inputs.forEach(i => { if (!i.disabled) i.checked = defaults.has(i.value); });
        } else if (action === 'ru') {
          inputs.forEach(i => { if (!i.disabled) i.checked = groupRu.has(i.value); });
        } else if (action === 'global') {
          inputs.forEach(i => { if (!i.disabled) i.checked = groupGlobal.has(i.value); });
        } else if (action === 'new' || action === 'newgtld') {
          inputs.forEach(i => { if (!i.disabled) i.checked = groupNew.has(i.value); });
        }
        updateZonesCounter();
      });
    });

    const filter = form.querySelector('[data-zone-filter]');
    if (filter) {
      filter.addEventListener('input', () => {
        const q = filter.value.trim().toLowerCase().replace(/^\./, '');
        zoneInputs().forEach(input => {
          const label = input.closest('label');
          if (!label) return;
          const v = (input.value || '').toLowerCase();
          label.style.display = (!q || v.includes(q)) ? '' : 'none';
        });
      });
    }

    zoneInputs().forEach(input => {
      input.addEventListener('change', updateZonesCounter);
    });
    updateZonesCounter();
  });

  // ===== Domain buy-flow analytics (no PII)
  document.querySelectorAll('[data-buy-track]').forEach((link) => {
    link.addEventListener('click', () => {
      const domain = (link.getAttribute('data-buy-domain') || '').toLowerCase();
      const locale = (link.getAttribute('data-buy-locale') || '').toLowerCase();
      const tld = domain.includes('.') ? domain.split('.').slice(-1)[0] : '';
      if (!tld) return;
      const payload = JSON.stringify({ tld, locale: (locale === 'en' ? 'en' : 'ru') });
      try {
        if (navigator.sendBeacon) {
          navigator.sendBeacon('/track/buy-click', new Blob([payload], { type: 'application/json' }));
        } else {
          fetch('/track/buy-click', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: payload,
            keepalive: true,
          }).catch(() => {});
        }
      } catch (e) {}
    });
  });

  // ===== Security quick-set ports (client-side only; no extra GET requests)
  document.querySelectorAll('[data-security-quick-port]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const form = btn.closest('form.security-form');
      if (!form) return;
      const portsInput = form.querySelector('input[name="ports"]');
      if (!portsInput) return;
      portsInput.value = btn.getAttribute('data-security-quick-port') || '';
      portsInput.focus();
      portsInput.select();
    });
  });

  // ===== Security quick-set ports (client-side only; no extra GET requests)
  document.querySelectorAll('[data-security-quick-port]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const form = btn.closest('form.security-form');
      if (!form) return;
      const portsInput = form.querySelector('input[name="ports"]');
      if (!portsInput) return;
      portsInput.value = btn.getAttribute('data-security-quick-port') || '';
      portsInput.focus();
      portsInput.select();
    });
  });

  updateThemeToggleIcon();

  // ===== Domains zones controls =====
  document.querySelectorAll('form[data-zones-controls]').forEach(form => {
    const zoneInputs = () => Array.from(form.querySelectorAll('input[name="zones"]'));
    const list = form.querySelector('[data-zones-list]');
    const defaults = new Set((list?.dataset.defaultZones || '').split(',').map(s => s.trim()).filter(Boolean));

    form.querySelectorAll('[data-zone-action]').forEach(btn => {
      btn.addEventListener('click', () => {
        const action = btn.getAttribute('data-zone-action');
        const inputs = zoneInputs();
        if (action === 'all') {
          inputs.forEach(i => { if (!i.disabled) i.checked = true; });
        } else if (action === 'none') {
          inputs.forEach(i => { if (!i.disabled) i.checked = false; });
        } else if (action === 'defaults') {
          inputs.forEach(i => { if (!i.disabled) i.checked = defaults.has(i.value); });
        }
      });
    });

    const filter = form.querySelector('[data-zone-filter]');
    if (filter) {
      filter.addEventListener('input', () => {
        const q = filter.value.trim().toLowerCase().replace(/^\./, '');
        zoneInputs().forEach(input => {
          const label = input.closest('label');
          if (!label) return;
          const v = (input.value || '').toLowerCase();
          label.style.display = (!q || v.includes(q)) ? '' : 'none';
        });
      });
    }
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
        nav.classList.remove('show');
      }
    }
  }

  document.addEventListener('click', (e) => {
    const link = e.target.closest('.navbar .nav-link');
    if (link) closeNav();
  });
})();
