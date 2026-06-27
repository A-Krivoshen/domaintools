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
    const effective = getEffectiveTheme(getThemeMode());
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

    updateZonesCounter();
  });

  function sendAnalyticsBeacon(url, payload) {
    const body = JSON.stringify(payload);
    try {
      if (navigator.sendBeacon) {
        navigator.sendBeacon(url, new Blob([body], { type: 'application/json' }));
      } else {
        fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body,
          keepalive: true,
        }).catch(() => {});
      }
    } catch (e) {}
  }

  document.querySelectorAll('[data-buy-track]').forEach((link) => {
    link.addEventListener('click', () => {
      const domain = (link.getAttribute('data-buy-domain') || '').toLowerCase();
      const locale = (link.getAttribute('data-buy-locale') || '').toLowerCase();
      const tld = domain.includes('.') ? domain.split('.').slice(-1)[0] : '';
      if (!tld) return;
      sendAnalyticsBeacon('/track/buy-click', { tld, locale: (locale === 'en' ? 'en' : 'ru') });
    });
  });

  document.querySelectorAll('[data-ref-track]').forEach((link) => {
    link.addEventListener('click', () => {
      const type = (link.getAttribute('data-ref-type') || '').toLowerCase();
      const id = (link.getAttribute('data-ref-id') || '').toLowerCase();
      const placement = (link.getAttribute('data-ref-placement') || '').toLowerCase();
      const locale = (link.getAttribute('data-ref-locale') || '').toLowerCase();
      if (!type || !id) return;
      sendAnalyticsBeacon('/track/ref-click', {
        type,
        id,
        placement,
        locale: (locale === 'en' ? 'en' : 'ru'),
      });
    });
  });

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

  (function dedupeReportNavLink() {
    const nav = document.getElementById('mainNav');
    if (!nav) return;
    const links = Array.from(nav.querySelectorAll('.nav-link[href]'));
    const reportLinks = links.filter((a) => {
      try {
        return new URL(a.href, window.location.origin).pathname === '/report';
      } catch (e) {
        return false;
      }
    });
    if (reportLinks.length <= 1) return;
    reportLinks.slice(0, -1).forEach((a) => a.closest('.nav-item')?.remove());
  })();

  // ===== Command palette (Ctrl/Cmd+K) =====
  (function initCommandPalette() {
    const root = document.getElementById('commandPalette');
    const input = document.getElementById('commandPaletteInput');
    const list = document.getElementById('commandPaletteList');
    const dataEl = document.getElementById('command-palette-data');
    if (!root || !input || !list || !dataEl) return;

    let items = [];
    try {
      items = JSON.parse(dataEl.textContent || '[]');
    } catch (e) {
      items = [];
    }

    let filtered = items.slice();
    let selectedIndex = 0;
    let lastFocus = null;

    function normalize(value) {
      return String(value || '').toLowerCase().trim();
    }

    function itemHaystack(item) {
      const keywords = Array.isArray(item.keywords) ? item.keywords.join(' ') : '';
      return normalize(`${item.title} ${item.subtitle || ''} ${keywords}`);
    }

    function filterItems(query) {
      const q = normalize(query);
      if (!q) return items.slice();
      const tokens = q.split(/\s+/).filter(Boolean);
      return items.filter((item) => {
        const hay = itemHaystack(item);
        return tokens.every((token) => hay.includes(token));
      });
    }

    function renderList() {
      list.innerHTML = '';
      if (!filtered.length) {
        const empty = document.createElement('li');
        empty.className = 'command-palette__empty';
        empty.textContent = document.documentElement.lang.startsWith('en')
          ? 'No matching tools'
          : 'Ничего не найдено';
        list.appendChild(empty);
        return;
      }

      filtered.forEach((item, index) => {
        const li = document.createElement('li');
        const link = document.createElement('a');
        link.className = 'command-palette__item';
        link.href = item.url;
        link.setAttribute('role', 'option');
        link.setAttribute('aria-selected', index === selectedIndex ? 'true' : 'false');
        if (index === selectedIndex) link.classList.add('is-selected');
        link.dataset.index = String(index);

        const icon = document.createElement('span');
        icon.className = 'command-palette__item-icon';
        icon.innerHTML = `<i class="fa-solid ${item.icon || 'fa-arrow-right'}" aria-hidden="true"></i>`;

        const text = document.createElement('span');
        text.className = 'command-palette__item-text';
        const title = document.createElement('span');
        title.className = 'command-palette__item-title';
        title.textContent = item.title || '';
        const subtitle = document.createElement('span');
        subtitle.className = 'command-palette__item-subtitle';
        subtitle.textContent = item.subtitle || '';
        text.append(title, subtitle);

        link.append(icon, text);
        li.appendChild(link);
        list.appendChild(li);
      });
    }

    function scrollSelectedIntoView() {
      const selected = list.querySelector('.command-palette__item.is-selected');
      if (selected) selected.scrollIntoView({ block: 'nearest' });
    }

    function setSelected(index) {
      if (!filtered.length) {
        selectedIndex = 0;
        renderList();
        return;
      }
      selectedIndex = ((index % filtered.length) + filtered.length) % filtered.length;
      renderList();
      scrollSelectedIntoView();
    }

    function openPalette() {
      if (root.classList.contains('is-open')) return;
      lastFocus = document.activeElement;
      filtered = items.slice();
      selectedIndex = 0;
      input.value = '';
      renderList();
      root.removeAttribute('hidden');
      root.setAttribute('aria-hidden', 'false');
      root.classList.add('is-open');
      document.body.classList.add('command-palette-open');
      closeNav();
      window.setTimeout(() => input.focus(), 0);
    }

    function closePalette() {
      if (!root.classList.contains('is-open')) return;
      root.classList.remove('is-open');
      root.setAttribute('aria-hidden', 'true');
      root.setAttribute('hidden', '');
      document.body.classList.remove('command-palette-open');
      if (lastFocus && typeof lastFocus.focus === 'function') {
        lastFocus.focus();
      }
    }

    function navigateToSelected() {
      const item = filtered[selectedIndex];
      if (!item || !item.url) return;
      window.location.href = item.url;
    }

    document.addEventListener('click', (e) => {
      if (e.target.closest('[data-command-palette-open]')) {
        e.preventDefault();
        openPalette();
      }
      if (e.target.closest('[data-command-palette-close]')) {
        e.preventDefault();
        closePalette();
      }
    });

    document.addEventListener('keydown', (e) => {
      const isMac = /Mac|iPhone|iPad|iPod/.test(navigator.platform || '');
      const modifier = isMac ? e.metaKey : e.ctrlKey;
      if (modifier && (e.key === 'k' || e.key === 'K')) {
        const tag = (document.activeElement?.tagName || '').toLowerCase();
        if (tag === 'input' || tag === 'textarea' || document.activeElement?.isContentEditable) return;
        e.preventDefault();
        if (root.classList.contains('is-open')) closePalette();
        else openPalette();
        return;
      }

      if (!root.classList.contains('is-open')) return;

      if (e.key === 'Escape') {
        e.preventDefault();
        closePalette();
        return;
      }

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelected(selectedIndex + 1);
        return;
      }

      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelected(selectedIndex - 1);
        return;
      }

      if (e.key === 'Enter') {
        const tag = (document.activeElement?.tagName || '').toLowerCase();
        if (tag === 'input' || tag === 'textarea') {
          e.preventDefault();
          navigateToSelected();
        }
      }
    });

    input.addEventListener('input', () => {
      filtered = filterItems(input.value);
      selectedIndex = 0;
      renderList();
    });

    list.addEventListener('mousemove', (e) => {
      const itemEl = e.target.closest('.command-palette__item');
      if (!itemEl) return;
      const idx = Number(itemEl.dataset.index);
      if (!Number.isNaN(idx) && idx !== selectedIndex) {
        selectedIndex = idx;
        renderList();
      }
    });

    list.addEventListener('click', (e) => {
      const itemEl = e.target.closest('.command-palette__item');
      if (!itemEl) return;
      e.preventDefault();
      const idx = Number(itemEl.dataset.index);
      if (!Number.isNaN(idx)) selectedIndex = idx;
      navigateToSelected();
    });
  })();

  document.querySelectorAll('[data-domain-sticky-cta]').forEach((el) => {
    document.body.classList.add('has-domain-sticky-cta');
  });

  (function initScrollToTop() {
    const btn = document.getElementById('scrollToTop');
    if (!btn) return;

    const threshold = 320;
    const label = body?.dataset.i18nScrollTop || 'Back to top';
    btn.setAttribute('aria-label', label);
    btn.setAttribute('title', label);

    let ticking = false;

    function updateVisibility() {
      const y = window.scrollY || document.documentElement.scrollTop || 0;
      const show = y > threshold;
      btn.classList.toggle('is-visible', show);
      btn.hidden = !show;
      ticking = false;
    }

    function onScroll() {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(updateVisibility);
    }

    btn.addEventListener('click', () => {
      const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      window.scrollTo({ top: 0, behavior: reduceMotion ? 'auto' : 'smooth' });
      btn.blur();
    });

    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll, { passive: true });
    updateVisibility();
  })();
})();