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

    const expandBtn = form.querySelector('[data-zones-expand]');
    const zonesList = form.querySelector('[data-zones-list]');
    if (expandBtn && zonesList) {
      const showLabel = expandBtn.dataset.expandLabel || expandBtn.textContent.trim();
      if (!expandBtn.dataset.expandLabel) expandBtn.dataset.expandLabel = showLabel;
      const hideLabel = expandBtn.dataset.collapseLabel || showLabel;
      expandBtn.addEventListener('click', () => {
        const expanded = zonesList.classList.toggle('zones-list--expanded');
        expandBtn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
        expandBtn.textContent = expanded ? hideLabel : showLabel;
      });
    }

    updateZonesCounter();
  });

  document.querySelectorAll('[data-monetization-slot]').forEach((el, index) => {
    if (index > 0) el.classList.add('monetization-slot--hidden');
  });

  function capVisualBanners() {
    const slots = Array.from(document.querySelectorAll('[data-banner-priority]'));
    if (!slots.length) return;
    let best = null;
    let bestPriority = -1;
    slots.forEach((el) => {
      const hasContent = el.textContent && el.textContent.trim().length > 0;
      if (!hasContent) {
        el.classList.add('banner-slot--hidden');
        return;
      }
      const priority = Number(el.getAttribute('data-banner-priority')) || 0;
      if (priority > bestPriority) {
        bestPriority = priority;
        best = el;
      }
    });
    slots.forEach((el) => {
      if (el !== best) el.classList.add('banner-slot--hidden');
    });
  }

  (function initUxModeToggle() {
    const toggle = document.querySelector('[data-ux-mode-toggle]');
    if (!toggle) return;

    function currentMode() {
      return document.documentElement.getAttribute('data-ux-mode') === 'expert' ? 'expert' : 'simple';
    }

    function applyMode(mode) {
      const next = mode === 'expert' ? 'expert' : 'simple';
      document.documentElement.setAttribute('data-ux-mode', next);
      try {
        localStorage.setItem('dt_ux_mode', next);
      } catch (e) {}
      const isRu = (document.documentElement.getAttribute('lang') || '').toLowerCase().startsWith('ru');
      toggle.title = next === 'expert'
        ? (isRu ? 'Простой режим' : (body?.dataset.i18nUxSimple || 'Simple mode'))
        : (isRu ? 'Режим специалиста' : (body?.dataset.i18nUxExpert || 'Expert mode'));
      toggle.setAttribute(
        'aria-label',
        next === 'expert'
          ? (isRu ? 'Включить простой режим' : 'Switch to simple mode')
          : (isRu ? 'Включить режим специалиста' : 'Switch to expert mode'),
      );
    }

    toggle.addEventListener('click', () => {
      applyMode(currentMode() === 'expert' ? 'simple' : 'expert');
    });
    applyMode(currentMode());
  })();

  capVisualBanners();

  (function initOnboarding() {
    const root = document.querySelector('[data-onboarding]');
    const storageKey = 'dt_onboarding_done_v1';
    const panel = root?.querySelector('.onboarding__panel');
    const target = document.querySelector('[data-onboarding-target]');
    const nextBtn = root?.querySelector('[data-onboarding-next]');
    const doneBtn = root?.querySelector('[data-onboarding-done]');
    let steps = [];
    let dots = [];
    let current = 0;
    let releaseFocusTrap = null;
    let positionHandler = null;

    function isDone() {
      try {
        return localStorage.getItem(storageKey) === '1';
      } catch (e) {
        return true;
      }
    }

    function markDone() {
      try {
        localStorage.setItem(storageKey, '1');
      } catch (e) {}
    }

    function positionPanel() {
      if (!root || !panel || root.hidden) return;
      if (window.matchMedia('(max-width: 767.98px)').matches) return;
      if (!target) {
        panel.style.top = '50%';
        panel.style.left = '50%';
        panel.style.transform = 'translate(-50%, -50%)';
        panel.style.width = 'min(calc(100vw - 2rem), 22rem)';
        return;
      }
      const rect = target.getBoundingClientRect();
      const panelRect = panel.getBoundingClientRect();
      const left = Math.min(
        Math.max(16, rect.left),
        window.innerWidth - panelRect.width - 16,
      );
      const top = Math.min(rect.bottom + 14, window.innerHeight - panelRect.height - 16);
      panel.style.left = `${left}px`;
      panel.style.top = `${Math.max(16, top)}px`;
      panel.style.transform = 'none';
      panel.style.width = `${Math.min(22 * 16, Math.max(280, rect.width))}px`;
    }

    function trapFocus(container) {
      const nodes = container.querySelectorAll(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      const items = Array.from(nodes).filter((el) => !el.disabled && el.offsetParent !== null);
      const first = items[0];
      const last = items[items.length - 1];
      function onKeydown(ev) {
        if (ev.key === 'Escape') {
          ev.preventDefault();
          dismiss();
          return;
        }
        if (ev.key !== 'Tab' || !items.length) return;
        if (ev.shiftKey && document.activeElement === first) {
          ev.preventDefault();
          last.focus();
        } else if (!ev.shiftKey && document.activeElement === last) {
          ev.preventDefault();
          first.focus();
        }
      }
      container.addEventListener('keydown', onKeydown);
      (nextBtn || doneBtn || first)?.focus();
      return () => container.removeEventListener('keydown', onKeydown);
    }

    function showStep(idx) {
      if (!root) return;
      current = Math.max(0, Math.min(idx, steps.length - 1));
      steps.forEach((step, i) => step.classList.toggle('d-none', i !== current));
      dots.forEach((dot, i) => dot.classList.toggle('is-active', i === current));
      const onLast = current >= steps.length - 1;
      nextBtn?.classList.toggle('d-none', onLast);
      doneBtn?.classList.toggle('d-none', !onLast);
      target?.classList.toggle('onboarding-highlight', current === 0);
      requestAnimationFrame(positionPanel);
    }

    function dismiss() {
      if (!root) return;
      root.hidden = true;
      document.body.classList.remove('onboarding-open');
      target?.classList.remove('onboarding-highlight');
      if (releaseFocusTrap) {
        releaseFocusTrap();
        releaseFocusTrap = null;
      }
      if (positionHandler) {
        window.removeEventListener('resize', positionHandler);
        window.removeEventListener('scroll', positionHandler, true);
        positionHandler = null;
      }
    }

    function complete() {
      markDone();
      dismiss();
    }

    function open(force) {
      if (!root) {
        const tipUrl = new URL(window.location.href);
        if (tipUrl.pathname === '/' || tipUrl.pathname === '') {
          return;
        }
        tipUrl.pathname = '/';
        tipUrl.searchParams.set('tip', '1');
        window.location.href = tipUrl.toString();
        return;
      }
      if (!force && isDone()) return;

      steps = Array.from(root.querySelectorAll('[data-onboarding-step]'));
      dots = Array.from(root.querySelectorAll('[data-onboarding-dot]'));
      root.hidden = false;
      document.body.classList.add('onboarding-open');
      showStep(0);
      releaseFocusTrap = trapFocus(root);
      positionHandler = () => positionPanel();
      window.addEventListener('resize', positionHandler, { passive: true });
      window.addEventListener('scroll', positionHandler, { passive: true, capture: true });
      positionPanel();
    }

    document.querySelectorAll('[data-onboarding-replay]').forEach((btn) => {
      btn.addEventListener('click', (ev) => {
        ev.preventDefault();
        open(true);
      });
    });

    if (!root) return;

    root.querySelectorAll('[data-onboarding-dismiss]').forEach((btn) => {
      btn.addEventListener('click', dismiss);
    });
    nextBtn?.addEventListener('click', () => showStep(current + 1));
    doneBtn?.addEventListener('click', complete);

    const params = new URLSearchParams(window.location.search);
    if (params.get('tip') === '1') {
      open(true);
      params.delete('tip');
      const clean = `${window.location.pathname}${params.toString() ? `?${params}` : ''}`;
      window.history.replaceState({}, '', clean);
    } else if (!isDone()) {
      window.setTimeout(() => open(false), 480);
    }
  })();

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
      const registrar = (link.getAttribute('data-buy-registrar') || '').toLowerCase();
      const tld = domain.includes('.') ? domain.split('.').slice(-1)[0] : '';
      if (!tld) return;
      const payload = { tld, locale: (locale === 'en' ? 'en' : 'ru') };
      if (registrar) payload.registrar = registrar;
      sendAnalyticsBeacon('/track/buy-click', payload);
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

  function confirmAction(message) {
    if (!message) return true;
    return window.confirm(message);
  }

  document.querySelectorAll('[data-security-quick-port]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const form = btn.closest('form.security-form');
      if (!form) return;
      const portsInput = form.querySelector('input[name="ports"]');
      if (!portsInput) return;
      const preset = btn.getAttribute('data-security-quick-port') || '';
      const msg = body?.dataset?.i18nConfirmPortPreset;
      if (portsInput.value && portsInput.value !== preset && !confirmAction(msg)) return;
      portsInput.value = preset;
      portsInput.focus();
      portsInput.select();
    });
  });

  document.querySelectorAll('[data-security-port-form]').forEach((form) => {
    form.addEventListener('submit', (e) => {
      const consent = form.querySelector('input[name="confirm_ownership"]');
      if (consent && !consent.checked) {
        e.preventDefault();
        consent.focus();
      }
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

  // ===== Smart query intent (live hints + dynamic submit labels) =====
  (function initSmartQuery() {
    const QUERY_HISTORY_KEY = 'dt:query-history-v1';
    const HISTORY_LIMIT = 8;
    let resolveTimer = null;
    let resolveAbort = null;

    function isEn() {
      return (document.documentElement.lang || '').toLowerCase().startsWith('en');
    }

    function pageLang() {
      return isEn() ? 'en' : 'ru';
    }

    function readHistory() {
      try {
        const raw = localStorage.getItem(QUERY_HISTORY_KEY);
        const parsed = raw ? JSON.parse(raw) : [];
        return Array.isArray(parsed) ? parsed.filter((x) => typeof x === 'string' && x.trim()) : [];
      } catch (e) {
        return [];
      }
    }

    function writeHistory(query) {
      const q = String(query || '').trim();
      if (!q) return;
      const prev = readHistory().filter((item) => item !== q);
      prev.unshift(q);
      try {
        localStorage.setItem(QUERY_HISTORY_KEY, JSON.stringify(prev.slice(0, HISTORY_LIMIT)));
      } catch (e) {}
      renderHistoryChips();
    }

    function renderHistoryChips() {
      const wrap = document.querySelector('[data-query-history]');
      const chips = document.querySelector('[data-query-history-chips]');
      if (!wrap || !chips) return;
      const items = readHistory();
      chips.innerHTML = '';
      if (!items.length) {
        wrap.classList.add('d-none');
        return;
      }
      wrap.classList.remove('d-none');
      items.forEach((item) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'query-history__chip';
        btn.textContent = item;
        btn.addEventListener('click', () => {
          const paletteInput = document.getElementById('commandPaletteInput');
          if (paletteInput) {
            paletteInput.value = item;
            paletteInput.dispatchEvent(new Event('input', { bubbles: true }));
            paletteInput.focus();
          }
        });
        chips.appendChild(btn);
      });
    }

    window.__dtWriteQueryHistory = writeHistory;
    window.__dtReadQueryHistory = readHistory;
    renderHistoryChips();

    function cacheSubmitLabels(form) {
      if (!form || form.dataset.smartLabelsCached) return;
      form.querySelectorAll('.btn-label--long').forEach((el) => {
        if (!el.dataset.defaultLabel) {
          el.dataset.defaultLabel = el.textContent.trim();
        }
      });
      form.querySelectorAll('.btn-label--short').forEach((el) => {
        if (!el.dataset.defaultLabel) {
          el.dataset.defaultLabel = el.textContent.trim();
        }
      });
      form.dataset.smartLabelsCached = '1';
    }

    function restoreSubmitLabels(form) {
      if (!form) return;
      form.querySelectorAll('.btn-label--long, .btn-label--short').forEach((el) => {
        if (el.dataset.defaultLabel) {
          el.textContent = el.dataset.defaultLabel;
        }
      });
    }

    function updateSubmitLabels(form, actionLabel) {
      if (!form || !actionLabel) return;
      cacheSubmitLabels(form);
      form.querySelectorAll('.btn-label--long').forEach((el) => {
        el.textContent = actionLabel;
      });
    }

    function applyResolved(form, intentEl, data) {
      if (!intentEl) return;
      const textEl = intentEl.querySelector('[data-query-intent-text]');
      const iconEl = intentEl.querySelector('[data-query-intent-icon]');
      const label = data?.intent_label || '';
      if (!label) {
        intentEl.classList.add('d-none');
        return;
      }
      intentEl.classList.remove('d-none');
      if (textEl) textEl.textContent = label;
      if (iconEl && data?.intent_icon) {
        iconEl.className = `fa-solid ${data.intent_icon} query-intent__icon`;
      }
      updateSubmitLabels(form, data?.action_label || '');
      form.dataset.smartResolvedUrl = data?.default_url || '';
      form.dataset.smartResolvedKind = data?.kind || '';
    }

    async function resolveQuery(query, context) {
      const q = String(query || '').trim();
      if (!q) return null;
      if (resolveAbort) resolveAbort.abort();
      resolveAbort = new AbortController();
      const url = `/api/resolve?${new URLSearchParams({ q, context: context || 'global', lang: pageLang() })}`;
      const resp = await fetch(url, { signal: resolveAbort.signal, headers: { Accept: 'application/json' } });
      if (!resp.ok) return null;
      return resp.json();
    }

    function prefillSmartInputs() {
      document.querySelectorAll('[data-smart-query]').forEach((input) => {
        if ((input.value || '').trim()) return;
        const explicit = input.getAttribute('data-prefill');
        if (explicit) {
          input.value = explicit;
          return;
        }
        const form = input.closest('[data-smart-query-form]');
        const ctx = form?.dataset.queryContext || '';
        if (ctx === 'check') {
          const m = window.location.pathname.match(/^\/check\/(.+?)\/?$/);
          if (m && m[1]) {
            try {
              input.value = decodeURIComponent(m[1]);
            } catch (e) {
              input.value = m[1];
            }
          }
        }
      });
    }

    prefillSmartInputs();

    document.querySelectorAll('[data-smart-query-form]').forEach((form) => {
      const input = form.querySelector('[data-smart-query]');
      const intentEl = form.querySelector('[data-query-intent]');
      const context = form.dataset.queryContext || intentEl?.dataset.queryContext || 'global';
      if (!input) return;
      cacheSubmitLabels(form);

      const runResolve = () => {
        const value = input.value.trim();
        if (!value) {
          if (intentEl) intentEl.classList.add('d-none');
          delete form.dataset.smartResolvedUrl;
          delete form.dataset.smartResolvedKind;
          restoreSubmitLabels(form);
          return;
        }
        resolveQuery(value, context)
          .then((data) => applyResolved(form, intentEl, data))
          .catch(() => {});
      };

      input.addEventListener('input', () => {
        clearTimeout(resolveTimer);
        resolveTimer = window.setTimeout(runResolve, 260);
      });

      if (input.value.trim()) runResolve();

      form.addEventListener('submit', (e) => {
        writeHistory(input.value);
        const kind = form.dataset.smartResolvedKind;
        const target = form.dataset.smartResolvedUrl;
        if (!target || !kind || kind === 'invalid' || kind === 'empty') return;
        const ctx = form.dataset.queryContext || 'global';
        const redirectKinds = new Set(['fqdn', 'ip', 'label', 'ideas', 'batch']);
        const mismatchContexts = new Set(['whois', 'dns', 'geo', 'reverse']);
        if (redirectKinds.has(kind)) {
          if (mismatchContexts.has(ctx) && (kind === 'label' || kind === 'ideas')) {
            e.preventDefault();
            window.location.href = target;
            return;
          }
          if (ctx === 'check' && (kind === 'label' || kind === 'ideas' || kind === 'ip')) {
            e.preventDefault();
            window.location.href = target;
            return;
          }
          if (ctx === 'home' && form.getAttribute('method')?.toLowerCase() === 'post') {
            return;
          }
          if (kind === 'batch' && ctx === 'report') {
            return;
          }
        }
      });
    });
  })();

  (function initWhoisPendingRefresh() {
    if (!window.__DT_WHOIS_PENDING__) return;
    const path = window.location.pathname || '';
    if (!path.startsWith('/check/')) return;
    const sep = path.includes('?') ? '&' : '?';
    window.setTimeout(() => {
      if (!document.querySelector('.report-skeleton')) return;
      window.location.replace(`${path}${sep}run=1`);
    }, 1200);
  })();

  // ===== Command palette (Ctrl/Cmd+K) =====
  (function initCommandPalette() {
    const isMacPlatform = /Mac|iPhone|iPad|iPod/.test(navigator.platform || '');
    document.querySelectorAll('[data-shortcut-mod]').forEach((el) => {
      el.textContent = isMacPlatform ? 'Cmd' : 'Ctrl';
    });

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
    let executeItem = null;
    let paletteResolveTimer = null;

    function normalize(value) {
      return String(value || '').toLowerCase().trim();
    }

    function itemHaystack(item) {
      const keywords = Array.isArray(item.keywords) ? item.keywords.join(' ') : '';
      return normalize(`${item.title} ${item.subtitle || ''} ${keywords}`);
    }

    function looksLikeQuery(q) {
      const text = String(q || '').trim();
      if (text.length < 2) return false;
      if (text.includes('.') || text.includes('@')) return true;
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(text)) return true;
      if (/\s/.test(text)) return true;
      return text.length >= 3;
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

    function scheduleResolve(query) {
      clearTimeout(paletteResolveTimer);
      const q = String(query || '').trim();
      if (!looksLikeQuery(q)) {
        executeItem = null;
        filtered = filterItems(q);
        selectedIndex = 0;
        renderList();
        return;
      }
      paletteResolveTimer = window.setTimeout(async () => {
        try {
          const resp = await fetch(`/api/resolve?${new URLSearchParams({ q, context: 'home', lang: pageLang() })}`, {
            headers: { Accept: 'application/json' },
          });
          if (!resp.ok) throw new Error('resolve failed');
          const data = await resp.json();
          if (!data || data.kind === 'empty' || data.kind === 'invalid') {
            executeItem = null;
          } else {
            executeItem = {
              id: 'execute-query',
              title: data.action_label || (document.documentElement.lang.startsWith('en') ? 'Run query' : 'Выполнить'),
              subtitle: data.intent_label || q,
              url: data.default_url,
              icon: data.intent_icon || 'fa-bolt',
              isExecute: true,
            };
          }
        } catch (e) {
          executeItem = null;
        }
        filtered = filterItems(q);
        selectedIndex = 0;
        renderList();
      }, 220);
    }

    function renderList() {
      list.innerHTML = '';
      const rows = executeItem ? [executeItem, ...filtered] : filtered.slice();
      if (!rows.length) {
        const empty = document.createElement('li');
        empty.className = 'command-palette__empty';
        empty.textContent = document.documentElement.lang.startsWith('en')
          ? 'No matching tools'
          : 'Ничего не найдено';
        list.appendChild(empty);
        return;
      }

      rows.forEach((item, index) => {
        const li = document.createElement('li');
        const link = document.createElement('a');
        link.className = 'command-palette__item';
        if (item.isExecute) link.classList.add('command-palette__item--execute');
        link.href = item.url || '#';
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

    function visibleRows() {
      return executeItem ? [executeItem, ...filtered] : filtered.slice();
    }

    function setSelected(index) {
      const rows = visibleRows();
      if (!rows.length) {
        selectedIndex = 0;
        renderList();
        return;
      }
      selectedIndex = ((index % rows.length) + rows.length) % rows.length;
      renderList();
      scrollSelectedIntoView();
    }

    function openPalette() {
      if (root.classList.contains('is-open')) return;
      lastFocus = document.activeElement;
      filtered = items.slice();
      executeItem = null;
      selectedIndex = 0;
      input.value = '';
      renderList();
      if (typeof window.__dtReadQueryHistory === 'function') {
        const histWrap = document.querySelector('[data-query-history]');
        if (histWrap) histWrap.classList.toggle('d-none', !window.__dtReadQueryHistory().length);
      }
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
      const rows = visibleRows();
      const item = rows[selectedIndex];
      if (!item || !item.url) return;
      if (typeof window.__dtWriteQueryHistory === 'function' && input.value.trim()) {
        window.__dtWriteQueryHistory(input.value.trim());
      }
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
      const modifier = isMacPlatform ? e.metaKey : e.ctrlKey;
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
      scheduleResolve(input.value);
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

    // Mobile/touch: rely on native browser scroll (avoids duplicate arrows with Safari/Chrome UI).
    const mobileScrollMq = window.matchMedia('(max-width: 991.98px), (pointer: coarse)');
    const threshold = 320;
    const label = body?.dataset.i18nScrollTop || 'Back to top';
    btn.setAttribute('aria-label', label);
    btn.setAttribute('title', label);

    let ticking = false;
    let desktopBound = false;

    function updateVisibility() {
      if (mobileScrollMq.matches) {
        btn.classList.remove('is-visible');
        btn.hidden = true;
        ticking = false;
        return;
      }
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

    function onClick() {
      const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      window.scrollTo({ top: 0, behavior: reduceMotion ? 'auto' : 'smooth' });
      btn.blur();
    }

    function bindDesktop() {
      if (desktopBound || mobileScrollMq.matches) return;
      desktopBound = true;
      btn.addEventListener('click', onClick);
      window.addEventListener('scroll', onScroll, { passive: true });
      window.addEventListener('resize', onScroll, { passive: true });
    }

    function applyScrollPolicy() {
      btn.classList.toggle('scroll-to-top--disabled-mobile', mobileScrollMq.matches);
      if (mobileScrollMq.matches) {
        btn.classList.remove('is-visible');
        btn.hidden = true;
        return;
      }
      bindDesktop();
      updateVisibility();
    }

    applyScrollPolicy();
    mobileScrollMq.addEventListener('change', applyScrollPolicy);
  })();

  // ===== Quick actions dock (reusable) =====
  (function initQuickActionsDock() {
    const dock = document.querySelector('[data-quick-actions-dock]');
    if (!dock) return;

    const toggleBtns = dock.querySelectorAll('[data-qa-dock-toggle]');
    let pinned = false;

    function setExpanded(next) {
      pinned = next;
      dock.classList.toggle('is-expanded', pinned);
      dock.setAttribute('aria-expanded', pinned ? 'true' : 'false');
      toggleBtns.forEach((btn) => {
        const isRu = (document.documentElement.getAttribute('lang') || '').toLowerCase().startsWith('ru');
        btn.setAttribute(
          'aria-label',
          pinned
            ? (isRu ? 'Свернуть быстрые действия' : 'Collapse quick actions')
            : (isRu ? 'Развернуть быстрые действия' : 'Expand quick actions')
        );
      });
    }

    toggleBtns.forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        setExpanded(!pinned);
      });
    });

    document.addEventListener('click', (e) => {
      if (!pinned) return;
      if (!dock.contains(e.target)) setExpanded(false);
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && pinned) setExpanded(false);
    });

    const lang = (document.documentElement.getAttribute('lang') || '').toLowerCase();
    const isRu = lang.startsWith('ru');
    let ctx = {};
    try {
      ctx = JSON.parse(dock.getAttribute('data-qa-context') || '{}');
    } catch (e) {
      ctx = {};
    }

    const kind = ctx.kind || 'generic';
    const domain = ctx.domain || '';
    const shareUrl = ctx.share_url || window.location.href;
    const payload = ctx.payload || {};
    const FAVORITES_KEY = 'dt_favorites_v1';

    function payloadPlainText() {
      if (kind === 'dns' && payload && typeof payload === 'object' && !Array.isArray(payload)) {
        const lines = [];
        Object.keys(payload).sort().forEach((rtype) => {
          const vals = payload[rtype];
          if (!Array.isArray(vals) || !vals.length) return;
          lines.push(rtype);
          vals.forEach((v) => lines.push(`  ${v}`));
          lines.push('');
        });
        return lines.join('\n').trim();
      }
      if (kind === 'domains' && Array.isArray(payload)) {
        return payload.map((row) => {
          const name = row.fqdn || row.puny || '';
          const status = row.available
            ? (isRu ? 'свободен' : 'available')
            : (isRu ? 'занят' : 'taken');
          return `${name}\t${status}`;
        }).join('\n');
      }
      if (kind === 'report' && payload && typeof payload === 'object') {
        const lines = [];
        const whois = payload.whois || {};
        const dns = payload.dns || {};
        if (whois.registrar) lines.push(`${isRu ? 'Регистратор' : 'Registrar'}: ${whois.registrar}`);
        if (whois.expiration_date) lines.push(`${isRu ? 'Истекает' : 'Expires'}: ${whois.expiration_date}`);
        if (dns.records && typeof dns.records === 'object') {
          Object.keys(dns.records).forEach((rtype) => {
            const vals = dns.records[rtype];
            if (Array.isArray(vals) && vals.length) {
              lines.push(`${rtype}: ${vals.join(', ')}`);
            }
          });
        }
        if (lines.length) return lines.join('\n');
      }
      try {
        return JSON.stringify(payload, null, 2);
      } catch (e) {
        return String(payload || '');
      }
    }

    function copyHeader() {
      if (kind === 'dns') {
        return isRu ? `DNS записи для ${domain}\n\n` : `DNS records for ${domain}\n\n`;
      }
      return isRu ? `Результат для ${domain}\n\n` : `Result for ${domain}\n\n`;
    }

    function downloadFile(filename, content, mime) {
      const blob = new Blob([content], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    }

    function flashDone(btn) {
      if (!btn) return;
      btn.classList.add('is-done');
      window.setTimeout(() => btn.classList.remove('is-done'), 1400);
    }

    function confirmForAction(action, risk) {
      if (action === 'export-json' || action === 'export-csv') {
        return confirmAction(body?.dataset?.i18nConfirmExport);
      }
      if (action === 'copy') {
        return confirmAction(body?.dataset?.i18nConfirmCopy);
      }
      if (action === 'share') {
        return confirmAction(body?.dataset?.i18nConfirmShare);
      }
      return true;
    }

    const mobileOpen = document.querySelector('[data-mobile-qa-open]');
    const mobileCanvas = document.getElementById('mobileQuickActions');
    if (mobileOpen && mobileCanvas && window.bootstrap?.Offcanvas) {
      const offcanvas = bootstrap.Offcanvas.getOrCreateInstance(mobileCanvas);
      mobileOpen.addEventListener('click', () => offcanvas.show());
    }

    document.addEventListener('click', async (e) => {
      const clearBtn = e.target.closest('[data-qa-clear-history]');
      if (clearBtn) {
        e.preventDefault();
        if (!confirmAction(body?.dataset?.i18nConfirmClearHistory)) return;
        try {
          const resp = await fetch('/api/history/user/clear', { method: 'POST', headers: { Accept: 'application/json' } });
          if (resp.ok && typeof window.dtRefreshPanelHistory === 'function') window.dtRefreshPanelHistory();
        } catch (err) {
          /* noop */
        }
        return;
      }

      const btn = e.target.closest('[data-qa-action]');
      if (!btn) return;
      const qaRoot = btn.closest('[data-quick-actions-dock], #mobileQuickActions');
      if (!qaRoot) return;
      e.preventDefault();
      const action = btn.getAttribute('data-qa-action');
      const copyTarget = btn.getAttribute('data-qa-copy-target');
      if (!confirmForAction(action, btn.getAttribute('data-qa-risk'))) return;

      try {
        if (action === 'share') {
          const title = `${kind.toUpperCase()} ${domain}`.trim();
          const text = isRu ? `Результаты для ${domain}` : `Results for ${domain}`;
          if (navigator.share) {
            await navigator.share({ title, text, url: shareUrl });
          } else {
            await navigator.clipboard.writeText(shareUrl);
          }
          flashDone(btn);
        } else if (action === 'copy') {
          let txt = '';
          if (copyTarget) {
            txt = (document.querySelector(copyTarget)?.textContent || '').trim();
          } else {
            txt = copyHeader() + payloadPlainText();
          }
          await navigator.clipboard.writeText(txt);
          flashDone(btn);
        } else if (action === 'export-json') {
          const body = { kind, domain, payload, exported_at: new Date().toISOString() };
          downloadFile(`${kind}-${domain || 'export'}.json`, JSON.stringify(body, null, 2), 'application/json');
          flashDone(btn.closest('.quick-actions-dock__item')?.querySelector('[data-qa-action="export-json"]') || btn);
        } else if (action === 'export-csv') {
          const rows = [['type', 'value']];
          if (kind === 'dns' && payload && typeof payload === 'object' && !Array.isArray(payload)) {
            Object.keys(payload).sort().forEach((rtype) => {
              (payload[rtype] || []).forEach((v) => rows.push([rtype, v]));
            });
          } else if (kind === 'domains' && Array.isArray(payload)) {
            rows.length = 0;
            rows.push(['domain', 'punycode', 'available']);
            payload.forEach((row) => {
              rows.push([row.fqdn || '', row.puny || '', row.available ? 'yes' : 'no']);
            });
          } else {
            rows.push(['data', JSON.stringify(payload)]);
          }
          const csv = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
          downloadFile(`${kind}-${domain || 'export'}.csv`, csv, 'text/csv');
          flashDone(btn);
        } else if (action === 'favorite') {
          let favs = [];
          try {
            favs = JSON.parse(localStorage.getItem(FAVORITES_KEY) || '[]');
          } catch (err) {
            favs = [];
          }
          const entry = { domain, url: shareUrl, kind, ts: Date.now() };
          if (!favs.some((f) => f.url === entry.url)) favs.unshift(entry);
          localStorage.setItem(FAVORITES_KEY, JSON.stringify(favs.slice(0, 50)));
          const icon = btn.querySelector('.fa-regular, .fa-solid');
          if (icon) {
            icon.classList.remove('fa-regular');
            icon.classList.add('fa-solid');
          }
          flashDone(btn);
        }
      } catch (err) {
        /* noop */
      }
    });
  })();

  // ===== Global history preference (navbar + panel toggles) =====
  (function initGlobalHistoryPreference() {
    const GLOBAL_HIST_KEY = 'dt:show-global-history';

    function toggles() {
      return document.querySelectorAll('[data-qa-show-global-history], [data-qa-show-global-history-nav]');
    }

    function globalWraps() {
      return document.querySelectorAll('[data-qa-history-global-wrap]');
    }

    function applyVisible(show) {
      globalWraps().forEach((wrap) => wrap.classList.toggle('d-none', !show));
    }

    function setGlobalHistory(show, { refresh = true } = {}) {
      localStorage.setItem(GLOBAL_HIST_KEY, show ? '1' : '0');
      toggles().forEach((el) => {
        el.checked = show;
      });
      applyVisible(show);
      if (refresh && typeof window.dtRefreshPanelHistory === 'function') {
        window.dtRefreshPanelHistory();
      }
    }

    const initial = localStorage.getItem(GLOBAL_HIST_KEY) === '1';
    toggles().forEach((el) => {
      el.checked = initial;
    });
    applyVisible(initial);

    document.addEventListener('change', (e) => {
      const target = e.target;
      if (!target.matches('[data-qa-show-global-history], [data-qa-show-global-history-nav]')) return;
      setGlobalHistory(target.checked);
    });
  })();

  // ===== Panel history — live refresh inside Quick Actions =====
  (function initPanelHistoryRefresh() {
    const dock = document.querySelector('[data-quick-actions-dock]');
    if (!dock) return;
    const POLL_MS = 12000;
    const GLOBAL_HIST_KEY = 'dt:show-global-history';
    let inflight = false;
    let fingerprint = '';

    function pageLang() {
      const lang = (document.documentElement.getAttribute('lang') || 'ru').toLowerCase();
      return lang.startsWith('en') ? 'en' : 'ru';
    }

    function esc(value) {
      return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/"/g, '&quot;');
    }

    function renderChip(item) {
      const href = esc(item.repeat_url || item.view_url || '#');
      const domain = esc(item.domain_display || item.query || '—');
      const kind = esc(item.chip_kind_label || String(item.kind || '').toUpperCase());
      const timeRu = item.time_ago_ru || '';
      const timeEn = item.time_ago_en || '';
      const isRu = pageLang() === 'ru';
      const time = esc(isRu ? timeRu : timeEn);
      const timeHtml = time ? `<span class="quick-actions-dock__history-time">${time}</span>` : '';
      return `<a class="quick-actions-dock__history-chip" href="${href}" title="${domain}">
        <span class="quick-actions-dock__history-domain">${domain}</span>
        <span class="quick-actions-dock__history-meta">
          <span class="quick-actions-dock__history-kind">${kind}</span>${timeHtml}
        </span>
      </a>`;
    }

    function renderLists(selector, items) {
      document.querySelectorAll(selector).forEach((el) => {
        el.innerHTML = (items || []).map(renderChip).join('');
      });
    }

    async function refreshPanelHistory() {
      if (document.visibilityState === 'hidden') return;
      if (inflight) return;
      inflight = true;
      try {
        const showGlobal = localStorage.getItem(GLOBAL_HIST_KEY) === '1';
        document.querySelectorAll('[data-qa-history-global-wrap]').forEach((wrap) => {
          wrap.classList.toggle('d-none', !showGlobal);
        });
        const url = `/api/history/dock?lang=${encodeURIComponent(pageLang())}${showGlobal ? '&global=1' : ''}`;
        const resp = await fetch(url, { headers: { Accept: 'application/json' }, cache: 'no-store' });
        if (!resp.ok) return;
        const data = await resp.json();
        const fp = JSON.stringify(data);
        if (fp === fingerprint) return;
        fingerprint = fp;
        renderLists('[data-qa-history-user]', data.user?.items || []);
        if (showGlobal) renderLists('[data-qa-history-global]', data.global?.items || []);
      } catch (err) {
        /* noop */
      } finally {
        inflight = false;
      }
    }

    window.setTimeout(refreshPanelHistory, 800);
    window.setInterval(refreshPanelHistory, POLL_MS);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') refreshPanelHistory();
    });
    window.dtRefreshPanelHistory = refreshPanelHistory;
  })();

  // ===== Session info (opt-in, fetched on demand) =====
  (function initSessionInfo() {
    const wraps = document.querySelectorAll('[data-qa-session-info-wrap]');
    if (!wraps.length) return;

    const cache = { loaded: false, data: null, inflight: null };

    function pageLang() {
      const lang = (document.documentElement.getAttribute('lang') || 'ru').toLowerCase();
      return lang.startsWith('en') ? 'en' : 'ru';
    }

    function label(ru, en) {
      return pageLang() === 'en' ? en : ru;
    }

    function esc(value) {
      return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/"/g, '&quot;');
    }

    function renderData(panel, data) {
      const dl = panel.querySelector('[data-qa-session-info-data]');
      const note = panel.querySelector('[data-qa-session-info-note]');
      const loading = panel.querySelector('[data-qa-session-info-loading]');
      if (!dl) return;

      const loc = pageLang() === 'en' ? data.location_en : data.location_ru;
      const browser = pageLang() === 'en' ? data.browser_en : data.browser_ru;
      const rows = [
        [label('IP', 'IP'), data.ip || '—'],
        [label('Местоположение', 'Location'), loc || '—'],
        [label('Браузер', 'Browser'), browser || '—'],
      ];
      if (data.session_id_short) {
        rows.push([label('Сессия', 'Session'), data.session_id_short]);
      }
      dl.innerHTML = rows.map(([k, v]) => (
        `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`
      )).join('');
      dl.hidden = false;
      if (note) note.hidden = false;
      if (loading) loading.hidden = true;
    }

    async function fetchSessionInfo() {
      if (cache.loaded) return cache.data;
      if (cache.inflight) return cache.inflight;
      cache.inflight = fetch('/api/session/info', {
        headers: { Accept: 'application/json' },
        cache: 'no-store',
      }).then(async (resp) => {
        if (!resp.ok) throw new Error('session info failed');
        const data = await resp.json();
        cache.data = data;
        cache.loaded = true;
        return data;
      }).finally(() => {
        cache.inflight = null;
      });
      return cache.inflight;
    }

    function setPanelOpen(wrap, open) {
      const toggle = wrap.querySelector('[data-qa-session-info-toggle]');
      const panel = wrap.querySelector('[data-qa-session-info-panel]');
      if (!toggle || !panel) return;
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      panel.classList.toggle('d-none', !open);
      panel.hidden = !open;
    }

    wraps.forEach((wrap) => {
      const toggle = wrap.querySelector('[data-qa-session-info-toggle]');
      const panel = wrap.querySelector('[data-qa-session-info-panel]');
      if (!toggle || !panel) return;

      toggle.addEventListener('click', async () => {
        const isOpen = toggle.getAttribute('aria-expanded') === 'true';
        if (isOpen) {
          setPanelOpen(wrap, false);
          return;
        }
        setPanelOpen(wrap, true);
        const loading = panel.querySelector('[data-qa-session-info-loading]');
        if (loading) loading.hidden = false;
        try {
          const data = await fetchSessionInfo();
          document.querySelectorAll('[data-qa-session-info-panel]').forEach((p) => {
            renderData(p, data);
          });
        } catch (err) {
          const dl = panel.querySelector('[data-qa-session-info-data]');
          if (dl) {
            dl.innerHTML = `<dt>${esc(label('Ошибка', 'Error'))}</dt><dd>${esc(label('Не удалось загрузить', 'Could not load'))}</dd>`;
            dl.hidden = false;
          }
          if (loading) loading.hidden = true;
        }
      });
    });
  })();
})();