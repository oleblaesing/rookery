/**
 * partials.js — in-house fetch+swap helper for rookery.
 *
 * Hand-written, no third-party library. Replaces HTMX per ADR-0012.
 * Provides a small set of primitives for the handful of places rookery
 * needs partial-page updates:
 *
 *   - Recipient key-status hints on the compose page (Phase 2).
 *   - DNS verification polling on the custom-domain setup page (Phase 3).
 *   - Mark-as-read (inbox row update).
 *   - Logout link.
 *
 * Endpoints called by this module return HTML fragments (never JSON), except
 * where the JS crypto module needs raw data (ciphertext, key material).
 * This discipline prevents drift toward an accidental SPA. See ADR-0012.
 *
 * API surface (intentionally tiny):
 *
 *   partials.swap(selector, url, options)
 *     Fetches url and replaces the innerHTML of selector with the response.
 *     options: { method, body, headers, onError }
 *
 *   partials.poll(selector, url, intervalMs, stopWhen)
 *     Polls url every intervalMs ms, swapping the result into selector.
 *     Stops when stopWhen(element) returns true.
 *
 *   partials.debounce(fn, ms) → debounced fn
 *
 *   partials.onSubmit(formSelector, handler)
 *     Intercepts form submit, calls handler(formData, form).
 *
 * CSRF token is read from the meta[name="csrf-token"] tag.
 *
 * This file ships as-is — no build step, no minification here.
 * The Containerfile copies it directly into the image.
 */

(function (global) {
  'use strict';

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  async function swap(selector, url, options = {}) {
    const el = typeof selector === 'string'
      ? document.querySelector(selector)
      : selector;
    if (!el) return;

    const method  = (options.method || 'GET').toUpperCase();
    const headers = Object.assign({ 'X-CSRF-Token': csrfToken() }, options.headers || {});
    let body = options.body;

    try {
      const resp = await fetch(url, { method, headers, body, credentials: 'same-origin' });
      const html = await resp.text();
      el.innerHTML = html;
    } catch (err) {
      if (options.onError) options.onError(err, el);
      else console.error('partials.swap error', url, err);
    }
  }

  function poll(selector, url, intervalMs, stopWhen) {
    const el = typeof selector === 'string'
      ? document.querySelector(selector)
      : selector;
    if (!el) return;

    const timer = setInterval(async function () {
      try {
        const resp = await fetch(url, {
          headers: { 'X-CSRF-Token': csrfToken() },
          credentials: 'same-origin',
        });
        const html = await resp.text();
        el.innerHTML = html;
        if (stopWhen && stopWhen(el)) clearInterval(timer);
      } catch (err) {
        console.error('partials.poll error', url, err);
      }
    }, intervalMs);
    return timer;
  }

  function debounce(fn, ms) {
    let timer;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), ms);
    };
  }

  function onSubmit(formSelector, handler) {
    const form = typeof formSelector === 'string'
      ? document.querySelector(formSelector)
      : formSelector;
    if (!form) return;
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      handler(new FormData(form), form);
    });
  }

  // ---- Wired-up behaviour (runs on every page) ----------------------------

  document.addEventListener('DOMContentLoaded', function () {
    // When another tab logs out it removes the localStorage key material.
    // Redirect this tab to /login as soon as that removal is observed.
    window.addEventListener('storage', function (e) {
      if (e.key === 'rookery_swk' && e.newValue === null) {
        window.location.href = '/login';
      }
    });

    // Logout link: clear localStorage key material, POST to the logout API,
    // then redirect to /login. The localStorage clear is inlined here rather
    // than delegated to window.RookeryCrypto so it runs even if crypto.js
    // failed to load.
    document.querySelectorAll('[data-action="logout"]').forEach(function (el) {
      el.addEventListener('click', async function (e) {
        e.preventDefault();
        try {
          localStorage.removeItem('rookery_swk');
          localStorage.removeItem('rookery_swb');
          localStorage.removeItem('rookery_sfp');
        } catch (_) {}
        await fetch('/api/v1/auth/logout', {
          method: 'POST',
          headers: { 'X-CSRF-Token': csrfToken() },
          credentials: 'same-origin',
        });
        window.location.href = '/login';
      });
    });


  });

  global.partials = { swap, poll, debounce, onSubmit };
})(window);
