(function (global) {
  "use strict";

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');

    return meta ? meta.getAttribute("content") : "";
  }

  function resolveEl(selector) {
    return typeof selector === "string"
      ? document.querySelector(selector)
      : selector;
  }

  async function swap(selector, url, options = {}) {
    const el = resolveEl(selector);

    if (!el) {
      return;
    }

    const method = (options.method || "GET").toUpperCase();
    const headers = Object.assign(
      { "X-CSRF-Token": csrfToken() },
      options.headers || {},
    );
    let body = options.body;

    try {
      const resp = await fetch(url, {
        method,
        headers,
        body,
        credentials: "same-origin",
      });
      const html = await resp.text();
      el.innerHTML = html;
    } catch (err) {
      if (options.onError) {
        options.onError(err, el);
      } else {
        console.error("partials.swap error", url, err);
      }
    }
  }

  function poll(selector, url, intervalMs, stopWhen) {
    const el = resolveEl(selector);

    if (!el) {
      return;
    }

    const timer = setInterval(async function () {
      try {
        const resp = await fetch(url, {
          headers: { "X-CSRF-Token": csrfToken() },
          credentials: "same-origin",
        });
        const html = await resp.text();
        el.innerHTML = html;

        if (stopWhen && stopWhen(el)) {
          clearInterval(timer);
        }
      } catch (err) {
        console.error("partials.poll error", url, err);
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
    const form = resolveEl(formSelector);

    if (!form) {
      return;
    }

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      handler(new FormData(form), form);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    // Cross-tab logout: another tab clearing the key material is our cue to
    // redirect this tab to /login as well.
    window.addEventListener("storage", function (e) {
      if (e.key === "rookery_swk" && e.newValue === null) {
        window.location.href = "/login";
      }
    });

    // Key material is cleared inline rather than via the crypto module, so
    // logout still works if the crypto code threw during load.
    document.querySelectorAll('[data-action="logout"]').forEach(function (el) {
      el.addEventListener("click", async function (e) {
        e.preventDefault();

        try {
          localStorage.removeItem("rookery_swk");
          localStorage.removeItem("rookery_swb");
          localStorage.removeItem("rookery_sfp");
        } catch (_) {
          /* localStorage may be unavailable; log out regardless */
        }

        await fetch("/api/v1/auth/logout", {
          method: "POST",
          headers: { "X-CSRF-Token": csrfToken() },
          credentials: "same-origin",
        });
        window.location.href = "/login";
      });
    });
  });

  global.partials = { swap, poll, debounce, onSubmit };
})(window);
