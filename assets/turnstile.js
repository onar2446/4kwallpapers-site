/* Turnstile challenge glue for the gate page.
 *
 * Why this file exists at all: the site runs under a strict
 * `script-src 'self'` CSP, so the challenge page carries no inline JS. The
 * widget therefore talks to these small, named globals instead:
 *
 *   __tsOk(token)       widget solved        -> unlock the submit button
 *   __tsExpired()       token went stale     -> lock it again
 *   __tsError(code)     widget failed        -> explain, keep it locked
 *
 * Turnstile auto-renders any .cf-turnstile element once api.js loads and, for
 * an enclosing <form>, injects a hidden `cf-turnstile-response` input. We
 * still mirror the token into our own hidden field on submit, so the POST is
 * correct even if the widget's auto-injection ever changes.
 */
(function () {
  "use strict";

  var form = document.getElementById("tsform");
  if (!form) return;

  var button = form.querySelector('button[type="submit"]');
  var token = "";
  var settled = false;

  function setEnabled(on) {
    if (!button) return;
    button.disabled = !on;
    button.style.opacity = on ? "1" : "0.45";
    button.style.cursor = on ? "pointer" : "not-allowed";
  }

  function note(message, isError) {
    var box = document.getElementById("tsnote");
    if (!box) return;
    box.textContent = message;
    box.style.color = isError ? "#9c3138" : "#7a7a7a";
    box.style.display = message ? "block" : "none";
  }

  setEnabled(false);

  window.__tsOk = function (t) {
    settled = true;
    token = t || "";
    setEnabled(!!token);
    note("", false);
  };

  window.__tsExpired = function () {
    token = "";
    setEnabled(false);
    note("انتهت صلاحية التحقق، اعمله تاني من فضلك.", false);
  };

  window.__tsError = function (code) {
    token = "";
    setEnabled(false);
    note("ماقدرناش نحمّل التحقق (" + (code || "خطأ") + "). "
       + "جرّب تحدّث الصفحة، ولو المشكلة كمّلت اتأكد من اتصالك بالإنترنت.", true);
  };

  form.addEventListener("submit", function (ev) {
    if (!token) {
      ev.preventDefault();
      note("استنى لحد ما التحقق يخلص الأول.", true);
      return;
    }
    var field = form.querySelector('input[name="cf-turnstile-response"]');
    if (!field) {
      field = document.createElement("input");
      field.type = "hidden";
      field.name = "cf-turnstile-response";
      form.appendChild(field);
    }
    if (!field.value) field.value = token;
  });

  // If the widget never renders — offline, blocked, or Cloudflare unreachable —
  // the visitor must not be left staring at a dead page with no explanation.
  window.setTimeout(function () {
    if (settled) return;
    var box = document.querySelector(".cf-turnstile");
    var empty = !box || box.childNodes.length === 0;
    if (empty) {
      window.__tsError("انتهت مدة الانتظار");
    }
  }, 15000);
})();
