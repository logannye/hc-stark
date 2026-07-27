(() => {
  "use strict";

  // Every number rendered by this file comes verbatim from the JSON body
  // `POST /v1/estimate` returns (itself the untouched output of the
  // compiled Rust cost model, `estimate_json` — see site/_worker.js). This
  // file never recomputes, rounds, clamps, or unit-converts a single figure
  // from that response; the only arithmetic below is choosing which of the
  // response's own fields to render, and building the OUTGOING request from
  // form fields (never touching a result).
  const FIELD_EXTENSION_DEGREE = {
    goldilocks: 2,
    babybear: 4,
    koalabear: 4,
    mersenne31: 4,
  };

  const form = document.querySelector("[data-estimate-form]");
  if (!form) return;

  const extensionDegreeField = form.querySelector("[data-extension-degree]");
  const configJson = document.querySelector("[data-config-json]");
  const keyField = document.querySelector("[data-estimate-key]");
  const output = document.querySelector("[data-estimate-output]");
  const numberFormat = new Intl.NumberFormat("en-US");

  function fieldValue(selector) {
    return form.querySelector(selector).value;
  }

  function checkboxValue(selector) {
    return form.querySelector(selector).checked;
  }

  function currentRequest() {
    const field = fieldValue("[data-field-select]");
    return {
      schema_version: 1,
      field,
      extension_degree: FIELD_EXTENSION_DEGREE[field] || 2,
      logical_rows: Number(fieldValue("[data-logical-rows]")),
      trace_width: Number(fieldValue("[data-trace-width]")),
      max_constraint_degree: Number(fieldValue("[data-max-constraint-degree]")),
      public_values: Number(fieldValue("[data-public-values]")),
      has_next_row_columns: checkboxValue("[data-has-next-row-columns]"),
      features: {
        uses_lookups: checkboxValue("[data-uses-lookups]"),
        uses_buses: checkboxValue("[data-uses-buses]"),
        uses_permutations: checkboxValue("[data-uses-permutations]"),
        uses_multi_table: checkboxValue("[data-uses-multi-table]"),
        uses_preprocessed_columns: checkboxValue("[data-uses-preprocessed-columns]"),
        uses_periodic_columns: checkboxValue("[data-uses-periodic-columns]"),
        uses_recursion: checkboxValue("[data-uses-recursion]"),
        uses_gpu: checkboxValue("[data-uses-gpu]"),
      },
      ram_budget_bytes: Number(fieldValue("[data-ram-budget-bytes]")),
    };
  }

  // Keeps the "equivalent CLI one-liner" block byte-for-byte in sync with
  // whatever the fetch call below is about to send — copy-pasting it into a
  // local `job.json` and running `tinyzkp-engine estimate --config job.json`
  // must reproduce the exact request this page just submitted.
  function updatePreview() {
    if (extensionDegreeField) {
      extensionDegreeField.value = String(FIELD_EXTENSION_DEGREE[fieldValue("[data-field-select]")] || 2);
    }
    if (configJson) {
      configJson.textContent = JSON.stringify(currentRequest(), null, 2);
    }
  }

  form.addEventListener("input", updatePreview);
  updatePreview();

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function renderEstimate(body) {
    if (!output) return;
    output.hidden = false;
    const parts = [];
    parts.push(
      `<p><strong>provable_today:</strong> ${body.provable_today ? "true" : "false"}` +
        (body.provable_today ? "" : " — see the blocking reason(s) below; the estimate is still real.") +
        "</p>",
    );
    if (Array.isArray(body.blocking_reasons) && body.blocking_reasons.length > 0) {
      parts.push(
        "<ul>" +
          body.blocking_reasons
            .map(
              (reason) =>
                `<li><code>${escapeHtml(reason.code)}</code> — ${escapeHtml(reason.summary)} ` +
                `<a href="/troubleshooting#${encodeURIComponent(reason.code)}">Why</a></li>`,
            )
            .join("") +
          "</ul>",
      );
    }
    if (body.estimates && body.estimates.conventional && body.estimates.bounded) {
      parts.push(
        '<div class="table-wrap"><table><thead><tr><th>Plan</th><th>Peak resident bytes</th>' +
          "<th>Scratch high-water bytes</th><th>Total read bytes</th></tr></thead><tbody>" +
          ["conventional", "bounded"]
            .map((plan) => {
              const est = body.estimates[plan];
              return (
                `<tr><td>${plan}</td><td>${numberFormat.format(est.peak_resident_bytes)}</td>` +
                `<td>${numberFormat.format(est.scratch_high_water_bytes)}</td>` +
                `<td>${numberFormat.format(est.total_read_bytes)}</td></tr>`
              );
            })
            .join("") +
          "</tbody></table></div>",
      );
    }
    if (typeof body.request_digest === "string") {
      parts.push(`<p class="subtle">request_digest: <code>${escapeHtml(body.request_digest)}</code></p>`);
    }
    output.innerHTML = parts.join("");
  }

  function renderNotice(className, message) {
    if (!output) return;
    output.hidden = false;
    output.innerHTML = `<div class="notice ${className}"><strong>${className === "danger" ? "Error:" : "Note:"}</strong> ${escapeHtml(message)}</div>`;
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const request = currentRequest();
    const headers = { "Content-Type": "application/json" };
    const key = keyField ? keyField.value.trim() : "";
    if (key) headers.Authorization = `Bearer ${key}`;

    if (output) {
      output.hidden = false;
      output.innerHTML = "<p>Estimating…</p>";
    }

    fetch("/v1/estimate", { method: "POST", headers, body: JSON.stringify(request) })
      .then((response) => response.json().then((body) => ({ status: response.status, body })))
      .then(({ status, body }) => {
        if (status === 429) {
          renderNotice("danger", "Rate limit reached for this hour. Mint a free key below for a higher ceiling, or try again next hour.");
          return;
        }
        if (status === 401) {
          renderNotice("danger", "That key is invalid or unknown. Clear the key field to fall back to the anonymous limit, or mint a new key below.");
          return;
        }
        if (body && body.ok === false && body.error) {
          const summary = body.error.reason && body.error.reason.summary ? body.error.reason.summary : "The request was rejected.";
          renderNotice("danger", summary);
          return;
        }
        renderEstimate(body);
      })
      .catch(() => renderNotice("danger", "The request failed. Check your connection and try again."));
  });

  // --- Free key minting ---------------------------------------------
  const keyForm = document.querySelector("[data-key-form]");
  const keyResult = document.querySelector("[data-key-result]");
  if (keyForm) {
    keyForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const email = keyForm.querySelector("[data-key-email]").value.trim();
      if (!keyResult) return;
      keyResult.hidden = false;
      keyResult.innerHTML = "<p>Requesting…</p>";
      fetch("/v1/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      })
        .then((response) => response.json().then((body) => ({ status: response.status, body })))
        .then(({ status, body }) => {
          if (status !== 200 || !body || body.ok !== true || typeof body.key !== "string") {
            const reason = body && typeof body.error === "string" ? body.error : "request_failed";
            keyResult.innerHTML = `<div class="notice danger"><strong>Could not mint a key:</strong> ${escapeHtml(reason)}.</div>`;
            return;
          }
          keyResult.innerHTML = [
            '<div class="notice good"><strong>Save this now — it will not be shown again.</strong> ',
            "We store a hash of it, never the key itself, and we never store your email.</div>",
            `<div class="key-output"><code>${escapeHtml(body.key)}</code></div>`,
            `<p class="subtle">Raises your hourly limit to ${numberFormat.format(body.rate_limit_per_hour)} requests. It has been filled into the key field above.</p>`,
          ].join("");
          if (keyField) keyField.value = body.key;
        })
        .catch(() => {
          keyResult.innerHTML = '<div class="notice danger"><strong>Request failed.</strong> Check your connection and try again.</div>';
        });
    });
  }
})();
