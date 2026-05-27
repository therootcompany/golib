(function () {
  "use strict";

  function $(sel, $parent) {
    return ($parent || document).querySelector(sel);
  }

  function $$(sel, $parent) {
    return Array.from(($parent || document).querySelectorAll(sel));
  }

  const form      = $(".search-form");
  const input     = $("input[type=\"text\"]", form);
  const btn       = $("button", form);
  const myIpLink  = $("#my-ip-link");
  const loading   = $(".loading");
  const errorEl   = $(".error-msg");
  const resultEl  = $(".result");
  let myIpVisible = false;

  function show(el) { el.classList.add("visible"); }
  function hide(el) { el.classList.remove("visible"); }

  function render(result, isMyIp) {
    hide(errorEl);
    hide(resultEl);
    if (isMyIp) myIpVisible = true;

    const host = result.ip;
    const resolvedFrom = result.resolved_from || "";
    const blocked = result.blocked;
    const blockedIn = result.blocked_inbound;
    const blockedOut = result.blocked_outbound;
    const whitelisted = result.allowlisted;
    const geo = result.geo || {};

    // Verdict
    let verdictClass = "unknown";
    let verdictText = "UNKNOWN";
    if (whitelisted) {
      verdictClass = "whitelist";
      verdictText = "ALLOWED (whitelist)";
    } else if (blocked) {
      verdictClass = "blocked";
      verdictText = "BLOCKED";
    } else {
      verdictClass = "allowed";
      verdictText = "ALLOWED";
    }

    // Geo info
    let geoParts = [];
    if (geo.city) geoParts.push(geo.city);
    if (geo.region) {
      geoParts.push(geo.region + (geo.region_iso ? " (" + geo.region_iso + ")" : ""));
    } else if (geo.region_iso) {
      geoParts.push(geo.region_iso);
    }
    if (geo.country) {
      geoParts.push(geo.country + (geo.country_iso ? " (" + geo.country_iso + ")" : ""));
    }
    if (geo.continent) {
      geoParts.push(geo.continent + (geo.continent_code ? " (" + geo.continent_code + ")" : ""));
    }
    let geoStr = geoParts.length ? geoParts.join(", ") : "—";
    let latLonStr = "";
    if (geo.latitude || geo.longitude) {
      latLonStr = geo.latitude.toFixed(4) + ", " + geo.longitude.toFixed(4);
    }
    let asnStr = geo.asn ? "AS" + geo.asn + " " + (geo.asn_org || "") : "—";
    let postalStr = geo.postal_code || "";
    let tzStr = geo.timezone || "";
    let metroStr = geo.metro_code ? String(geo.metro_code) : "";
    let accuracyStr = geo.accuracy_radius ? String(geo.accuracy_radius) : "";
    let registeredStr = geo.registered_country ? (geo.registered_country + (geo.registered_country_iso ? " (" + geo.registered_country_iso + ")" : "")) : "";

    // Trait badges
    let traitBadges = "";
    if (geo.anycast) {
      traitBadges += '<span class="trait-badge anycast">anycast</span>';
    }
    if (geo.anonymous_proxy) {
      traitBadges += '<span class="trait-badge anonymous">anonymous proxy</span>';
    }
    if (geo.satellite) {
      traitBadges += '<span class="trait-badge satellite">satellite</span>';
    }
    if (geo.country_in_eu) {
      traitBadges += '<span class="trait-badge eu">EU</span>';
    }

    // Block details
    let blockHtml = "";
    if (blockedIn || blockedOut) {
      const parts = [];
      if (blockedIn) parts.push("inbound");
      if (blockedOut) parts.push("outbound");
      blockHtml = '<span class="block-badge">BLOCKED: ' + parts.join(" + ") + '</span>';
    } else {
      blockHtml = '<span class="block-badge clean">clean</span>';
    }

    resultEl.innerHTML =
      '<div class="result-header">' +
        '<span class="verdict ' + verdictClass + '">' + verdictText + '</span>' +
        '<span class="host">' + escapeHtml(host) + '</span>' +
        (resolvedFrom ? '<span class="resolved">→ ' + escapeHtml(resolvedFrom) + '</span>' : '') +
      '</div>' +
      '<div class="result-body">' +
        (geoStr !== "—" ?
          '<div class="result-section">' +
            '<h3>Location</h3>' +
            '<p class="mono">' + escapeHtml(geoStr) + '</p>' +
          '</div>' : '') +
        (latLonStr ?
          '<div class="result-section">' +
            '<h3>Coordinates</h3>' +
            '<p class="mono">' + escapeHtml(latLonStr) + '</p>' +
          '</div>' : '') +
        (postalStr || tzStr || metroStr || accuracyStr ?
          '<div class="result-section">' +
            '<h3>Details</h3>' +
            '<p class="mono">' +
              (postalStr ? escapeHtml(postalStr) + " " : "") +
              (tzStr ? escapeHtml(tzStr) + " " : "") +
              (metroStr ? "Metro " + escapeHtml(metroStr) + " " : "") +
              (accuracyStr ? "±" + escapeHtml(accuracyStr) + "km" : "") +
            '</p>' +
          '</div>' : '') +
        (traitBadges ?
          '<div class="result-section">' +
            '<h3>Traits</h3>' +
            '<div class="block-list">' + traitBadges + '</div>' +
          '</div>' : '') +
        (registeredStr ?
          '<div class="result-section">' +
            '<h3>Registered Country</h3>' +
            '<p class="mono">' + escapeHtml(registeredStr) + '</p>' +
          '</div>' : '') +
        '<div class="result-section">' +
          '<h3>ASN</h3>' +
          '<p class="mono">' + escapeHtml(asnStr) + '</p>' +
        '</div>' +
        '<div class="result-section">' +
          '<h3>Blocklist</h3>' +
          '<div class="block-list">' + blockHtml + '</div>' +
        '</div>' +
      '</div>';

    show(resultEl);
  }

  function escapeHtml(s) {
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }

  function submitHost(host) {
    hide(errorEl);
    hide(resultEl);
    show(loading);
    btn.disabled = true;
    var isMyIp = host === "";

    fetch("/check?host=" + encodeURIComponent(host) + "&format=json")
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (data) {
        hide(loading);
        render(data, isMyIp);
      })
      .catch(function (err) {
        hide(loading);
        errorEl.textContent = "Error: " + err.message;
        show(errorEl);
      })
      .finally(function () {
        btn.disabled = false;
      });
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    submitHost(input.value.trim());
  });

  myIpLink.addEventListener("click", function (e) {
    e.preventDefault();
    if (myIpVisible) {
      hide(resultEl);
      myIpLink.textContent = "Show my IP Info";
      myIpVisible = false;
    } else {
      myIpLink.textContent = "Hide my IP Info";
      submitHost("");
    }
  });

  // Pre-fill from URL query param or hash fragment and auto-submit
  (function init() {
    let host = new URLSearchParams(window.location.search).get("host");
    // Also check hash fragment (e.g. /#/?host=google.com)
    if (!host) {
      const hashQuery = window.location.hash.split("?")[1];
      if (hashQuery) {
        host = new URLSearchParams(hashQuery).get("host");
      }
    }
    if (host) {
      input.value = host;
      submitHost(host);
    }
    // Focus input on load (only if no auto-submit triggered)
    if (!host) {
      input.focus();
    }
  })();
})();
