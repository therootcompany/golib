const App = {
  myIpMode: false,

  submit(event) {
    event.preventDefault();
    const input = event.target.querySelector('[data-input]');
    const host = input.value.trim();
    this.check(host);
  },

  check(host) {
    const btn = document.querySelector('[data-submit-btn]');
    btn.disabled = true;
    this.clearState();
    document.querySelector('[data-state="loading"]').hidden = false;
    this.myIpMode = host === '';

    fetch('/check?host=' + encodeURIComponent(host) + '&format=json')
      .then(function(r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function(data) {
        document.querySelector('[data-state="loading"]').hidden = true;
        document.querySelector('[data-state="result"]').hidden = false;
        App.render(data);
      })
      .catch(function(err) {
        document.querySelector('[data-state="loading"]').hidden = true;
        document.querySelector('[data-state="error"]').hidden = false;
        document.querySelector('[data-error-text]').textContent = err.message;
      })
      .finally(function() {
        btn.disabled = false;
      });
  },

  clearState() {
    document.querySelector('[data-state="result"]').hidden = true;
    document.querySelector('[data-state="error"]').hidden = true;
    document.querySelectorAll('[data-verdict]').forEach(function(el) { el.hidden = true; });
    document.querySelectorAll('[data-section]').forEach(function(el) { el.hidden = true; });
    document.querySelectorAll('[data-trait]').forEach(function(el) { el.hidden = true; });
    document.querySelectorAll('[data-block]').forEach(function(el) { el.hidden = true; });
    document.querySelector('[data-resolved-from]').hidden = true;
  },

  render(data) {
    /* ── Verdict ──────────────────────────────────────────── */
    document.querySelectorAll('[data-verdict]').forEach(function(el) { el.hidden = true; });
    var verdictKey = 'allowed';
    if (data.allowlisted) {
      verdictKey = 'whitelist';
    } else if (data.blocked_inbound && data.blocked_outbound) {
      verdictKey = 'blocked-inbound-outbound';
    } else if (data.blocked_inbound) {
      verdictKey = 'blocked-inbound';
    } else if (data.blocked_outbound) {
      verdictKey = 'blocked-outbound';
    }
    document.querySelector('[data-verdict="' + verdictKey + '"]').hidden = false;

    /* ── IP address ───────────────────────────────────────── */
    document.querySelector('[data-value="ip"]').textContent = data.ip;

    /* ── Resolved from ────────────────────────────────────── */
    if (data.resolved_from) {
      document.querySelector('[data-value="resolved-from"]').textContent = data.resolved_from;
      document.querySelector('[data-resolved-from]').hidden = false;
    }

    /* ── Geo ──────────────────────────────────────────────── */
    var geo = data.geo || {};

    /* Location */
    var locParts = [];
    if (geo.city) locParts.push(geo.city);
    if (geo.region) {
      locParts.push(geo.region + (geo.region_iso ? ' (' + geo.region_iso + ')' : ''));
    } else if (geo.region_iso) {
      locParts.push(geo.region_iso);
    }
    if (geo.country) {
      locParts.push(geo.country + (geo.country_iso ? ' (' + geo.country_iso + ')' : ''));
    }
    if (geo.continent) {
      locParts.push(geo.continent + (geo.continent_code ? ' (' + geo.continent_code + ')' : ''));
    }
    if (locParts.length) {
      document.querySelector('[data-value="location"]').textContent = locParts.join(', ');
      document.querySelector('[data-section="location"]').hidden = false;
    }

    /* Coordinates */
    if (geo.latitude || geo.longitude) {
      document.querySelector('[data-value="coordinates"]').textContent =
        geo.latitude.toFixed(4) + ', ' + geo.longitude.toFixed(4);
      document.querySelector('[data-section="coordinates"]').hidden = false;
    }

    /* Details */
    var detailParts = [];
    if (geo.postal_code) detailParts.push(geo.postal_code);
    if (geo.timezone) detailParts.push(geo.timezone);
    if (geo.metro_code) detailParts.push('Metro ' + String(geo.metro_code));
    if (geo.accuracy_radius) detailParts.push('±' + String(geo.accuracy_radius) + 'km');
    if (detailParts.length) {
      document.querySelector('[data-value="details"]').textContent = detailParts.join(' ');
      document.querySelector('[data-section="details"]').hidden = false;
    }

    /* Traits */
    var traitMap = {
      anycast: 'anycast',
      anonymous: 'anonymous_proxy',
      satellite: 'satellite',
      eu: 'country_in_eu'
    };
    var hasTraits = false;
    var traitKeys = Object.keys(traitMap);
    for (var i = 0; i < traitKeys.length; i++) {
      if (geo[traitMap[traitKeys[i]]]) {
        document.querySelector('[data-trait="' + traitKeys[i] + '"]').hidden = false;
        hasTraits = true;
      }
    }
    if (hasTraits) {
      document.querySelector('[data-section="traits"]').hidden = false;
    }

    /* Registered country */
    if (geo.registered_country) {
      var rcParts = geo.registered_country +
        (geo.registered_country_iso ? ' (' + geo.registered_country_iso + ')' : '');
      document.querySelector('[data-value="registered-country"]').textContent = rcParts;
      document.querySelector('[data-section="registered-country"]').hidden = false;
    }

    /* ASN */
    if (geo.asn) {
      document.querySelector('[data-value="asn"]').textContent =
        'AS' + geo.asn + ' ' + (geo.asn_org || '');
    } else {
      document.querySelector('[data-value="asn"]').textContent = '—';
    }

    /* Blocklist */
    var hasBlock = false;
    if (data.blocked_inbound) {
      document.querySelector('[data-block="inbound"]').hidden = false;
      hasBlock = true;
    }
    if (data.blocked_outbound) {
      document.querySelector('[data-block="outbound"]').hidden = false;
      hasBlock = true;
    }
    if (!hasBlock) {
      document.querySelector('[data-block="clean"]').hidden = false;
    }
  },

  toggleIpInfo(event) {
    event.preventDefault();
    var link = document.querySelector('[data-my-ip-link]');
    if (this.myIpMode) {
      document.querySelector('[data-state="result"]').hidden = true;
      link.textContent = 'Show my IP Info';
      this.myIpMode = false;
    } else {
      link.textContent = 'Hide my IP Info';
      this.check('');
    }
  },

  init() {
    var host = new URLSearchParams(window.location.search).get('host');
    if (!host) {
      var hashQuery = window.location.hash.split('?')[1];
      if (hashQuery) {
        host = new URLSearchParams(hashQuery).get('host');
      }
    }
    if (host) {
      document.querySelector('[data-input]').value = host;
      this.check(host);
    } else {
      document.querySelector('[data-input]').focus();
    }
  }
};

App.init();
