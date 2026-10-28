# Changelog

## 0.1.1

- **KEV trends scoped to detected software.** CISA KEV matching now uses the
  products actually present on the host (via each plugin's `kev_terms`) instead
  of a broad built-in keyword list, so results no longer include appliances and
  products the host doesn't run (Fortinet, Cisco, Citrix, VMware, ...).
- Plugins gained an optional `kev_terms` attribute; `plugin.detected_kev_terms()`
  collects terms for present services.
- `trends` output and the HTML report now state that matches are name-level and
  that version applicability must be confirmed per CVE.

## 0.1.0

- Initial public release.
