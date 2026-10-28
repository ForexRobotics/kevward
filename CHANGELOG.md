# Changelog

## 0.1.3

- **Python 3.10 support** (Ubuntu 22.04 LTS). The 3.11-only `StrEnum`,
  `tomllib` and `datetime.UTC` are replaced with 3.10-compatible equivalents;
  `tomli` is pulled in automatically on 3.10 only. Tested on 3.10–3.13.
- **New service plugins**: Apache HTTP Server, MySQL, MariaDB, PostgreSQL and
  Redis — apt-managed, with CISA KEV term mapping. Apache also gets a
  ServerTokens hardening check.
- README: documented supported services, the Python requirement and the
  virtualenv/system-path install.

## 0.1.2

- **KEV matching no longer uses the free-text vulnerability name**, only the
  vendor and product. A CVE whose description happens to mention a technology
  (e.g. a Zimbra or Juniper advisory with "PHP" in its name) no longer
  false-matches a host that merely runs that technology.

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
