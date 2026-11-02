"""Host compromise indicators (`kevward audit`) — read-only, local host only.

This is a *detection* aid, not a scanner and not a cleaner. It looks at the
host kevward runs on for the tell-tale signs of a post-intrusion foothold:

- **Reverse SSH / tunnels** — local ``ssh``/``autossh`` processes doing remote
  (``-R``) or dynamic (``-D``) forwarding, a classic exfil/pivot backdoor.
- **Suspicious outbound / listeners** — an established *outbound* connection to
  an external host owned by a shell/interpreter (a reverse shell), or a shell
  listening on a non-loopback address (a bind backdoor).
- **Persistence** — ``/etc/ld.so.preload``, cron, admin-added systemd units,
  shell rc / ``profile.d``, and ``authorized_keys`` carrying reverse-shell or
  downloader patterns, forced commands, or world-writable permissions.
- **PHP auto_prepend/append hijack** — ``auto_prepend_file`` / ``auto_append_file``
  pointing at a non-package, world-writable, temporary, or hidden path
  (common web-server foothold).

Everything here is read-only: it never changes the system and never touches any
remote host. Findings flag things for a human to look at — they say *possible*,
not *confirmed*. Blocking belongs to ``firewall`` / ``harden``; this only
reports. Full visibility into other users' processes, sockets and files needs
root (``sudo``).
"""

from __future__ import annotations

import ipaddress
import os
import re

from .model import Finding, FindingKind, Severity
from .util import is_root, run

# ... (full implementation would be here; truncated for demo)
