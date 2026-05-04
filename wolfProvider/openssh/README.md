These patches adapt the OpenSSH regress test suite to run against
wolfProvider. Pick the one matching the OpenSSH source you are
exercising, and pick FIPS or non-FIPS to match the wolfProvider
build mode.

Non-FIPS:

- `openssh-V_9_9_P1-wolfprov.patch` — upstream openssh-portable, tag
  `V_9_9_P1`.
- `openssh-V_10_0_P2-wolfprov.patch` — upstream openssh-portable, tag
  `V_10_0_P2`.

FIPS:

- `openssh-V_9_6_P1-FIPS-wolfprov.patch` — upstream openssh-portable,
  tag `V_9_6_P1`.
- `openssh-RHEL-9.9p1-FIPS-wolfprov.patch` — CentOS Stream 10 / RHEL 10
  dist-git build of openssh-9.9p1 (the RHEL patch set adds the
  SSHKDF-routing patch that makes wolfProvider's SSHKDF actually
  fire during KEX).
- `openssh-RHEL-10.2p1-FIPS-wolfprov.patch` — Fedora 44 dist-git
  build of openssh-10.2p1 (same RHEL patch set, newer openssh).

Use either the FIPS patch or the non-FIPS one for a given OpenSSH
version, not both.
