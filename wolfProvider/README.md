# wolfProvider OSP patches

Patches that adapt upstream open-source projects (curl, krb5, libssh2,
hostap, etc.) to test cleanly against `wolfProvider` (FIPS and non-FIPS).

## Naming convention

Every patch follows exactly one pattern (no exceptions):

    <project>/<project>-<projver>-wolfprov.patch          (non-FIPS)
    <project>/<project>-<projver>-wolfprov-fips.patch     (FIPS)
    <project>/<project>-<projver>-wolfssl-X.Y.Z-wolfprov.patch       (pinned snapshot)
    <project>/<project>-<projver>-wolfssl-X.Y.Z-wolfprov-fips.patch  (pinned snapshot)

Rules:
- FIPS is always the `-fips` suffix before `.patch` (never an
  uppercase `-FIPS-` infix).
- The provider segment is always `-wolfprov` (never `-wolfprovider`).
- `<projver>` is the upstream version ref the patch targets and may be
  empty for version-agnostic patches.

- **Universal** name (no `-wolfssl-X.Y.Z-` infix) is the **latest**
  patch content. By default a patch should be universal — it tracks
  current wolfSSL master / latest stable and is reused unchanged across
  wolfSSL version bumps.
- `-wolfssl-X.Y.Z-` infix marks a **pinned snapshot** for that wolfSSL
  line. Add one only when the universal patch has diverged in a way
  that breaks on an older wolfSSL release that is still supported.

When you modify a patch for a new wolfSSL release in a way that breaks
an older line:
  1. Copy the pre-modification content as
     `<stem>-wolfssl-<old-version>-wolfprov[-fips].patch`.
  2. Keep editing the universal file for the new wolfSSL release.

## How workflows pick the right patch

`wolfssl/wolfProvider` workflows resolve patches via
`scripts/resolve-osp-patch.sh`:

| wolfssl_ref         | order tried                                |
|---------------------|--------------------------------------------|
| `v5.8.X-stable`     | `-wolfssl-5.8.4-` then universal           |
| `v5.9.X-stable`     | `-wolfssl-5.9.1-` then universal           |
| `master` / other    | universal only                             |

For FIPS, the helper tries `-wolfprov-fips.patch` and falls back to the
non-FIPS patch when no FIPS-specific one exists. Because the naming is
uniform, the helper stays simple — one pattern, no per-project special
cases.
