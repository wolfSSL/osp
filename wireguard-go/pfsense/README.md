# wolfGuard-go on pfSense

This directory contains what is needed to run WolfGuard-go (the wolfCrypt port
of wireguard-go in the parent directory) on a pfSense firewall, managed from
the pfSense web interface:

- `build-freebsd.sh` builds `wolfguard-go` and the `wg-fips` tool on FreeBSD.
- `pkg/` contains `pfSense-pkg-wolfGuard`, a pfSense package that adds
  **VPN > wolfGuard** and **Status > wolfGuard** pages, starts the tunnels at
  boot, and applies the system settings wolfguard-go needs.
- `pkg/make-pkg.sh` builds the package file without needing the pfSense ports
  tree.

WolfGuard replaces WireGuard's cryptography with FIPS-approved algorithms
(ECC P-256, AES-256-GCM, SHA-256). A wolfGuard tunnel on pfSense works with the
wolfGuard Linux kernel module (<https://github.com/wolfssl/wolfguard>), with
wolfguard-go on other systems, and with other wolfGuard peers. It does **not**
work with WireGuard peers, and pfSense's own WireGuard package cannot manage it.

## Tested configuration

| Component | Version |
|-----------|---------|
| pfSense | CE 2.9.0 (FreeBSD 16.0-CURRENT), amd64, 2 vCPU VM on Proxmox VE 9.2 |
| Build host | FreeBSD 16.0-CURRENT VM snapshot 2026-11-09, Go 1.27 |
| wireguard-go | tag `0.0.20250522` with `Wireguard-Go-FIPS-wolfCrypt-port.patch` |
| wolfSSL | master (non-FIPS), `--enable-sp-asm --enable-intelasm` |
| Peer | Debian 13, wolfGuard kernel module and `wg-fips` |

Throughput through the tunnel, iperf3 from a host behind pfSense to the peer
(Intel i5-9500T host, pfSense limited to 2 vCPUs):

| Direction | Throughput |
|-----------|-----------|
| LAN host to peer | about 990 Mbit/s |
| Peer to LAN host | about 1100 Mbit/s |

At this rate pfSense's CPUs are about 90% busy, roughly half of it in system
calls: wireguard-go on FreeBSD handles one packet per system call. More vCPUs
should help but have not been measured.

FIPS: the scripts accept a wolfSSL FIPS bundle (see below), but a FIPS build
has not been tested on pfSense yet.

## 1. Prepare a FreeBSD build host

pfSense does not include a compiler, so the binaries are built on a separate
FreeBSD system. It must run the same FreeBSD major version as your pfSense
release, because the binaries link against the FreeBSD base system libraries.
Check the version on pfSense (Diagnostics > Command Prompt, or the shell):

```
freebsd-version -k
```

pfSense CE 2.9.0 reports `16.0-CURRENT`. A FreeBSD 16.0-CURRENT VM image from
<https://download.freebsd.org/snapshots/VM-IMAGES/16.0-CURRENT/amd64/Latest/>
works. Give it 4 CPUs, 8 GB RAM and 40 GB of disk, network access, and a user
that can run `sudo`.

## 2. Build wolfguard-go and wg-fips

Copy this repository's `wireguard-go` directory to the build host, then run
the build script from an empty directory:

```
mkdir build && cd build
/path/to/osp/wireguard-go/pfsense/build-freebsd.sh
```

The script:

1. Installs the build tools (`go`, `git`, `autoconf`, `automake`, `libtool`,
   `gmake`, `bash`, `pkgconf`).
2. Builds two static wolfSSL libraries:
   - `/opt/wolfssl` for wolfguard-go:
     `--enable-sp="yes, 256" --enable-sp-asm --enable-intelasm`
   - `/opt/wolfssl-wg` for wg-fips: `--enable-wolfguard --enable-intelasm`
3. Applies `Wireguard-Go-FIPS-wolfCrypt-port.patch` to wireguard-go
   `0.0.20250522`, builds it against go-wolfssl, and runs the `device` unit
   tests. The UAPI socket directory is set to `/var/run/wolfguard` so that
   `wg-fips` can find it.
4. Builds `wg-fips` from the wolfguard repository.

`wg-fips` needs the fix in
[wolfSSL/wolfGuard#33](https://github.com/wolfSSL/wolfGuard/pull/33) to
configure wolfguard-go (see [Known issues](#known-issues)). Until that is
merged, build from its branch:

```
WOLFGUARD_REPO=https://github.com/LinuxJedi/wolfguard.git \
WOLFGUARD_REF=wg-fips-uapi-set-reply \
    /path/to/osp/wireguard-go/pfsense/build-freebsd.sh
```

The binaries are written to `./out`. They are statically linked against
wolfSSL and only depend on FreeBSD base libraries (`ldd` is printed at the
end). `--enable-intelasm` requires a CPU with AES-NI and AVX2; leave it out of
the script for other x86-64 CPUs.

To build against a wolfSSL FIPS bundle, unpack and prepare it as described
in the parent `README.md`, then pass it with `-w` and add the FIPS configure
option:

```
WOLFSSL_EXTRA_CONFIGURE="--enable-fips=v5" \
    /path/to/osp/wireguard-go/pfsense/build-freebsd.sh -w /path/to/wolfssl-fips
```

## 3. Build the pfSense package

On the same build host:

```
/path/to/osp/wireguard-go/pfsense/pkg/make-pkg.sh -b out -o pkgout
```

This produces `pkgout/pfSense-pkg-wolfGuard-0.1.0.pkg`, which contains the
package's PHP and GUI files plus the two binaries. Use `-v` to set a different
version.

## 4. Install on pfSense

Enable SSH on pfSense (System > Advanced > Admin Access) if it is not already,
copy the package across and install it:

```
scp pkgout/pfSense-pkg-wolfGuard-0.1.0.pkg admin@<pfsense>:/tmp/
ssh admin@<pfsense>        # choose option 8, Shell
pkg add /tmp/pfSense-pkg-wolfGuard-0.1.0.pkg
```

Installing the package:

- installs `/usr/local/sbin/wolfguard-go` and `/usr/local/bin/wg-fips`;
- adds the **VPN > wolfGuard** and **Status > wolfGuard** menu entries and a
  `wolfguard` entry under **Status > Services**;
- adds an early boot command (`/usr/local/etc/rc.d/wolfguard.sh start`, shown
  under the `earlyshellcmd` setting) so tunnels exist before pfSense
  configures interfaces;
- sets the system tunable `kern.ipc.maxsockbuf` to 16777216 (System >
  Advanced > System Tunables) and applies it immediately.

The package is installed outside the pfSense package manager, so it will not
show under System > Package Manager > Available Packages and is not updated
automatically. Rebuild and reinstall it after upgrading pfSense to a release
based on a newer FreeBSD version.

## 5. Configure a tunnel

### Create the tunnel

1. Go to **VPN > wolfGuard** and click **Add Tunnel**.
2. Leave the private key empty to generate one, set the listen port (51820
   by default) and click **Save**. The tunnel starts immediately as device
   `tun_wolf0`, and its public key is shown. Give that key to the peer.

### Add a peer

1. In the tunnel's page click **Add Peer**.
2. Paste the peer's public key (88 base64 characters, from
   `wg-fips pubkey` on the peer).
3. Set the endpoint address and port if pfSense should connect to the peer,
   or leave it empty if the peer connects to pfSense. Set a keepalive (for
   example 25) if either side is behind NAT.
4. Enter the allowed IPs: the peer's tunnel address (for example
   `10.200.0.2/32`) and any networks behind it.

### Assign the interface

1. Go to **Interfaces > Assignments**, select `tun_wolf0` under
   **Available network ports** and click **Add**.
2. Open the new interface, enable it, set **IPv4 Configuration Type** to
   Static IPv4 and give it the tunnel address (for example `10.200.0.1/24`).
   The package already set the interface MTU to the tunnel MTU (1420); keep
   it.
3. Save and apply.

For networks behind the peer beyond the tunnel subnet, add a gateway on the
wolfGuard interface pointing at the peer's tunnel address and a static route
under **System > Routing**. wolfguard-go does not add routes itself.

### Firewall rules

- **WAN**: pass UDP to the WAN address on the listen port, from the peer's
  public address (only needed when the peer connects to pfSense).
- **The wolfGuard interface**: pass the traffic you want to allow from the
  tunnel, for example source `WOLFGUARD subnets`, destination any.

If WAN is on a private network (as in a lab), also untick **Block private
networks** and **Block bogon networks** on the WAN interface, or the peer's
packets are dropped.

### Example peer: Linux with the wolfGuard kernel module

Install the kernel module and `wg-fips` as described in the wolfguard
repository, then create `/etc/wolfguard/wg0.conf` on the Linux peer:

```
[Interface]
PrivateKey = <output of wg-fips genkey>
Address = 10.200.0.2/24
ListenPort = 51820

[Peer]
PublicKey = <public key shown on the pfSense tunnel page>
Endpoint = <pfSense WAN address>:51820
AllowedIPs = 10.200.0.1/32, <LAN subnet behind pfSense>
PersistentKeepalive = 25
```

and start it with `systemctl enable --now wg-fips-quick@wg0`. Use the public
key of this private key (`wg-fips pubkey < private.key`) as the peer key on
pfSense.

## Status and troubleshooting

- **Status > wolfGuard** shows each tunnel's state, its peers, the time of
  the latest handshake and transfer counters.
- From the pfSense shell, `wg-fips show` gives the same information, and
  `wg-fips set` / `wg-fips showconf` work as with WireGuard's `wg`.
- The daemon logs errors to `/var/log/wolfguard.log`; package errors go to the
  system log.
- The generated per-tunnel configuration is in
  `/usr/local/etc/wolfguard/tun_wolfN.conf` (mode 0600, rewritten on every
  save). Change settings in the GUI rather than in this file.
- `/usr/local/etc/rc.d/wolfguard.sh restart` restarts all tunnels.

Key formats: `wg-fips` and the GUI use base64, with 32 byte private keys
(44 characters) and 65 byte uncompressed public keys (88 characters). The
wireguard-go UAPI socket uses the same keys in hex.

## pfSense integration notes

These are the pfSense specific problems found while bringing wolfGuard-go up,
and how the package handles them. They matter if you run wolfguard-go on
pfSense without the package.

**Interface names must start with `tun`.** At boot pfSense checks that every
assigned interface exists and, if one is missing, stops at the console
interface assignment prompt. wolfguard-go creates its interface after this
check. pfSense skips the check for names beginning with `tun`, and still lists
`tun_<name>N` devices under Interfaces > Assignments, so the package names its
devices `tun_wolfN`.

**Start wolfguard-go in its own session.** Started directly from an early
boot command, wolfguard-go is terminated (it logs a clean shutdown) shortly
after boot. The package starts it with `daemon(8)`, which detaches it into a
new session.

**UDP socket buffers.** wireguard-go requests 7 MiB socket buffers and ignores
a failure. With pfSense's default `kern.ipc.maxsockbuf` of 4262144 the request
fails, the socket keeps FreeBSD's 42 KB default receive buffer, and incoming
tunnel packets are dropped under load ("dropped due to full socket buffers" in
`netstat -s -p udp`). In testing this halved throughput from the peer to the
LAN. Raising `kern.ipc.maxsockbuf` to 16777216 fixes it. This affects upstream
wireguard-go on FreeBSD as well.

**MTU.** When pfSense configures an assigned interface without an MTU set,
it applies 1500, which makes tunnel packets larger than the WAN MTU after
encapsulation. The package writes the tunnel MTU (1420) into the interface
configuration.

**UAPI socket directory.** wireguard-go puts its control socket in
`/var/run/wireguard`, while `wg-fips` looks in `/var/run/wolfguard`. The build
sets wolfguard-go's directory to `/var/run/wolfguard` at link time, which also
keeps it apart from WireGuard.

**AES-NI.** Without `--enable-intelasm`, wolfSSL's AES-GCM runs in C and the
tunnel is about 35% slower.

## Known issues

- Without [wolfSSL/wolfGuard#33](https://github.com/wolfSSL/wolfGuard/pull/33),
  `wg-fips set` hangs against wolfguard-go, and the package cannot apply
  tunnel settings. `wg-fips` reads the reply with
  `fscanf(f, "errno=%d\n\n", ...)`, whose trailing whitespace directive keeps
  reading until the connection closes, but wireguard-go keeps the UAPI
  connection open after replying.
- Linking `wg-fips` against a static wolfSSL on FreeBSD needs `-lm -lpthread`
  in `LDLIBS`. `build-freebsd.sh` adds it; wolfSSL/wolfGuard#33 also adds it
  to the wolfguard Makefile.
- IPv6 tunnel addresses and endpoints are supported by the package but have
  not been tested.
- There is no dashboard widget, no interface group for rules across all
  wolfGuard tunnels, and no configuration export for peers.

## Removing the package

```
pkg delete pfSense-pkg-wolfGuard
```

This stops all tunnels and removes the early boot command and the tunable the
package added. Tunnel settings stay in the pfSense configuration, so
reinstalling restores them. Remove any interface assignments, routes and
firewall rules that use the tunnels before removing the package.

## Files

```
pfsense/
  README.md                         this file
  build-freebsd.sh                  builds wolfguard-go and wg-fips on FreeBSD
  pkg/
    make-pkg.sh                     builds pfSense-pkg-wolfGuard-<version>.pkg
    pfSense-pkg-wolfGuard/
      LICENSE                       GPLv3
      files/                        installed file tree
        etc/inc/priv/wolfguard.priv.inc         GUI privileges
        usr/local/etc/rc.d/wolfguard.sh         start/stop script
        usr/local/pkg/wolfguard.xml             package definition
        usr/local/pkg/wolfguard/wolfguard.inc   configuration and runtime logic
        usr/local/pkg/wolfguard/wolfguard_gui.inc
        usr/local/pkg/wolfguard/wolfguard_service.php
        usr/local/share/pfSense-pkg-wolfGuard/info.xml
        usr/local/www/shortcuts/pkg_wolfguard.inc  title bar shortcuts
        usr/local/www/wolfguard/*.php           GUI pages
```
