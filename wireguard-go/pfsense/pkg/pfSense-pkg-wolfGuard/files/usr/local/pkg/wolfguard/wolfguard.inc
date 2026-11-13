<?php
/*
 * wolfguard.inc
 *
 * pfSense integration for wolfGuard-go, the FIPS 140-3 oriented userspace
 * WolfGuard VPN daemon built from wireguard-go and wolfCrypt.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

require_once("config.inc");
require_once("globals.inc");
require_once("interfaces.inc");
require_once("util.inc");
require_once("service-utils.inc");

define('WOLFGUARD_DAEMON', '/usr/local/sbin/wolfguard-go');
define('WOLFGUARD_TOOL', '/usr/local/bin/wg-fips');
define('WOLFGUARD_CONF_DIR', '/usr/local/etc/wolfguard');
define('WOLFGUARD_RUN_DIR', '/var/run/wolfguard');
define('WOLFGUARD_LOG', '/var/log/wolfguard.log');
define('WOLFGUARD_CONFIG_PATH', 'installedpackages/wolfguard');
define('WOLFGUARD_IF_PREFIX', 'tun_wolf');
define('WOLFGUARD_DEFAULT_PORT', 51820);
define('WOLFGUARD_DEFAULT_MTU', 1420);
define('WOLFGUARD_EARLYSHELLCMD', '/usr/local/etc/rc.d/wolfguard.sh start');
/*
 * wireguard-go asks for 7 MiB UDP socket buffers and silently ignores a
 * failure. The pfSense default kern.ipc.maxsockbuf (about 4 MiB) makes the
 * request fail, leaving a 42 KB receive buffer that drops packets under load.
 */
define('WOLFGUARD_MAXSOCKBUF', 16777216);
define('WOLFGUARD_SYSCTL_DESCR', 'wolfGuard: allow 7 MiB UDP socket buffers for wolfguard-go');

/* P-256: 32 byte private scalar, 65 byte uncompressed public point. */
define('WOLFGUARD_PRIVKEY_LEN', 32);
define('WOLFGUARD_PUBKEY_LEN', 65);
define('WOLFGUARD_PSK_LEN', 32);

/* ------------------------------------------------------------------------
 * Configuration access
 * --------------------------------------------------------------------- */

function wolfguard_get_tunnels() {
	$tunnels = config_get_path(WOLFGUARD_CONFIG_PATH . '/tunnels/item', []);
	if (!is_array($tunnels)) {
		return [];
	}
	foreach ($tunnels as &$t) {
		if (!is_array($t['peers']['item'] ?? null)) {
			$t['peers'] = ['item' => []];
		}
	}
	return $tunnels;
}

function wolfguard_set_tunnels($tunnels, $desc) {
	config_set_path(WOLFGUARD_CONFIG_PATH . '/tunnels/item', array_values($tunnels));
	write_config($desc);
}

function wolfguard_next_ifname($tunnels) {
	$used = array_column($tunnels, 'name');
	for ($i = 0; ; $i++) {
		if (!in_array(WOLFGUARD_IF_PREFIX . $i, $used)) {
			return WOLFGUARD_IF_PREFIX . $i;
		}
	}
}

/* Friendly pfSense interface name (e.g. "opt1") if assigned, else NULL. */
function wolfguard_assigned_friendly($ifname) {
	foreach (config_get_path('interfaces', []) as $friendly => $ifcfg) {
		if (($ifcfg['if'] ?? '') == $ifname) {
			return $friendly;
		}
	}
	return NULL;
}

/* ------------------------------------------------------------------------
 * Keys
 * --------------------------------------------------------------------- */

function wolfguard_b64_len($b64) {
	$raw = base64_decode(trim($b64), true);
	return ($raw === false) ? -1 : strlen($raw);
}

function wolfguard_valid_privkey($b64) {
	return wolfguard_b64_len($b64) == WOLFGUARD_PRIVKEY_LEN;
}

function wolfguard_valid_pubkey($b64) {
	$raw = base64_decode(trim($b64), true);
	return ($raw !== false) && (strlen($raw) == WOLFGUARD_PUBKEY_LEN) &&
	    (ord($raw[0]) == 0x04);
}

function wolfguard_valid_psk($b64) {
	return wolfguard_b64_len($b64) == WOLFGUARD_PSK_LEN;
}

/*
 * Run wg-fips with optional stdin, return trimmed stdout or false. The
 * timeout keeps a misbehaving wg-fips (for example one without the UAPI
 * reply fix from wolfSSL/wolfGuard#33) from hanging the GUI.
 */
function wolfguard_tool($args, $stdin = NULL) {
	$cmd = '/usr/bin/timeout 10 ' . WOLFGUARD_TOOL . ' ' . $args;
	$desc = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
	$proc = proc_open($cmd, $desc, $pipes);
	if (!is_resource($proc)) {
		return false;
	}
	if ($stdin !== NULL) {
		fwrite($pipes[0], $stdin);
	}
	fclose($pipes[0]);
	$out = stream_get_contents($pipes[1]);
	$err = stream_get_contents($pipes[2]);
	fclose($pipes[1]);
	fclose($pipes[2]);
	$rc = proc_close($proc);
	if ($rc != 0) {
		log_error("wolfGuard: wg-fips {$args} failed: " . trim($err));
		return false;
	}
	return trim($out);
}

function wolfguard_genkey() {
	return wolfguard_tool('genkey');
}

function wolfguard_genpsk() {
	return wolfguard_tool('genpsk');
}

function wolfguard_pubkey($privkey) {
	return wolfguard_tool('pubkey', trim($privkey) . "\n");
}

/* ------------------------------------------------------------------------
 * Validation helpers shared by the GUI pages
 * --------------------------------------------------------------------- */

function wolfguard_split_list($str) {
	$items = preg_split('/[\s,]+/', trim((string)$str), -1, PREG_SPLIT_NO_EMPTY);
	return array_values(array_unique($items));
}

/*
 * True if array index $i is the entry being edited. $id is NULL for a new
 * entry; a plain "$i != $id" would treat index 0 as equal to NULL.
 */
function wolfguard_same_index($i, $id) {
	return ($id !== NULL) && ((string)$i === (string)$id);
}

function wolfguard_validate_tunnel($t, $id, $tunnels) {
	$errors = [];
	if (!is_port($t['listenport'] ?? '')) {
		$errors[] = gettext("The listen port must be a port number between 1 and 65535.");
	}
	foreach ($tunnels as $i => $other) {
		if (!wolfguard_same_index($i, $id) &&
		    ($other['listenport'] ?? '') == ($t['listenport'] ?? '')) {
			$errors[] = sprintf(gettext("Listen port %s is already used by %s."),
			    $t['listenport'], $other['name']);
		}
	}
	if (!wolfguard_valid_privkey($t['privatekey'] ?? '')) {
		$errors[] = gettext("The private key must be a base64 encoded 32 byte P-256 key, as produced by wg-fips genkey.");
	}
	$mtu = $t['mtu'] ?? '';
	if ($mtu !== '' && (!is_numericint($mtu) || $mtu < 1280 || $mtu > 9000)) {
		$errors[] = gettext("The MTU must be between 1280 and 9000.");
	}
	foreach (wolfguard_split_list($t['addresses'] ?? '') as $addr) {
		if (!is_subnet($addr)) {
			$errors[] = sprintf(gettext("%s is not a valid address in CIDR notation."), $addr);
		}
	}
	return $errors;
}

function wolfguard_validate_peer($p, $id, $peers) {
	$errors = [];
	if (!wolfguard_valid_pubkey($p['publickey'] ?? '')) {
		$errors[] = gettext("The public key must be a base64 encoded 65 byte uncompressed P-256 key, as produced by wg-fips pubkey.");
	}
	foreach ($peers as $i => $other) {
		if (!wolfguard_same_index($i, $id) &&
		    trim($other['publickey']) == trim($p['publickey'] ?? '')) {
			$errors[] = gettext("Another peer on this tunnel already uses this public key.");
		}
	}
	if (($p['presharedkey'] ?? '') !== '' && !wolfguard_valid_psk($p['presharedkey'])) {
		$errors[] = gettext("The pre-shared key must be a base64 encoded 32 byte key, as produced by wg-fips genpsk.");
	}
	if (($p['endpoint'] ?? '') !== '') {
		if (!is_ipaddr($p['endpoint']) && !is_hostname($p['endpoint'])) {
			$errors[] = gettext("The endpoint must be an IP address or hostname.");
		}
		if (!is_port($p['port'] ?? '')) {
			$errors[] = gettext("An endpoint requires a port between 1 and 65535.");
		}
	}
	$ka = $p['keepalive'] ?? '';
	if ($ka !== '' && (!is_numericint($ka) || $ka < 0 || $ka > 65535)) {
		$errors[] = gettext("The keepalive interval must be between 0 and 65535 seconds.");
	}
	$allowed = wolfguard_split_list($p['allowedips'] ?? '');
	if (empty($allowed)) {
		$errors[] = gettext("At least one allowed IP is required.");
	}
	foreach ($allowed as $net) {
		if (!is_subnet($net)) {
			$errors[] = sprintf(gettext("%s is not a valid network in CIDR notation."), $net);
		}
	}
	return $errors;
}

/* ------------------------------------------------------------------------
 * Runtime control
 * --------------------------------------------------------------------- */

function wolfguard_pidfile($ifname) {
	return "/var/run/wolfguard-{$ifname}.pid";
}

function wolfguard_sockfile($ifname) {
	return WOLFGUARD_RUN_DIR . "/{$ifname}.sock";
}

function wolfguard_conffile($ifname) {
	return WOLFGUARD_CONF_DIR . "/{$ifname}.conf";
}

function wolfguard_tunnel_running($ifname) {
	$pidfile = wolfguard_pidfile($ifname);
	if (!file_exists($pidfile)) {
		return false;
	}
	$pid = (int)trim(file_get_contents($pidfile));
	return ($pid > 0) && posix_kill($pid, 0);
}

/* Write the wg-fips setconf style file for a tunnel (mode 0600). */
function wolfguard_write_conf($t) {
	$lines = [];
	$lines[] = "# Generated by pfSense-pkg-wolfGuard. Do not edit.";
	$lines[] = "[Interface]";
	$lines[] = "PrivateKey = " . trim($t['privatekey']);
	$lines[] = "ListenPort = " . (int)$t['listenport'];
	foreach ($t['peers']['item'] as $p) {
		if (($p['enabled'] ?? '') != 'yes') {
			continue;
		}
		$lines[] = "";
		$lines[] = "[Peer]";
		$lines[] = "PublicKey = " . trim($p['publickey']);
		if (($p['presharedkey'] ?? '') !== '') {
			$lines[] = "PresharedKey = " . trim($p['presharedkey']);
		}
		$allowed = wolfguard_split_list($p['allowedips'] ?? '');
		if (!empty($allowed)) {
			$lines[] = "AllowedIPs = " . implode(', ', $allowed);
		}
		if (($p['endpoint'] ?? '') !== '') {
			$host = is_ipaddrv6($p['endpoint']) ? "[{$p['endpoint']}]" : $p['endpoint'];
			$lines[] = "Endpoint = {$host}:" . (int)$p['port'];
		}
		if (($p['keepalive'] ?? '') !== '' && (int)$p['keepalive'] > 0) {
			$lines[] = "PersistentKeepalive = " . (int)$p['keepalive'];
		}
	}
	safe_mkdir(WOLFGUARD_CONF_DIR, 0700);
	$file = wolfguard_conffile($t['name']);
	$tmp = "{$file}.tmp";
	$old = umask(0077);
	file_put_contents($tmp, implode("\n", $lines) . "\n");
	umask($old);
	chmod($tmp, 0600);
	rename($tmp, $file);
	return $file;
}

function wolfguard_wait_for_socket($ifname, $timeout_ms = 5000) {
	$sock = wolfguard_sockfile($ifname);
	for ($waited = 0; $waited < $timeout_ms; $waited += 100) {
		clearstatcache(true, $sock);
		if (file_exists($sock)) {
			return true;
		}
		usleep(100000);
	}
	return false;
}

/*
 * Start (or reconfigure) one tunnel.
 *
 * At boot this runs from an earlyshellcmd, before pfSense configures
 * interfaces, so an assigned tunnel's address and MTU are applied later by
 * pfSense itself. Outside of boot an assigned interface is reconfigured here.
 */
function wolfguard_start_tunnel($t, $booting = false) {
	$ifname = $t['name'];
	$conf = wolfguard_write_conf($t);

	if (!wolfguard_tunnel_running($ifname)) {
		/* A daemon that died leaves its tun device behind. */
		if (does_interface_exist($ifname)) {
			mwexec("/sbin/ifconfig " . escapeshellarg($ifname) . " destroy");
		}
		safe_mkdir(WOLFGUARD_RUN_DIR, 0700);
		/*
		 * daemon(8) puts wolfguard-go in its own session. Started directly
		 * from the boot scripts it is terminated late in the boot process.
		 */
		$cmd = "/usr/bin/env LOG_LEVEL=error /usr/sbin/daemon -f" .
		    " -p " . escapeshellarg(wolfguard_pidfile($ifname)) .
		    " -o " . escapeshellarg(WOLFGUARD_LOG) .
		    " " . WOLFGUARD_DAEMON . " -f " . escapeshellarg($ifname);
		mwexec($cmd);
		if (!wolfguard_wait_for_socket($ifname)) {
			log_error("wolfGuard: {$ifname} did not start, see " . WOLFGUARD_LOG);
			return false;
		}
	}

	if (wolfguard_tool("syncconf " . escapeshellarg($ifname) . " " .
	    escapeshellarg($conf)) === false) {
		return false;
	}

	$friendly = wolfguard_assigned_friendly($ifname);
	$mtu = (int)(($t['mtu'] ?? '') !== '' ? $t['mtu'] : WOLFGUARD_DEFAULT_MTU);
	if ($friendly === NULL) {
		/* Unassigned: the package owns the addresses and MTU. */
		mwexec("/sbin/ifconfig " . escapeshellarg($ifname) . " mtu {$mtu}");
		foreach (wolfguard_split_list($t['addresses'] ?? '') as $addr) {
			$family = is_subnetv6($addr) ? "inet6" : "inet";
			mwexec("/sbin/ifconfig " . escapeshellarg($ifname) .
			    " {$family} " . escapeshellarg($addr) . " alias");
		}
		mwexec("/sbin/ifconfig " . escapeshellarg($ifname) . " up");
	} elseif (!$booting) {
		interface_configure($friendly, true);
		mwexec("/sbin/ifconfig " . escapeshellarg($ifname) . " up");
	}
	return true;
}

function wolfguard_stop_tunnel($ifname) {
	$pidfile = wolfguard_pidfile($ifname);
	if (file_exists($pidfile)) {
		$pid = (int)trim(file_get_contents($pidfile));
		if ($pid > 0) {
			posix_kill($pid, SIGTERM);
			for ($i = 0; $i < 30 && posix_kill($pid, 0); $i++) {
				usleep(100000);
			}
		}
		@unlink($pidfile);
	}
	if (does_interface_exist($ifname)) {
		mwexec("/sbin/ifconfig " . escapeshellarg($ifname) . " destroy");
	}
}

/* Names of wolfGuard tun devices that currently exist. */
function wolfguard_running_ifnames() {
	$names = [];
	foreach (glob("/var/run/wolfguard-" . WOLFGUARD_IF_PREFIX . "*.pid") ?: [] as $pidfile) {
		$names[] = preg_replace('/^.*\/wolfguard-(.*)\.pid$/', '$1', $pidfile);
	}
	return $names;
}

/* Bring the running state in line with the configuration. */
function wolfguard_resync($booting = false) {
	$tunnels = wolfguard_get_tunnels();
	$wanted = [];
	foreach ($tunnels as $t) {
		if (($t['enabled'] ?? '') == 'yes') {
			$wanted[] = $t['name'];
		}
	}
	foreach (wolfguard_running_ifnames() as $ifname) {
		if (!in_array($ifname, $wanted)) {
			wolfguard_stop_tunnel($ifname);
			@unlink(wolfguard_conffile($ifname));
		}
	}
	foreach ($tunnels as $t) {
		if (in_array($t['name'], $wanted)) {
			wolfguard_start_tunnel($t, $booting);
		}
	}
}

function wolfguard_stop_all() {
	foreach (wolfguard_running_ifnames() as $ifname) {
		wolfguard_stop_tunnel($ifname);
	}
}

/*
 * Keep an assigned tunnel's interface MTU in sync with the tunnel setting.
 * Without it pfSense applies 1500 when it configures the interface at boot.
 */
function wolfguard_sync_interface_mtu($t) {
	$friendly = wolfguard_assigned_friendly($t['name']);
	if ($friendly === NULL) {
		return false;
	}
	$mtu = ($t['mtu'] ?? '') !== '' ? $t['mtu'] : (string)WOLFGUARD_DEFAULT_MTU;
	if (config_get_path("interfaces/{$friendly}/mtu") != $mtu) {
		config_set_path("interfaces/{$friendly}/mtu", $mtu);
		return true;
	}
	return false;
}

/* ------------------------------------------------------------------------
 * Status
 * --------------------------------------------------------------------- */

/*
 * Parse "wg-fips show <if> dump". Returns
 * ['interface' => [...], 'peers' => [pubkey => [...]]] or NULL.
 */
function wolfguard_status($ifname) {
	if (!wolfguard_tunnel_running($ifname)) {
		return NULL;
	}
	$out = wolfguard_tool("show " . escapeshellarg($ifname) . " dump");
	if ($out === false || $out === '') {
		return NULL;
	}
	$lines = explode("\n", $out);
	$first = explode("\t", array_shift($lines));
	$status = [
		'interface' => [
			'publickey' => $first[1] ?? '',
			'listenport' => $first[2] ?? '',
		],
		'peers' => [],
	];
	foreach ($lines as $line) {
		$f = explode("\t", $line);
		if (count($f) < 8) {
			continue;
		}
		$status['peers'][$f[0]] = [
			'endpoint' => ($f[2] == '(none)') ? '' : $f[2],
			'allowedips' => $f[3],
			'latest_handshake' => (int)$f[4],
			'rx' => (int)$f[5],
			'tx' => (int)$f[6],
			'keepalive' => $f[7],
		];
	}
	return $status;
}

function wolfguard_format_ago($ts) {
	if ($ts <= 0) {
		return gettext("never");
	}
	$d = time() - $ts;
	if ($d < 120) {
		return sprintf(gettext("%d seconds ago"), $d);
	}
	if ($d < 7200) {
		return sprintf(gettext("%d minutes ago"), intdiv($d, 60));
	}
	return sprintf(gettext("%d hours ago"), intdiv($d, 3600));
}

/* ------------------------------------------------------------------------
 * Package install / removal hooks
 * --------------------------------------------------------------------- */

function wolfguard_earlyshellcmd_list() {
	$cmds = config_get_path('system/earlyshellcmd', []);
	if (!is_array($cmds)) {
		$cmds = ($cmds === '' || $cmds === NULL) ? [] : [$cmds];
	}
	return $cmds;
}

function wolfguard_ensure_sysctl() {
	$items = config_get_path('sysctl/item', []);
	$found = false;
	foreach ($items as &$item) {
		if ($item['tunable'] == 'kern.ipc.maxsockbuf') {
			$found = true;
			if ((int)$item['value'] < WOLFGUARD_MAXSOCKBUF) {
				$item['value'] = (string)WOLFGUARD_MAXSOCKBUF;
			}
		}
	}
	unset($item);
	if (!$found) {
		$items[] = [
			'tunable' => 'kern.ipc.maxsockbuf',
			'value' => (string)WOLFGUARD_MAXSOCKBUF,
			'descr' => WOLFGUARD_SYSCTL_DESCR,
		];
	}
	config_set_path('sysctl/item', $items);
	$cur = (int)trim(shell_exec('/sbin/sysctl -n kern.ipc.maxsockbuf'));
	if ($cur < WOLFGUARD_MAXSOCKBUF) {
		mwexec('/sbin/sysctl kern.ipc.maxsockbuf=' . WOLFGUARD_MAXSOCKBUF);
	}
}

function wolfguard_install() {
	safe_mkdir(WOLFGUARD_CONF_DIR, 0700);
	$cmds = wolfguard_earlyshellcmd_list();
	if (!in_array(WOLFGUARD_EARLYSHELLCMD, $cmds)) {
		$cmds[] = WOLFGUARD_EARLYSHELLCMD;
	}
	config_set_path('system/earlyshellcmd', $cmds);
	wolfguard_ensure_sysctl();
	write_config("wolfGuard: package installed (earlyshellcmd, kern.ipc.maxsockbuf)");
}

function wolfguard_deinstall() {
	wolfguard_stop_all();
	$cmds = array_values(array_diff(wolfguard_earlyshellcmd_list(),
	    [WOLFGUARD_EARLYSHELLCMD]));
	if (empty($cmds)) {
		config_del_path('system/earlyshellcmd');
	} else {
		config_set_path('system/earlyshellcmd', $cmds);
	}
	/* Only remove the tunable if we created it. */
	$items = config_get_path('sysctl/item', []);
	$items = array_values(array_filter($items, function ($i) {
		return ($i['descr'] ?? '') != WOLFGUARD_SYSCTL_DESCR;
	}));
	config_set_path('sysctl/item', $items);
	write_config("wolfGuard: package removed");
}
