<?php
/*
 * wolfguard_gui.inc - helpers shared by the wolfGuard GUI pages.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

require_once("/usr/local/pkg/wolfguard/wolfguard.inc");

function wolfguard_display_tabs($active) {
	$tabs = [
		'tunnels' => [gettext("Tunnels"), "/wolfguard/vpn_wolfguard_tunnels.php"],
		'status' => [gettext("Status"), "/wolfguard/status_wolfguard.php"],
	];
	$tab_array = [];
	foreach ($tabs as $key => $tab) {
		$tab_array[] = [$tab[0], ($key == $active), $tab[1]];
	}
	display_top_tabs($tab_array);
}

/* Shorten a long base64 public key for tables. */
function wolfguard_short_key($key) {
	$key = trim((string)$key);
	return (strlen($key) > 20) ? substr($key, 0, 10) . '...' . substr($key, -8) : $key;
}

function wolfguard_interface_label($ifname) {
	$friendly = wolfguard_assigned_friendly($ifname);
	if ($friendly === NULL) {
		return gettext("Unassigned");
	}
	return htmlspecialchars(convert_friendly_interface_to_friendly_descr($friendly));
}
