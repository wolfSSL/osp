<?php
/*
 * vpn_wolfguard_peers_edit.php - add/edit a peer on a wolfGuard tunnel.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

##|+PRIV
##|*IDENT=page-vpn-wolfguard
##|*NAME=VPN: wolfGuard
##|*DESCR=Allow access to the 'VPN: wolfGuard' configuration pages.
##|*MATCH=wolfguard/vpn_wolfguard*
##|-PRIV

require_once("guiconfig.inc");
require_once("/usr/local/pkg/wolfguard/wolfguard_gui.inc");

$tunnels = wolfguard_get_tunnels();
$tid = $_REQUEST['tunnel'] ?? NULL;
if ($tid === NULL || !isset($tunnels[$tid])) {
	header("Location: vpn_wolfguard_tunnels.php");
	exit;
}
$peers = $tunnels[$tid]['peers']['item'];
$id = $_REQUEST['id'] ?? NULL;
if ($id !== NULL && !isset($peers[$id])) {
	header("Location: vpn_wolfguard_tunnels_edit.php?id={$tid}");
	exit;
}
$input_errors = [];

$pconfig = ($id !== NULL) ? $peers[$id] : [
	'enabled' => 'yes',
	'descr' => '',
	'publickey' => '',
	'presharedkey' => '',
	'endpoint' => '',
	'port' => (string)WOLFGUARD_DEFAULT_PORT,
	'keepalive' => '',
	'allowedips' => '',
];

if (isset($_POST['save'])) {
	$new = [
		'enabled' => isset($_POST['enabled']) ? 'yes' : 'no',
		'descr' => trim($_POST['descr'] ?? ''),
		'publickey' => trim($_POST['publickey'] ?? ''),
		'presharedkey' => trim($_POST['presharedkey'] ?? ''),
		'endpoint' => trim($_POST['endpoint'] ?? ''),
		'port' => trim($_POST['port'] ?? ''),
		'keepalive' => trim($_POST['keepalive'] ?? ''),
		'allowedips' => implode(',', wolfguard_split_list($_POST['allowedips'] ?? '')),
	];
	if (isset($_POST['genpsk'])) {
		$psk = wolfguard_genpsk();
		if ($psk === false) {
			$input_errors[] = gettext("Could not generate a pre-shared key with wg-fips.");
		} else {
			$new['presharedkey'] = $psk;
		}
	}
	if ($new['endpoint'] === '') {
		$new['port'] = '';
	}
	if (empty($input_errors)) {
		$input_errors = wolfguard_validate_peer($new, $id, $peers);
	}
	if (empty($input_errors)) {
		if ($id === NULL) {
			$tunnels[$tid]['peers']['item'][] = $new;
		} else {
			$tunnels[$tid]['peers']['item'][$id] = $new;
		}
		wolfguard_set_tunnels($tunnels, "wolfGuard: saved peer on {$tunnels[$tid]['name']}");
		wolfguard_resync();
		header("Location: vpn_wolfguard_tunnels_edit.php?id={$tid}&saved=1");
		exit;
	}
	$pconfig = $new;
}

$pgtitle = [gettext("VPN"), gettext("wolfGuard"), gettext("Tunnels"),
    htmlspecialchars($tunnels[$tid]['name']), ($id === NULL) ? gettext("Add Peer") : gettext("Edit Peer")];
$pglinks = ["", "/wolfguard/vpn_wolfguard_tunnels.php", "/wolfguard/vpn_wolfguard_tunnels.php",
    "/wolfguard/vpn_wolfguard_tunnels_edit.php?id={$tid}", "@self"];
$shortcut_section = "wolfguard";
include("head.inc");

if (!empty($input_errors)) {
	print_input_errors($input_errors);
}

wolfguard_display_tabs('tunnels');

$form = new Form();
$section = new Form_Section(sprintf(gettext("Peer on %s"), $tunnels[$tid]['name']));

$section->addInput(new Form_Checkbox(
	'enabled',
	'Enable',
	'Enable this peer',
	($pconfig['enabled'] == 'yes')
));

$section->addInput(new Form_Input(
	'descr',
	'Description',
	'text',
	$pconfig['descr']
));

$section->addInput(new Form_Input(
	'publickey',
	'*Public Key',
	'text',
	$pconfig['publickey']
))->setHelp('The peer\'s base64 P-256 public key (wg-fips pubkey format, 88 characters).');

$section->addInput(new Form_Input(
	'presharedkey',
	'Pre-shared Key',
	'password',
	$pconfig['presharedkey']
))->setHelp('Optional. Must match the peer\'s setting.');

$section->addInput(new Form_Checkbox(
	'genpsk',
	'New PSK',
	'Generate a new pre-shared key when saving',
	false
));

$group = new Form_Group('Endpoint');
$group->add(new Form_Input(
	'endpoint',
	'Address',
	'text',
	$pconfig['endpoint']
))->setHelp('IP address or hostname. Leave empty for a peer that connects to this firewall.');
$group->add(new Form_Input(
	'port',
	'Port',
	'number',
	$pconfig['port'],
	['min' => 1, 'max' => 65535]
))->setHelp('Port');
$section->add($group);

$section->addInput(new Form_Input(
	'keepalive',
	'Keepalive',
	'number',
	$pconfig['keepalive'],
	['min' => 0, 'max' => 65535, 'placeholder' => gettext('Off')]
))->setHelp('Persistent keepalive interval in seconds. 25 is typical when this side is behind NAT.');

$section->addInput(new Form_Input(
	'allowedips',
	'*Allowed IPs',
	'text',
	str_replace(',', ', ', $pconfig['allowedips'])
))->setHelp('Comma separated networks routed to and accepted from this peer, e.g. 10.200.0.2/32, 192.168.100.0/24. ' .
    'wolfguard-go does not add routes: for networks beyond the tunnel subnet, add a gateway on the assigned interface and a static route under System &gt; Routing.');

$form->add($section);
$form->addGlobal(new Form_Input('tunnel', null, 'hidden', $tid));
if ($id !== NULL) {
	$form->addGlobal(new Form_Input('id', null, 'hidden', $id));
}
print($form);

include("foot.inc");
