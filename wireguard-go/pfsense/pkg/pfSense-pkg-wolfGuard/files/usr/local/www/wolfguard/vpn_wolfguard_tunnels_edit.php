<?php
/*
 * vpn_wolfguard_tunnels_edit.php - add/edit a wolfGuard tunnel and its peers.
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
$id = $_REQUEST['id'] ?? NULL;
if ($id !== NULL && !isset($tunnels[$id])) {
	header("Location: vpn_wolfguard_tunnels.php");
	exit;
}
$input_errors = [];
$savemsg = '';

if ($id !== NULL) {
	$pconfig = $tunnels[$id];
} else {
	$pconfig = [
		'enabled' => 'yes',
		'name' => wolfguard_next_ifname($tunnels),
		'listenport' => (string)WOLFGUARD_DEFAULT_PORT,
		'mtu' => (string)WOLFGUARD_DEFAULT_MTU,
		'privatekey' => '',
		'descr' => '',
		'addresses' => '',
		'peers' => ['item' => []],
	];
	/* Suggest the next free port when several tunnels exist. */
	$ports = array_column($tunnels, 'listenport');
	while (in_array($pconfig['listenport'], $ports)) {
		$pconfig['listenport'] = (string)((int)$pconfig['listenport'] + 1);
	}
}

/* Peer deletion from the peer table on this page. */
if ($id !== NULL && ($_POST['act'] ?? '') == 'delpeer' &&
    isset($tunnels[$id]['peers']['item'][$_POST['peer']])) {
	unset($tunnels[$id]['peers']['item'][$_POST['peer']]);
	$tunnels[$id]['peers']['item'] = array_values($tunnels[$id]['peers']['item']);
	wolfguard_set_tunnels($tunnels, "wolfGuard: deleted peer from {$tunnels[$id]['name']}");
	wolfguard_resync();
	$tunnels = wolfguard_get_tunnels();
	$pconfig = $tunnels[$id];
	$savemsg = gettext("Peer deleted.");
}

if (isset($_POST['save'])) {
	$new = $pconfig;
	$new['enabled'] = isset($_POST['enabled']) ? 'yes' : 'no';
	$new['descr'] = trim($_POST['descr'] ?? '');
	$new['listenport'] = trim($_POST['listenport'] ?? '');
	$new['mtu'] = trim($_POST['mtu'] ?? '');
	$new['addresses'] = implode(',', wolfguard_split_list($_POST['addresses'] ?? ''));
	$new['privatekey'] = trim($_POST['privatekey'] ?? '');
	if (isset($_POST['genkey']) || $new['privatekey'] === '') {
		$key = wolfguard_genkey();
		if ($key === false) {
			$input_errors[] = gettext("Could not generate a private key with wg-fips. Check the system log.");
		} else {
			$new['privatekey'] = $key;
		}
	}

	if (empty($input_errors)) {
		$input_errors = wolfguard_validate_tunnel($new, $id, $tunnels);
	}
	if (empty($input_errors)) {
		$pub = wolfguard_pubkey($new['privatekey']);
		if ($pub === false || !wolfguard_valid_pubkey($pub)) {
			$input_errors[] = gettext("Could not derive the public key from the private key.");
		} else {
			$new['publickey'] = $pub;
		}
	}

	if (empty($input_errors)) {
		if ($id === NULL) {
			$tunnels[] = $new;
			$id = count($tunnels) - 1;
		} else {
			$tunnels[$id] = $new;
		}
		config_set_path(WOLFGUARD_CONFIG_PATH . '/tunnels/item', array_values($tunnels));
		wolfguard_sync_interface_mtu($new);
		write_config("wolfGuard: saved tunnel {$new['name']}");
		wolfguard_resync();
		header("Location: vpn_wolfguard_tunnels_edit.php?id={$id}&saved=1");
		exit;
	}
	$pconfig = $new;
}

if (!empty($_GET['saved'])) {
	$savemsg = gettext("Tunnel saved and applied.");
}

$pgtitle = [gettext("VPN"), gettext("wolfGuard"), gettext("Tunnels"),
    ($id === NULL) ? gettext("Add") : gettext("Edit")];
$pglinks = ["", "/wolfguard/vpn_wolfguard_tunnels.php", "/wolfguard/vpn_wolfguard_tunnels.php", "@self"];
$shortcut_section = "wolfguard";
include("head.inc");

if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg, 'success');
}

wolfguard_display_tabs('tunnels');

$form = new Form();
$section = new Form_Section(sprintf(gettext("Tunnel %s"), $pconfig['name']));

$section->addInput(new Form_Checkbox(
	'enabled',
	'Enable',
	'Enable this tunnel',
	($pconfig['enabled'] == 'yes')
));

$section->addInput(new Form_Input(
	'descr',
	'Description',
	'text',
	$pconfig['descr']
))->setHelp('Optional description for administrative reference.');

$section->addInput(new Form_Input(
	'listenport',
	'*Listen Port',
	'number',
	$pconfig['listenport'],
	['min' => 1, 'max' => 65535]
))->setHelp('UDP port wolfguard-go listens on. Allow it on WAN with a firewall rule when peers connect to this firewall.');

$section->addInput(new Form_Input(
	'privatekey',
	'Private Key',
	'password',
	$pconfig['privatekey']
))->setHelp('Base64 P-256 private key (wg-fips genkey format). Leave empty on a new tunnel to generate one.');

$section->addInput(new Form_Checkbox(
	'genkey',
	'New Key',
	'Generate a new key pair when saving (existing peers must be given the new public key)',
	false
));

if (!empty($pconfig['publickey'])) {
	$section->addInput(new Form_StaticText(
		'Public Key',
		'<code style="word-break: break-all;">' . htmlspecialchars($pconfig['publickey']) . '</code>'
	))->setHelp('Give this key to peers.');
}

$section->addInput(new Form_Input(
	'mtu',
	'MTU',
	'number',
	$pconfig['mtu'],
	['min' => 1280, 'max' => 9000, 'placeholder' => WOLFGUARD_DEFAULT_MTU]
))->setHelp('Tunnel MTU. When the tunnel is assigned, the interface MTU is set to this value.');

$section->addInput(new Form_Input(
	'addresses',
	'Addresses',
	'text',
	str_replace(',', ', ', $pconfig['addresses'])
))->setHelp('Only used while the tunnel is not assigned to an interface: comma separated CIDR addresses for %s, e.g. 10.200.0.1/24. Assigned tunnels take their address from the interface configuration.', $pconfig['name']);

$form->add($section);
if ($id !== NULL) {
	$form->addGlobal(new Form_Input('id', null, 'hidden', $id));
}
print($form);

if ($id !== NULL):
	$status = wolfguard_status($pconfig['name']);
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext("Peers")?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed">
			<thead>
				<tr>
					<th><?=gettext("Description")?></th>
					<th><?=gettext("Public Key")?></th>
					<th><?=gettext("Endpoint")?></th>
					<th><?=gettext("Allowed IPs")?></th>
					<th><?=gettext("Latest Handshake")?></th>
					<th><?=gettext("Actions")?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($pconfig['peers']['item'] as $pi => $p):
	$ps = $status['peers'][trim($p['publickey'])] ?? NULL;
?>
				<tr<?=($p['enabled'] == 'yes') ? '' : ' class="disabled"'?>>
					<td><?=htmlspecialchars($p['descr'])?></td>
					<td><code title="<?=htmlspecialchars($p['publickey'])?>"><?=htmlspecialchars(wolfguard_short_key($p['publickey']))?></code></td>
					<td><?=($p['endpoint'] !== '') ? htmlspecialchars("{$p['endpoint']}:{$p['port']}") : gettext("Dynamic")?></td>
					<td><?=htmlspecialchars(str_replace(',', ', ', $p['allowedips']))?></td>
					<td><?=$ps ? wolfguard_format_ago($ps['latest_handshake']) : '-'?></td>
					<td>
						<a class="fa-solid fa-pencil" title="<?=gettext("Edit peer")?>" href="vpn_wolfguard_peers_edit.php?tunnel=<?=$id?>&amp;id=<?=$pi?>"></a>
						<a class="fa-solid fa-trash-can" title="<?=gettext("Delete peer")?>" href="?act=delpeer&amp;id=<?=$id?>&amp;peer=<?=$pi?>" usepost></a>
					</td>
				</tr>
<?php endforeach; ?>
<?php if (empty($pconfig['peers']['item'])): ?>
				<tr><td colspan="6"><?=gettext("No peers are configured for this tunnel.")?></td></tr>
<?php endif; ?>
			</tbody>
		</table>
	</div>
</div>
<nav class="action-buttons">
	<a href="vpn_wolfguard_peers_edit.php?tunnel=<?=$id?>" class="btn btn-success btn-sm">
		<i class="fa-solid fa-plus icon-embed-btn"></i><?=gettext("Add Peer")?>
	</a>
</nav>
<?php endif; ?>

<?php include("foot.inc"); ?>
