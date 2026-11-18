<?php
/*
 * vpn_wolfguard_tunnels.php - list wolfGuard tunnels.
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
$input_errors = [];
$savemsg = '';

$act = $_POST['act'] ?? '';
$post_id = $_POST['id'] ?? NULL;

if ($act == 'del' && $post_id !== NULL && isset($tunnels[$post_id])) {
	$t = $tunnels[$post_id];
	$friendly = wolfguard_assigned_friendly($t['name']);
	if ($friendly !== NULL) {
		$input_errors[] = sprintf(gettext("%s is assigned to interface %s. Remove the assignment under Interfaces > Assignments before deleting the tunnel."),
		    $t['name'], convert_friendly_interface_to_friendly_descr($friendly));
	} else {
		unset($tunnels[$post_id]);
		wolfguard_set_tunnels($tunnels, "wolfGuard: deleted tunnel {$t['name']}");
		wolfguard_resync();
		$tunnels = wolfguard_get_tunnels();
		$savemsg = sprintf(gettext("Tunnel %s deleted."), $t['name']);
	}
}

if ($act == 'toggle' && $post_id !== NULL && isset($tunnels[$post_id])) {
	$id = $post_id;
	$tunnels[$id]['enabled'] = ($tunnels[$id]['enabled'] == 'yes') ? 'no' : 'yes';
	wolfguard_set_tunnels($tunnels, "wolfGuard: toggled tunnel {$tunnels[$id]['name']}");
	wolfguard_resync();
	$tunnels = wolfguard_get_tunnels();
}

$pgtitle = [gettext("VPN"), gettext("wolfGuard"), gettext("Tunnels")];
$pglinks = ["", "/wolfguard/vpn_wolfguard_tunnels.php", "@self"];
$shortcut_section = "wolfguard";
include("head.inc");

if (!empty($input_errors)) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg, 'success');
}

wolfguard_display_tabs('tunnels');
?>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext("wolfGuard Tunnels")?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed">
			<thead>
				<tr>
					<th><?=gettext("Tunnel")?></th>
					<th><?=gettext("Description")?></th>
					<th><?=gettext("Interface")?></th>
					<th><?=gettext("Listen Port")?></th>
					<th><?=gettext("Public Key")?></th>
					<th><?=gettext("Peers")?></th>
					<th><?=gettext("Actions")?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($tunnels as $i => $t):
	$enabled = ($t['enabled'] == 'yes');
	$running = wolfguard_tunnel_running($t['name']);
?>
				<tr<?=$enabled ? '' : ' class="disabled"'?>>
					<td>
						<i class="fa-solid fa-circle text-<?=$running ? 'success' : ($enabled ? 'danger' : 'muted')?>"
						   title="<?=$running ? gettext("Running") : gettext("Not running")?>"></i>
						<?=htmlspecialchars($t['name'])?>
					</td>
					<td><?=htmlspecialchars($t['descr'])?></td>
					<td><?=wolfguard_interface_label($t['name'])?></td>
					<td><?=htmlspecialchars($t['listenport'])?></td>
					<td><code title="<?=htmlspecialchars($t['publickey'])?>"><?=htmlspecialchars(wolfguard_short_key($t['publickey']))?></code></td>
					<td><?=count($t['peers']['item'])?></td>
					<td>
						<a class="fa-solid fa-pencil" title="<?=gettext("Edit tunnel")?>" href="vpn_wolfguard_tunnels_edit.php?id=<?=$i?>"></a>
						<a class="fa-solid fa-<?=$enabled ? 'ban' : 'square-check'?>" title="<?=$enabled ? gettext("Disable") : gettext("Enable")?>"
						   href="?act=toggle&amp;id=<?=$i?>" usepost></a>
						<a class="fa-solid fa-trash-can" title="<?=gettext("Delete tunnel")?>" href="?act=del&amp;id=<?=$i?>" usepost></a>
					</td>
				</tr>
<?php endforeach; ?>
<?php if (empty($tunnels)): ?>
				<tr><td colspan="7"><?=gettext("No wolfGuard tunnels are configured.")?></td></tr>
<?php endif; ?>
			</tbody>
		</table>
	</div>
</div>

<nav class="action-buttons">
	<a href="vpn_wolfguard_tunnels_edit.php" class="btn btn-success btn-sm">
		<i class="fa-solid fa-plus icon-embed-btn"></i><?=gettext("Add Tunnel")?>
	</a>
</nav>

<div class="infoblock">
<?php print_info_box(gettext("Tunnels appear as tun_wolfN devices. To use one with firewall rules, routing or the interface status pages, assign it under Interfaces &gt; Assignments and give it an address there; leave IPv4/IPv6 configuration type set to Static and the MTU at the tunnel MTU (1420 by default). Add firewall rules on WAN for the listen port and on the assigned interface for tunnel traffic. wolfGuard peers are not compatible with WireGuard peers."), 'info', false); ?>
</div>

<?php include("foot.inc"); ?>
