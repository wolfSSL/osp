<?php
/*
 * status_wolfguard.php - runtime status of wolfGuard tunnels and peers.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

##|+PRIV
##|*IDENT=page-status-wolfguard
##|*NAME=Status: wolfGuard
##|*DESCR=Allow access to the 'Status: wolfGuard' page.
##|*MATCH=wolfguard/status_wolfguard.php*
##|-PRIV

require_once("guiconfig.inc");
require_once("/usr/local/pkg/wolfguard/wolfguard_gui.inc");

$tunnels = wolfguard_get_tunnels();

$pgtitle = [gettext("Status"), gettext("wolfGuard")];
$pglinks = ["", "@self"];
$shortcut_section = "wolfguard";
include("head.inc");

wolfguard_display_tabs('status');

if (empty($tunnels)) {
	print_info_box(gettext("No wolfGuard tunnels are configured."), 'warning', false);
}

foreach ($tunnels as $i => $t):
	$st = wolfguard_status($t['name']);
	$peer_descr = [];
	foreach ($t['peers']['item'] as $p) {
		$peer_descr[trim($p['publickey'])] = $p['descr'];
	}
?>
<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title">
			<?=htmlspecialchars($t['name'])?>
			<?=($t['descr'] !== '') ? ' - ' . htmlspecialchars($t['descr']) : ''?>
			(<?=wolfguard_interface_label($t['name'])?>)
		</h2>
	</div>
	<div class="panel-body table-responsive">
<?php if ($st === NULL): ?>
		<p class="text-danger" style="padding: 8px;">
			<?=($t['enabled'] == 'yes') ? gettext("Not running. Check /var/log/wolfguard.log and the system log.") : gettext("Disabled.")?>
		</p>
<?php else: ?>
		<p style="padding: 8px;">
			<?=gettext("Listen port")?>: <?=htmlspecialchars($st['interface']['listenport'])?> &nbsp;
			<?=gettext("Public key")?>: <code style="word-break: break-all;"><?=htmlspecialchars($st['interface']['publickey'])?></code>
		</p>
		<table class="table table-striped table-hover table-condensed">
			<thead>
				<tr>
					<th><?=gettext("Peer")?></th>
					<th><?=gettext("Endpoint")?></th>
					<th><?=gettext("Allowed IPs")?></th>
					<th><?=gettext("Latest Handshake")?></th>
					<th><?=gettext("Received")?></th>
					<th><?=gettext("Sent")?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($st['peers'] as $key => $ps):
	$stale = ($ps['latest_handshake'] == 0) || (time() - $ps['latest_handshake'] > 180);
?>
				<tr>
					<td>
						<i class="fa-solid fa-circle text-<?=$stale ? 'danger' : 'success'?>"></i>
						<?=htmlspecialchars($peer_descr[$key] ?? '')?>
						<code title="<?=htmlspecialchars($key)?>"><?=htmlspecialchars(wolfguard_short_key($key))?></code>
					</td>
					<td><?=htmlspecialchars($ps['endpoint'] ?: '-')?></td>
					<td><?=htmlspecialchars(str_replace(',', ', ', $ps['allowedips']))?></td>
					<td><?=wolfguard_format_ago($ps['latest_handshake'])?></td>
					<td><?=format_bytes($ps['rx'])?></td>
					<td><?=format_bytes($ps['tx'])?></td>
				</tr>
<?php endforeach; ?>
<?php if (empty($st['peers'])): ?>
				<tr><td colspan="6"><?=gettext("No peers.")?></td></tr>
<?php endif; ?>
			</tbody>
		</table>
<?php endif; ?>
	</div>
</div>
<?php endforeach; ?>

<?php include("foot.inc"); ?>
