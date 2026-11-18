<?php
/*
 * wolfguard_service.php - CLI entry point used by rc.d/wolfguard.sh.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

require_once("/usr/local/pkg/wolfguard/wolfguard.inc");

$action = $argv[1] ?? '';
switch ($action) {
	case 'start':
		wolfguard_resync(platform_booting());
		break;
	case 'stop':
		wolfguard_stop_all();
		break;
	case 'restart':
		wolfguard_stop_all();
		wolfguard_resync(false);
		break;
	default:
		fwrite(STDERR, "usage: {$argv[0]} start|stop|restart\n");
		exit(1);
}
