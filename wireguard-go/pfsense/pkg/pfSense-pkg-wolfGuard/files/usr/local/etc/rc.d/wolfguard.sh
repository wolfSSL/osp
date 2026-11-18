#!/bin/sh
#
# wolfguard.sh - start/stop wolfGuard (wolfguard-go) tunnels on pfSense.
#
# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Runs from an earlyshellcmd at boot so tunnel devices exist before pfSense
# configures interfaces, and from the Status > Services page.

case "$1" in
start|stop|restart)
	exec /usr/local/bin/php -f /usr/local/pkg/wolfguard/wolfguard_service.php "$1"
	;;
*)
	echo "usage: $0 start|stop|restart" >&2
	exit 1
	;;
esac
