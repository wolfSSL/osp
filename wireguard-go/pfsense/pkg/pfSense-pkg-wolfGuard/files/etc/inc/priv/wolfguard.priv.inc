<?php
/*
 * wolfguard.priv.inc
 *
 * Copyright (C) 2026 wolfSSL Inc.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

global $priv_list;

$priv_list['page-vpn-wolfguard'] = array();
$priv_list['page-vpn-wolfguard']['name'] = "WebCfg - VPN: wolfGuard";
$priv_list['page-vpn-wolfguard']['descr'] = "Allow access to the 'VPN: wolfGuard' configuration pages.";
$priv_list['page-vpn-wolfguard']['match'] = array();
$priv_list['page-vpn-wolfguard']['match'][] = "wolfguard/vpn_wolfguard*";

$priv_list['page-status-wolfguard'] = array();
$priv_list['page-status-wolfguard']['name'] = "WebCfg - Status: wolfGuard";
$priv_list['page-status-wolfguard']['descr'] = "Allow access to the 'Status: wolfGuard' page.";
$priv_list['page-status-wolfguard']['match'] = array();
$priv_list['page-status-wolfguard']['match'][] = "wolfguard/status_wolfguard.php*";
