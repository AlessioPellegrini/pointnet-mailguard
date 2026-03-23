<?php
if (!defined('WP_UNINSTALL_PLUGIN')) exit;

global $wpdb;

// 1. Drop both log tables
$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}pointnet_mailguard_log_email");
$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}pointnet_mailguard_log_ip");

// 2. Delete all plugin options
delete_option('pn_mailguard_check_email');
delete_option('pn_mailguard_check_ip');
delete_option('pn_mailguard_email_alert');
delete_option('pn_mailguard_spf_domain');
delete_transient('pn_mailguard_scan_lock');
delete_transient('pn_mailguard_spf_lock');
delete_option('pn_mailguard_dmarc_domain');
delete_transient('pn_mailguard_dmarc_lock');

// 3. Clear the scheduled cron event
$timestamp = wp_next_scheduled('pn_mailguard_daily_scan');
if ($timestamp) wp_unschedule_event($timestamp, 'pn_mailguard_daily_scan');
