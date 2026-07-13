<?php
if (!defined('WP_UNINSTALL_PLUGIN')) exit;

global $wpdb;

// Check if user opted to preserve data on uninstall
$cleanup = get_option('pn_mailguard_uninstall_cleanup', '1');

if ($cleanup === '1') {

    // 1. Drop all plugin tables
    $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}pointnet_mailguard_log_email");
    $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}pointnet_mailguard_log_ip");
    $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}pointnet_mailguard_ai_results");

    // 2. Delete all plugin options and transients
    $options = [
        'pn_mailguard_check_email',
        'pn_mailguard_check_ip',
        'pn_mailguard_email_alert',
        'pn_mailguard_spf_domain',
        'pn_mailguard_dmarc_domain',
        'pn_mailguard_dkim_domain',
        'pn_mailguard_dkim_selector',
        'pn_mailguard_analyze_domain',
        'pn_mailguard_gemini_key',
        'pn_mailguard_gemini_model',
        'pn_mailguard_uninstall_cleanup',
    ];

    foreach ($options as $option) {
        delete_option($option);
    }

    $transients = [
        'pn_mailguard_scan_lock',
        'pn_mailguard_spf_lock',
        'pn_mailguard_dmarc_lock',
        'pn_mailguard_dkim_lock',
        'pn_mailguard_available_models',
    ];

    foreach ($transients as $transient) {
        delete_transient($transient);
    }

    // 3. Clear the scheduled cron event
    $timestamp = wp_next_scheduled('pn_mailguard_daily_scan');
    if ($timestamp) {
        wp_unschedule_event($timestamp, 'pn_mailguard_daily_scan');
    }

}