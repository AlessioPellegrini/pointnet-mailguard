<?php
if (!defined('WP_UNINSTALL_PLUGIN')) exit;

global $wpdb;

// Check if user opted to preserve data on uninstall
$pn_mailguard_cleanup = get_option('pn_mailguard_uninstall_cleanup', '1'); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ($pn_mailguard_cleanup === '1') {

    // 1. Drop all plugin tables
    $pn_mailguard_tables = [ // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
        $wpdb->prefix . 'pointnet_mailguard_log_email',
        $wpdb->prefix . 'pointnet_mailguard_log_ip',
        $wpdb->prefix . 'pointnet_mailguard_ai_results',
        $wpdb->prefix . 'pointnet_mailguard_dmarc_records',
        $wpdb->prefix . 'pointnet_mailguard_dmarc_reports',
        $wpdb->prefix . 'pointnet_mailguard_tls_records',
        $wpdb->prefix . 'pointnet_mailguard_tls_reports',
    ];
    foreach ($pn_mailguard_tables as $pn_mailguard_table) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
        $wpdb->query($wpdb->prepare("DROP TABLE IF EXISTS %i", $pn_mailguard_table));
    }

    // 2. Delete all plugin options and transients
    $pn_mailguard_options = [ // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
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
        'pn_mailguard_imap_host',
        'pn_mailguard_imap_port',
        'pn_mailguard_imap_encryption',
        'pn_mailguard_imap_username',
        'pn_mailguard_imap_password',
        'pn_mailguard_imap_mailbox',
        'pn_mailguard_imap_auto_fetch',
        'pn_mailguard_imap_action_after',
        'pn_mailguard_imap_last_fetch_time',
        'pn_mailguard_imap_last_fetch_summary',
    ];

    foreach ($pn_mailguard_options as $pn_mailguard_option) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
        delete_option($pn_mailguard_option);
    }

    $pn_mailguard_transients = [ // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
        'pn_mailguard_scan_lock',
        'pn_mailguard_spf_lock',
        'pn_mailguard_dmarc_lock',
        'pn_mailguard_dkim_lock',
        'pn_mailguard_available_models',
    ];

    foreach ($pn_mailguard_transients as $pn_mailguard_transient) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
        delete_transient($pn_mailguard_transient);
    }

    // 3. Clear scheduled cron events
    $pn_mailguard_timestamp = wp_next_scheduled('pn_mailguard_daily_scan'); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
    if ($pn_mailguard_timestamp) {
        wp_unschedule_event($pn_mailguard_timestamp, 'pn_mailguard_daily_scan');
    }

    $pn_mailguard_imap_timestamp = wp_next_scheduled('pn_mailguard_fetch_reports_cron'); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
    if ($pn_mailguard_imap_timestamp) {
        wp_unschedule_event($pn_mailguard_imap_timestamp, 'pn_mailguard_fetch_reports_cron');
    }

}