<?php
/**
 * Fired when the plugin is uninstalled.
 *
 * Drops custom tables, removes options, deletes transients, and unschedules crons
 * if the user selected to clean up data upon uninstall.
 */

if (!defined('WP_UNINSTALL_PLUGIN')) exit;

(function(): void {
    global $wpdb;

    // Check if user opted to preserve data on uninstall
    $cleanup = get_option('pn_mailguard_uninstall_cleanup', '1');

    if ($cleanup === '1') {
        // 1. Drop all plugin tables
        $tables = [
            $wpdb->prefix . 'pointnet_mailguard_log_email',
            $wpdb->prefix . 'pointnet_mailguard_log_ip',
            $wpdb->prefix . 'pointnet_mailguard_ai_results',
            $wpdb->prefix . 'pointnet_mailguard_dmarc_records',
            $wpdb->prefix . 'pointnet_mailguard_dmarc_reports',
            $wpdb->prefix . 'pointnet_mailguard_tls_records',
            $wpdb->prefix . 'pointnet_mailguard_tls_reports',
        ];
        foreach ($tables as $table) {
            $wpdb->query($wpdb->prepare("DROP TABLE IF EXISTS %i", $table));
        }

        // 2. Delete all plugin options
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

        foreach ($options as $option) {
            delete_option($option);
        }

        // 3. Delete all plugin transients
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

        // 4. Clear scheduled cron events
        $timestamp = wp_next_scheduled('pn_mailguard_daily_scan');
        if ($timestamp) {
            wp_unschedule_event($timestamp, 'pn_mailguard_daily_scan');
        }

        $imap_timestamp = wp_next_scheduled('pn_mailguard_fetch_reports_cron');
        if ($imap_timestamp) {
            wp_unschedule_event($imap_timestamp, 'pn_mailguard_fetch_reports_cron');
        }
    }
})();