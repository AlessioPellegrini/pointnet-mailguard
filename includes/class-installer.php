<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Installer
 *
 * Handles plugin activation, deactivation and database setup.
 * Creates two separate log tables — one for email scans, one for IP scans.
 */
class PN_Mailguard_Installer {

    const string TABLE_EMAIL = 'pointnet_mailguard_log_email';
    const string TABLE_IP    = 'pointnet_mailguard_log_ip';
    const string TABLE_AI    = 'pointnet_mailguard_ai_results';

    public static function activate(): void {
        self::install();
    }

    public static function deactivate(): void {
        $timestamp = wp_next_scheduled('pn_mailguard_daily_scan');
        if ($timestamp) {
            wp_unschedule_event($timestamp, 'pn_mailguard_daily_scan');
        }
    }

    /**
     * Called on plugins_loaded — creates missing tables on updates and reinstalls.
     */
    public static function maybe_install(): void {
        global $wpdb;
        $missing = false;
        foreach ([self::TABLE_EMAIL, self::TABLE_IP, self::TABLE_AI] as $table) {
            $full = $wpdb->prefix . $table;
            if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $full)) !== $full) {
                $missing = true;
                break;
            }
        }
        if ($missing) {
            self::install();
        }
    }

    /**
     * Creates both log tables and schedules the cron event.
     */
    public static function install(): void {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();

        foreach ([self::TABLE_EMAIL, self::TABLE_IP, self::TABLE_AI] as $table) {
            $full = $wpdb->prefix . $table;
            if ($table === self::TABLE_AI) {
                $sql  = "CREATE TABLE {$full} (
                    id bigint(20) NOT NULL AUTO_INCREMENT,
                    domain varchar(255) NOT NULL,
                    severity varchar(20) NOT NULL DEFAULT 'warning',
                    score int(3) NOT NULL DEFAULT 0,
                    summary_it text,
                    report longtext,
                    scan_data longtext,
                    spf_data longtext,
                    dmarc_data longtext,
                    dkim_data longtext,
                    created_at datetime DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (id),
                    KEY domain (domain)
                ) {$charset};";
            } else {
                $sql  = "CREATE TABLE {$full} (
                    id bigint(20) NOT NULL AUTO_INCREMENT,
                    scan_date datetime DEFAULT CURRENT_TIMESTAMP,
                    ip_address varchar(45) NOT NULL,
                    status varchar(30) NOT NULL,
                    details text,
                    PRIMARY KEY (id)
                ) {$charset};";
            }
            dbDelta($sql);
        }

        if (!wp_next_scheduled('pn_mailguard_daily_scan')) {
            wp_schedule_event(time(), 'daily', 'pn_mailguard_daily_scan');
        }
    }
}