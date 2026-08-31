<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Installer
 *
 * Handles plugin activation, deactivation and database setup.
 * Creates two separate log tables — one for email scans, one for IP scans.
 */
class PN_Mailguard_Installer {

    const string TABLE_EMAIL         = 'pointnet_mailguard_log_email';
    const string TABLE_IP            = 'pointnet_mailguard_log_ip';
    const string TABLE_AI            = 'pointnet_mailguard_ai_results';
    const string TABLE_DMARC_REPORTS = 'pointnet_mailguard_dmarc_reports';
    const string TABLE_DMARC_RECORDS = 'pointnet_mailguard_dmarc_records';
    const string TABLE_TLS_REPORTS   = 'pointnet_mailguard_tls_reports';
    const string TABLE_TLS_RECORDS   = 'pointnet_mailguard_tls_records';

    public static function activate(): void {
        self::install();
    }

    public static function deactivate(): void {
        $timestamp = wp_next_scheduled('pn_mailguard_daily_scan');
        if ($timestamp) {
            wp_unschedule_event($timestamp, 'pn_mailguard_daily_scan');
        }
        $imap_ts = wp_next_scheduled('pn_mailguard_fetch_reports_cron');
        if ($imap_ts) {
            wp_unschedule_event($imap_ts, 'pn_mailguard_fetch_reports_cron');
        }
    }

    /**
     * Called on plugins_loaded — creates missing tables on updates and reinstalls.
     */
    public static function maybe_install(): void {
        global $wpdb;
        $missing = false;
        foreach ([self::TABLE_EMAIL, self::TABLE_IP, self::TABLE_AI, self::TABLE_DMARC_REPORTS, self::TABLE_DMARC_RECORDS, self::TABLE_TLS_REPORTS, self::TABLE_TLS_RECORDS] as $table) {
            $full = $wpdb->prefix . $table;
            if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $full)) !== $full) {
                $missing = true;
                break;
            }
        }
        if ($missing) {
            self::install();
        }

        // Add mtasts_data column if missing (migration from v1.7.x to v1.8.0)
        $ai_table = $wpdb->prefix . self::TABLE_AI;
        $column   = $wpdb->get_results(
            $wpdb->prepare("SHOW COLUMNS FROM %i LIKE 'mtasts_data'", $ai_table)
        );
        if (empty($column)) {
            $wpdb->query($wpdb->prepare("ALTER TABLE %i ADD COLUMN mtasts_data longtext AFTER dkim_data", $ai_table));
        }
    }

    /**
     * Creates both log tables and schedules the cron event.
     */
    public static function install(): void {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();

        foreach ([self::TABLE_EMAIL, self::TABLE_IP, self::TABLE_AI, self::TABLE_DMARC_REPORTS, self::TABLE_DMARC_RECORDS, self::TABLE_TLS_REPORTS, self::TABLE_TLS_RECORDS] as $table) {
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
                    mtasts_data longtext,
                    created_at datetime DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (id),
                    KEY domain (domain)
                ) {$charset};";
            } elseif ($table === self::TABLE_DMARC_REPORTS) {
                $sql  = "CREATE TABLE {$full} (
                    id bigint(20) NOT NULL AUTO_INCREMENT,
                    report_id varchar(255) NOT NULL,
                    org_name varchar(255) NOT NULL,
                    email varchar(255) DEFAULT '',
                    domain varchar(255) NOT NULL,
                    date_begin datetime DEFAULT NULL,
                    date_end datetime DEFAULT NULL,
                    total_messages int(11) NOT NULL DEFAULT 0,
                    passed_messages int(11) NOT NULL DEFAULT 0,
                    failed_messages int(11) NOT NULL DEFAULT 0,
                    pass_rate float NOT NULL DEFAULT 0,
                    policy_published text DEFAULT NULL,
                    raw_xml longtext DEFAULT NULL,
                    created_at datetime DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (id),
                    KEY domain (domain),
                    KEY org_name (org_name)
                ) {$charset};";
            } elseif ($table === self::TABLE_DMARC_RECORDS) {
                $sql  = "CREATE TABLE {$full} (
                    id bigint(20) NOT NULL AUTO_INCREMENT,
                    report_id_fk bigint(20) NOT NULL,
                    source_ip varchar(45) NOT NULL,
                    count int(11) NOT NULL DEFAULT 0,
                    disposition varchar(20) NOT NULL DEFAULT 'none',
                    dkim_eval varchar(20) NOT NULL DEFAULT 'fail',
                    spf_eval varchar(20) NOT NULL DEFAULT 'fail',
                    header_from varchar(255) DEFAULT '',
                    envelope_from varchar(255) DEFAULT '',
                    envelope_to varchar(255) DEFAULT '',
                    country_code varchar(5) DEFAULT '',
                    auth_details longtext DEFAULT NULL,
                    PRIMARY KEY (id),
                    KEY report_id_fk (report_id_fk),
                    KEY source_ip (source_ip)
                ) {$charset};";
            } elseif ($table === self::TABLE_TLS_REPORTS) {
                $sql  = "CREATE TABLE {$full} (
                    id bigint(20) NOT NULL AUTO_INCREMENT,
                    report_id varchar(255) NOT NULL,
                    org_name varchar(255) NOT NULL,
                    contact_info varchar(255) DEFAULT '',
                    domain varchar(255) NOT NULL,
                    date_begin datetime DEFAULT NULL,
                    date_end datetime DEFAULT NULL,
                    successful_sessions int(11) NOT NULL DEFAULT 0,
                    failed_sessions int(11) NOT NULL DEFAULT 0,
                    success_rate float NOT NULL DEFAULT 100,
                    policies_json longtext DEFAULT NULL,
                    created_at datetime DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (id),
                    KEY domain (domain),
                    KEY org_name (org_name)
                ) {$charset};";
            } elseif ($table === self::TABLE_TLS_RECORDS) {
                $sql  = "CREATE TABLE {$full} (
                    id bigint(20) NOT NULL AUTO_INCREMENT,
                    report_id_fk bigint(20) NOT NULL,
                    policy_type varchar(50) NOT NULL DEFAULT 'sts',
                    policy_domain varchar(255) NOT NULL,
                    successful_count int(11) NOT NULL DEFAULT 0,
                    failed_count int(11) NOT NULL DEFAULT 0,
                    failure_details_json longtext DEFAULT NULL,
                    PRIMARY KEY (id),
                    KEY report_id_fk (report_id_fk),
                    KEY policy_domain (policy_domain)
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
