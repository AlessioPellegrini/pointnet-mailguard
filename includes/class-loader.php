<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Loader
 *
 * Registers all WordPress hooks for the plugin.
 * This is the only place where add_action / add_filter are called.
 */
class PN_Mailguard_Loader {

    public static function init(): void {
        // Translations
        add_action('init', ['PN_Mailguard_Loader', 'load_textdomain']);

        // Installation
        register_activation_hook(PN_MAILGUARD_PLUGIN_FILE,   ['PN_Mailguard_Installer', 'activate']);
        register_deactivation_hook(PN_MAILGUARD_PLUGIN_FILE, ['PN_Mailguard_Installer', 'deactivate']);
        add_action('plugins_loaded', ['PN_Mailguard_Installer', 'maybe_install']);

        // Daily cron scan (runs both email and IP)
        add_action('pn_mailguard_daily_scan', ['PN_Mailguard_Scanner', 'run_scheduled']);

        // Settings
        add_action('admin_init', ['PN_Mailguard_Dashboard', 'register_settings']);
        add_action('admin_init', ['PN_Mailguard_Dashboard', 'save_settings']);

        // Admin menu
        add_action('admin_menu', ['PN_Mailguard_Dashboard', 'add_menu']);

        // Plugin action links
        add_filter('plugin_action_links_' . plugin_basename(PN_MAILGUARD_PLUGIN_FILE),
            ['PN_Mailguard_Dashboard', 'action_links']
        );

        // AJAX — Run scheduled scan now
        add_action('wp_ajax_pn_mailguard_run_scheduled',       ['PN_Mailguard_Dashboard', 'ajax_run_scheduled']);

        // AJAX — Email tab
        add_action('wp_ajax_pn_mailguard_start_scan_email',   ['PN_Mailguard_Dashboard', 'ajax_start_scan_email']);
        add_action('wp_ajax_pn_mailguard_refresh_logs_email', ['PN_Mailguard_Dashboard', 'ajax_refresh_logs_email']);

        // AJAX — IP tab
        add_action('wp_ajax_pn_mailguard_start_scan_ip',      ['PN_Mailguard_Dashboard', 'ajax_start_scan_ip']);
        add_action('wp_ajax_pn_mailguard_refresh_logs_ip',    ['PN_Mailguard_Dashboard', 'ajax_refresh_logs_ip']);

        // AJAX — SPF Analyzer tab
        add_action('wp_ajax_pn_mailguard_analyze_spf',        ['PN_Mailguard_Dashboard', 'ajax_analyze_spf']);

        // AJAX — DMARC Analyzer tab
        add_action('wp_ajax_pn_mailguard_analyze_dmarc',       ['PN_Mailguard_Dashboard', 'ajax_analyze_dmarc']);

        // AJAX — DKIM Analyzer tab
        add_action('wp_ajax_pn_mailguard_analyze_dkim',        ['PN_Mailguard_Dashboard', 'ajax_analyze_dkim']);

        // AJAX — Fetch available models
        add_action('wp_ajax_pn_mailguard_fetch_models',        ['PN_Mailguard_Dashboard', 'ajax_fetch_models']);

        // AJAX — AI Chat
        add_action('wp_ajax_pn_mailguard_ai_chat',             ['PN_Mailguard_Dashboard', 'ajax_ai_chat']);

        // AJAX — AI analysis
        add_action('wp_ajax_pn_mailguard_ai_analyze',          ['PN_Mailguard_Dashboard', 'ajax_ai_analyze']);

        // AJAX — Save monitor settings (inline edit)
        add_action('wp_ajax_pn_mailguard_save_monitor',        ['PN_Mailguard_Dashboard', 'ajax_save_monitor']);

        // AJAX — IP Analysis tools (DNS & IP Tools tab)
        add_action('wp_ajax_pn_mailguard_ip_dnsbl',            ['PN_Mailguard_Dashboard', 'ajax_ip_dnsbl']);
        add_action('wp_ajax_pn_mailguard_ip_ptr',              ['PN_Mailguard_Dashboard', 'ajax_ip_ptr']);
        add_action('wp_ajax_pn_mailguard_ip_geoip',            ['PN_Mailguard_Dashboard', 'ajax_ip_geoip']);
        add_action('wp_ajax_pn_mailguard_ip_whois',            ['PN_Mailguard_Dashboard', 'ajax_ip_whois']);
    }

    public static function load_textdomain(): void {
        load_plugin_textdomain(
            'pointnet-mailguard',
            false,
            dirname(plugin_basename(PN_MAILGUARD_PLUGIN_FILE)) . '/languages'
        );
    }
}