<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Loader
 *
 * Registers all WordPress hooks for the plugin.
 * This is the only place where add_action / add_filter are called.
 */
class PN_Mailguard_Loader {

    public static function init() {
        // Translations
        add_action('init', array('PN_Mailguard_Loader', 'load_textdomain'));

        // Installation
        register_activation_hook(PN_MAILGUARD_PLUGIN_FILE,   array('PN_Mailguard_Installer', 'activate'));
        register_deactivation_hook(PN_MAILGUARD_PLUGIN_FILE, array('PN_Mailguard_Installer', 'deactivate'));
        add_action('plugins_loaded', array('PN_Mailguard_Installer', 'maybe_install'));

        // Daily cron scan (runs both email and IP)
        add_action('pn_mailguard_daily_scan', array('PN_Mailguard_Scanner', 'run_scheduled'));

        // Settings
        add_action('admin_init', array('PN_Mailguard_Dashboard', 'register_settings'));
        add_action('admin_init', array('PN_Mailguard_Dashboard', 'save_settings'));

        // Admin menu
        add_action('admin_menu', array('PN_Mailguard_Dashboard', 'add_menu'));

        // Plugin action links
        add_filter('plugin_action_links_' . plugin_basename(PN_MAILGUARD_PLUGIN_FILE),
            array('PN_Mailguard_Dashboard', 'action_links')
        );

        // AJAX — Email tab
        add_action('wp_ajax_pn_mailguard_start_scan_email',   array('PN_Mailguard_Dashboard', 'ajax_start_scan_email'));
        add_action('wp_ajax_pn_mailguard_refresh_logs_email', array('PN_Mailguard_Dashboard', 'ajax_refresh_logs_email'));

        // AJAX — IP tab
        add_action('wp_ajax_pn_mailguard_start_scan_ip',      array('PN_Mailguard_Dashboard', 'ajax_start_scan_ip'));
        add_action('wp_ajax_pn_mailguard_refresh_logs_ip',    array('PN_Mailguard_Dashboard', 'ajax_refresh_logs_ip'));
    }

    public static function load_textdomain() {
        load_plugin_textdomain(
            'pointnet-mailguard',
            false,
            dirname(plugin_basename(PN_MAILGUARD_PLUGIN_FILE)) . '/languages'
        );
    }
}
