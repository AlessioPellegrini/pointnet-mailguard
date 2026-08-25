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

        // Admin assets (CSS + JS)
        add_action('admin_enqueue_scripts', ['PN_Mailguard_Loader', 'enqueue_admin_assets']);

        // Installation
        register_activation_hook(PN_MAILGUARD_PLUGIN_FILE,   ['PN_Mailguard_Installer', 'activate']);
        register_deactivation_hook(PN_MAILGUARD_PLUGIN_FILE, ['PN_Mailguard_Installer', 'deactivate']);
        add_action('plugins_loaded', ['PN_Mailguard_Installer', 'maybe_install']);

        // Daily cron scan & IMAP report fetch cron
        add_action('pn_mailguard_daily_scan',          ['PN_Mailguard_Scanner', 'run_scheduled']);
        add_action('pn_mailguard_fetch_reports_cron', ['PN_Mailguard_Imap_Fetcher', 'fetch_reports']);

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

        // AJAX — DMARC Analyzer tab & DMARC/TLSRPT Reports
        add_action('wp_ajax_pn_mailguard_analyze_dmarc',       ['PN_Mailguard_Dashboard', 'ajax_analyze_dmarc']);
        add_action('wp_ajax_pn_mailguard_upload_dmarc_report', ['PN_Mailguard_Dashboard', 'ajax_upload_dmarc_report']);
        add_action('wp_ajax_pn_mailguard_delete_dmarc_report', ['PN_Mailguard_Dashboard', 'ajax_delete_dmarc_report']);
        add_action('wp_ajax_pn_mailguard_delete_tls_report',   ['PN_Mailguard_Dashboard', 'ajax_delete_tls_report']);
        add_action('wp_ajax_pn_mailguard_test_imap',           ['PN_Mailguard_Dashboard', 'ajax_test_imap']);
        add_action('wp_ajax_pn_mailguard_fetch_imap_now',      ['PN_Mailguard_Dashboard', 'ajax_fetch_imap_now']);

        // AJAX — DKIM Analyzer tab
        add_action('wp_ajax_pn_mailguard_analyze_dkim',        ['PN_Mailguard_Dashboard', 'ajax_analyze_dkim']);

        // AJAX — MTA-STS Analyzer tab
        add_action('wp_ajax_pn_mailguard_analyze_mtasts',      ['PN_Mailguard_Dashboard', 'ajax_analyze_mtasts']);

        // AJAX — Fetch available models
        add_action('wp_ajax_pn_mailguard_fetch_models',        ['PN_Mailguard_Dashboard', 'ajax_fetch_models']);

        // AJAX — AI Chat
        add_action('wp_ajax_pn_mailguard_ai_chat',             ['PN_Mailguard_Dashboard', 'ajax_ai_chat']);

        // AJAX — AI analysis
        add_action('wp_ajax_pn_mailguard_ai_analyze',          ['PN_Mailguard_Dashboard', 'ajax_ai_analyze']);

        // AJAX — Save monitor settings (inline edit)
        add_action('wp_ajax_pn_mailguard_save_monitor',        ['PN_Mailguard_Dashboard', 'ajax_save_monitor']);

        // AJAX — Export report
        add_action('wp_ajax_pn_mailguard_export_report',       ['PN_Mailguard_Dashboard', 'ajax_export_report']);

        // AJAX — IP Analysis tools (DNS & IP Tools tab)
        add_action('wp_ajax_pn_mailguard_ip_dnsbl',            ['PN_Mailguard_Dashboard', 'ajax_ip_dnsbl']);
        add_action('wp_ajax_pn_mailguard_ip_ptr',              ['PN_Mailguard_Dashboard', 'ajax_ip_ptr']);
        add_action('wp_ajax_pn_mailguard_ip_geoip',            ['PN_Mailguard_Dashboard', 'ajax_ip_geoip']);
        add_action('wp_ajax_pn_mailguard_ip_whois',            ['PN_Mailguard_Dashboard', 'ajax_ip_whois']);
    }

    public static function load_textdomain(): void {
        // WordPress automatically loads translations for plugins hosted on WordPress.org since 4.6.
        // This method is intentionally kept empty as a no-op — no longer needed.
    }

    /**
     * Enqueue admin CSS and JavaScript, and localize JS strings.
     */
    public static function enqueue_admin_assets(): void {
        $screen = get_current_screen();
        // Only load on our plugin page
        if (!$screen || $screen->id !== 'toplevel_page_pn-mailguard') {
            return;
        }

        // CSS
        wp_enqueue_style(
            'pn-mailguard-admin',
            PN_MAILGUARD_PLUGIN_URL . 'assets/admin.css',
            [],
            PN_MAILGUARD_VERSION
        );

        // JavaScript
        wp_enqueue_script(
            'pn-mailguard-admin',
            PN_MAILGUARD_PLUGIN_URL . 'assets/admin.js',
            ['jquery'],
            PN_MAILGUARD_VERSION,
            true // load in footer
        );

        // Localized strings and data for JS
        wp_localize_script('pn-mailguard-admin', 'pnMailguard', [
            'nonce'              => wp_create_nonce('pn_mailguard_ajax_nonce'),
            'running'            => __('Running...', 'pointnet-mailguard'),
            'runScheduled'       => __('Run Scheduled Scan Now', 'pointnet-mailguard'),
            'scanFailed'         => __('Scan failed.', 'pointnet-mailguard'),
            'runEmailDiagnosis'  => __('📧 Run Email Diagnosis', 'pointnet-mailguard'),
            'runIpDiagnosis'     => __('🌐 Run IP Diagnosis', 'pointnet-mailguard'),
            'analyzing'          => __('Analyzing...', 'pointnet-mailguard'),
            'analyzingEmail'     => __('Analyzing email configuration with AI...', 'pointnet-mailguard'),
            'analyzeWithAi'      => __('Analyze with AI', 'pointnet-mailguard'),
            'aiAnalysisFailed'   => __('AI analysis failed.', 'pointnet-mailguard'),
            'you'                => __('You', 'pointnet-mailguard'),
            'send'               => __('Send', 'pointnet-mailguard'),
            'chatFailed'         => __('Failed to get response.', 'pointnet-mailguard'),
            'networkError'       => __('Network error. Please try again.', 'pointnet-mailguard'),
            'enterEmailFirst'    => __('Enter a valid email first (Step 1).', 'pointnet-mailguard'),
            'detectingDkim'      => __('Detecting DKIM selector...', 'pointnet-mailguard'),
            'detect'             => __('Detect', 'pointnet-mailguard'),
            'dkimDetected'       => __('DKIM selector detected:', 'pointnet-mailguard'),
            'dkimFound'          => __('DKIM selector found:', 'pointnet-mailguard'),
            'dkimNotDetected'    => __('Could not auto-detect DKIM selector. You can enter it manually if you know it, or leave empty.', 'pointnet-mailguard'),
            'saveFailed'          => __('Save failed.', 'pointnet-mailguard'),
            'uploadingReport'     => __('Uploading and parsing DMARC report...', 'pointnet-mailguard'),
            'confirmDeleteReport' => __('Are you sure you want to delete this report?', 'pointnet-mailguard'),
            'analysisFailed'     => __('Analysis failed.', 'pointnet-mailguard'),
            'passed'             => __('passed', 'pointnet-mailguard'),
            'warnings'           => __('warnings', 'pointnet-mailguard'),
            'errors'             => __('errors', 'pointnet-mailguard'),
            'pass'               => __('Pass', 'pointnet-mailguard'),
            'warning'            => __('Warning', 'pointnet-mailguard'),
            'analyzeAllRecords'  => __('Analyze All Records', 'pointnet-mailguard'),
            'detectedProviders'  => __('Detected providers:', 'pointnet-mailguard'),
            'analyzeIp'          => __('Analyze IP', 'pointnet-mailguard'),
            'ipListed'           => __('IP is listed on one or more blacklists!', 'pointnet-mailguard'),
            'ipClean'            => __('IP is clean on all checked blacklists.', 'pointnet-mailguard'),
            'noDnsblResults'     => __('No DNSBL results.', 'pointnet-mailguard'),
            'noPtrRecord'        => __('No PTR record found', 'pointnet-mailguard'),
            'ptrFound'           => __('PTR record found', 'pointnet-mailguard'),
            'ip'                 => __('IP', 'pointnet-mailguard'),
            'country'            => __('Country', 'pointnet-mailguard'),
            'region'             => __('Region', 'pointnet-mailguard'),
            'city'               => __('City', 'pointnet-mailguard'),
            'isp'                => __('ISP', 'pointnet-mailguard'),
            'organization'       => __('Organization', 'pointnet-mailguard'),
            'asn'                => __('ASN', 'pointnet-mailguard'),
            'ipRange'            => __('IP Range', 'pointnet-mailguard'),
            'netName'            => __('Net Name', 'pointnet-mailguard'),
            'person'             => __('Person', 'pointnet-mailguard'),
            'email'              => __('Email', 'pointnet-mailguard'),
            'source'             => __('Source', 'pointnet-mailguard'),
            'loading'            => __('Loading...', 'pointnet-mailguard'),
            'fetchingModels'     => __('Fetching available models...', 'pointnet-mailguard'),
            'fetchModels'        => __('Fetch Models', 'pointnet-mailguard'),
            'modelsUpdated'      => __('Models updated successfully.', 'pointnet-mailguard'),
            'noModelsFound'      => __('No models found. Make sure your API key is valid.', 'pointnet-mailguard'),
            'fetchModelsFailed'  => __('Failed to fetch models. Check your API key.', 'pointnet-mailguard'),
        ]);
    }
}