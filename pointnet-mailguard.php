<?php
/**
 * Plugin Name: PointNet Mail Guard
 * Version: 1.8.4
 * Description: Complete email deliverability monitoring. Checks DNSBL blacklists, PTR record and SMTP configuration natively in PHP — no external dependencies required.
 * Plugin URI: https://www.pointnet.it/
 * Author: PointNet
 * Author URI: https://www.pointnet.it/
 * Text Domain: pointnet-mailguard
 * Domain Path: /languages
 * Requires at least: 7.0
 * Requires PHP: 8.3
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if (!defined('ABSPATH')) exit;

// Abort immediately if PHP version requirement is not met
if (version_compare(PHP_VERSION, '8.3', '<')) {
    add_action('admin_notices', function() {
        echo '<div class="notice notice-error"><p>'
            . '<strong>PointNet Mail Guard</strong> requires PHP 8.3 or higher. '
            . 'Your server is running PHP ' . esc_html(PHP_VERSION) . '.</p></div>';
    });
    return;
}

// --- Constants ---
define('PN_MAILGUARD_VERSION',    '1.8.4');
define('PN_MAILGUARD_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('PN_MAILGUARD_PLUGIN_URL', plugin_dir_url(__FILE__));
define('PN_MAILGUARD_PLUGIN_FILE', __FILE__);

// --- Load all classes and boot (admin and cron only to save frontend memory) ---
if (is_admin() || wp_doing_cron() || (defined('WP_CLI') && WP_CLI)) {
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-installer.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-mx.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-dnsbl.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-ptr.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-spf.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-dmarc.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-dmarc-parser.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-tlsrpt-parser.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-imap-fetcher.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-dkim.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-mta-sts.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-scanner.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-logger.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-mailer.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-crypto.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-ai.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-geoip.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-whois.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-dashboard.php';
    require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-loader.php';

    // --- Boot ---
    PN_Mailguard_Loader::init();
}