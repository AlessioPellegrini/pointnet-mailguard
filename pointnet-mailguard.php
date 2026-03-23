<?php
/**
 * Plugin Name: PointNet Mail Guard AI
 * Version: 1.1.0
 * Description: Complete email deliverability monitoring. Checks DNSBL blacklists, PTR record and SMTP configuration natively in PHP — no external dependencies required.
 * Plugin URI: https://www.pointnet.it/
 * Author: PointNet
 * Author URI: https://www.pointnet.it/
 * Text Domain: pointnet-mailguard
 * Domain Path: /languages
 * Requires at least: 5.0
 * Requires PHP: 7.4
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if (!defined('ABSPATH')) exit;

// Abort immediately if PHP version requirement is not met
if (version_compare(PHP_VERSION, '7.4', '<')) {
    add_action('admin_notices', function() {
        echo '<div class="notice notice-error"><p>'
            . '<strong>PointNet Mail Guard AI</strong> requires PHP 7.4 or higher. '
            . 'Your server is running PHP ' . esc_html(PHP_VERSION) . '.</p></div>';
    });
    return;
}

// --- Constants ---
define('PN_MAILGUARD_VERSION',    '1.1.0');
define('PN_MAILGUARD_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('PN_MAILGUARD_PLUGIN_URL', plugin_dir_url(__FILE__));
define('PN_MAILGUARD_PLUGIN_FILE', __FILE__);

// --- Load all classes ---
require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-installer.php';
require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-mx.php';
require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-dnsbl.php';
require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-ptr.php';
require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-spf.php';
// Future modules — uncomment as you add them:
// require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-dmarc.php';
// require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-dkim.php';
require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-scanner.php';
require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-logger.php';
require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-mailer.php';
require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-dashboard.php';
require_once PN_MAILGUARD_PLUGIN_DIR . 'includes/class-loader.php';

// --- Boot ---
PN_Mailguard_Loader::init();
