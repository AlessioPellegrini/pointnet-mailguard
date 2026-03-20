<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Scanner
 *
 * Orchestrates all check modules and returns a unified result array.
 * Supports two scan modes:
 *   - run_email($email) : resolves MX → IP, then runs full checks
 *   - run_ip($ip)       : runs DNSBL + PTR directly on a given IPv4
 *
 * To add a new check module (e.g. SPF):
 *   1. Create includes/class-spf.php
 *   2. Uncomment its require_once in pointnet-mailguard.php
 *   3. Add its call below and merge results
 */
class PN_Mailguard_Scanner {

    /**
     * Run a full scan for the given email address.
     *
     * @param string $email
     * @return array
     */
    public static function run_email($email) {
        // Step 1: Resolve MX → mail server IP
        $mx = PN_Mailguard_MX::resolve($email);
        if (!empty($mx['error'])) {
            return array_merge($mx, array(
                'dnsbl'       => array(),
                'is_alert'    => false,
                'ptr'         => '',
                'ptr_warning' => false,
            ));
        }

        $ip    = $mx['mx_ip'];
        $dnsbl = PN_Mailguard_DNSBL::check($ip);
        $ptr   = PN_Mailguard_PTR::check($ip);

        return array(
            'email'         => $mx['email'],
            'domain'        => $mx['domain'],
            'mx_host'       => $mx['mx_host'],
            'mx_ip'         => $ip,
            'wp_ip'         => $mx['wp_ip'],
            'shared_server' => $mx['shared_server'],
            'dnsbl'         => $dnsbl['results'],
            'is_alert'      => $dnsbl['is_alert'],
            'ptr'           => $ptr['ptr'],
            'ptr_warning'   => $ptr['ptr_warning'],
            'error'         => '',
        );
    }

    /**
     * Run DNSBL + PTR checks directly on a given IPv4 address.
     *
     * @param string $ip
     * @return array
     */
    public static function run_ip($ip) {
        if (!PN_Mailguard_MX::is_valid_ipv4($ip)) {
            return array(
                'ip'          => $ip,
                'dnsbl'       => array(),
                'is_alert'    => false,
                'ptr'         => '',
                'ptr_warning' => false,
                'error'       => 'Invalid IPv4 address: ' . $ip,
            );
        }

        $dnsbl = PN_Mailguard_DNSBL::check($ip);
        $ptr   = PN_Mailguard_PTR::check($ip);

        return array(
            'ip'          => $ip,
            'dnsbl'       => $dnsbl['results'],
            'is_alert'    => $dnsbl['is_alert'],
            'ptr'         => $ptr['ptr'],
            'ptr_warning' => $ptr['ptr_warning'],
            'error'       => '',
        );
    }

    /**
     * Run the scheduled daily scan for both email and IP monitors.
     * Called via the pn_mailguard_daily_scan cron hook.
     */
    public static function run_scheduled() {
        // Email scan
        $email = get_option('pn_mailguard_check_email', '');
        if (!empty($email) && is_email($email)) {
            $data = self::run_email($email);
            PN_Mailguard_Logger::save($data, 'email');
            PN_Mailguard_Mailer::maybe_send($data, 'email');
        }

        // IP scan
        $ip = get_option('pn_mailguard_check_ip', '');
        if (!empty($ip) && PN_Mailguard_MX::is_valid_ipv4($ip)) {
            $data = self::run_ip($ip);
            PN_Mailguard_Logger::save($data, 'ip');
            PN_Mailguard_Mailer::maybe_send($data, 'ip');
        }
    }
}
