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
    public static function run_email(string $email): array {
        // Step 1: Resolve MX → mail server IP
        $mx = PN_Mailguard_MX::resolve($email);
        if (!empty($mx['error'])) {
            return array_merge($mx, [
                'dnsbl'       => [],
                'is_alert'    => false,
                'ptr'         => '',
                'ptr_warning' => false,
            ]);
        }

        $ip    = $mx['mx_ip'];
        $dnsbl = PN_Mailguard_DNSBL::check($ip);
        $ptr   = PN_Mailguard_PTR::check($ip);
        $spf   = PN_Mailguard_SPF::check($mx['domain']);

        return [
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
            'spf_record'    => $spf['spf_record'],
            'spf_status'    => $spf['spf_status'],
            'spf_warning'   => $spf['spf_warning'],
            'error'         => '',
        ];
    }

    /**
     * Run DNSBL + PTR checks directly on a given IP address.
     * Fully supports both IPv4 and IPv6.
     * Note: DNSBL checks require IPv4 (8 of 9 blacklists do not support IPv6).
     *
     * @param string $ip
     * @return array
     */
    public static function run_ip(string $ip): array {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return [
                'ip'          => $ip,
                'dnsbl'       => [],
                'is_alert'    => false,
                'ptr'         => '',
                'ptr_warning' => false,
                /* translators: %s: IP address */
                'error'       => sprintf(
                    __('Invalid IP address: %s', 'pointnet-mailguard'),
                    $ip
                ),
            ];
        }

        $dnsbl = PN_Mailguard_DNSBL::check($ip);
        $ptr   = PN_Mailguard_PTR::check($ip);

        return [
            'ip'          => $ip,
            'dnsbl'       => $dnsbl['results'],
            'is_alert'    => $dnsbl['is_alert'],
            'ptr'         => $ptr['ptr'],
            'ptr_warning' => $ptr['ptr_warning'],
            'error'       => '',
        ];
    }

    /**
     * Run the scheduled daily scan for both email and IP monitors.
     * Called via the pn_mailguard_daily_scan cron hook.
     */
    public static function run_scheduled(): void {
        // Email scan
        $email = get_option('pn_mailguard_check_email', '');
        if (!empty($email) && is_email($email)) {
            $data = self::run_email($email);
            PN_Mailguard_Logger::save($data, 'email');
            PN_Mailguard_Mailer::maybe_send($data, 'email');
        }

        // IP scan
        $ip = get_option('pn_mailguard_check_ip', '');
        if (!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
            $data = self::run_ip($ip);
            PN_Mailguard_Logger::save($data, 'ip');
            PN_Mailguard_Mailer::maybe_send($data, 'ip');
        }
    }
}