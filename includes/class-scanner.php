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

        // DMARC quick check
        $dmarc_data = PN_Mailguard_DMARC::analyze($mx['domain']);
        $dmarc_status = $dmarc_data['status'] ?? 'missing';
        $dmarc_errors = $dmarc_data['errors'] ?? 0;
        $dmarc_warnings = $dmarc_data['warnings'] ?? 0;

        // DKIM quick check
        // Skip auto-detection for public email providers (Gmail, Outlook, Libero, etc.)
        // as they do not publish DKIM records in public DNS — the selector is only
        // included in the DKIM-Signature header of actually sent emails.
        $is_public = PN_Mailguard_DKIM::is_public_provider($mx['domain']);
        $dkim_sel = get_option('pn_mailguard_dkim_selector', '');
        if (empty($dkim_sel) && !$is_public) {
            $d = PN_Mailguard_DKIM::autodetect($mx['domain']);
            if (!empty($d['selector'])) {
                $dkim_sel = $d['selector'];
                update_option('pn_mailguard_dkim_selector', $dkim_sel);
            }
        }
        $dkim_status = 'missing';
        $dkim_errors = 0;
        $dkim_warnings = 0;
        if (!empty($dkim_sel)) {
            $dkim_data = PN_Mailguard_DKIM::analyze($mx['domain'], $dkim_sel);
            $dkim_status    = $dkim_data['status'] ?? 'missing';
            $dkim_errors    = $dkim_data['errors'] ?? 0;
            $dkim_warnings  = $dkim_data['warnings'] ?? 0;
        }

        // MTA-STS quick check — use check() which normalizes error → warning
        $mtasts_data = PN_Mailguard_MTA_STS::check($mx['domain']);

        // DNSSEC quick check
        $dnssec_data = PN_Mailguard_Dnssec::analyze($mx['domain']);
        $dnssec_status = $dnssec_data['status'] ?? 'warning';

        return [
            'email'          => $mx['email'],
            'domain'         => $mx['domain'],
            'mx_host'        => $mx['mx_host'],
            'mx_ip'          => $ip,
            'wp_ip'          => $mx['wp_ip'],
            'shared_server'  => $mx['shared_server'],
            'dnsbl'          => $dnsbl['results'],
            'is_alert'       => $dnsbl['is_alert'],
            'ptr'            => $ptr['ptr'],
            'ptr_warning'    => $ptr['ptr_warning'],
            'spf_record'     => $spf['spf_record'],
            'spf_status'     => $spf['spf_status'],
            'spf_warning'    => $spf['spf_warning'],
            'dmarc_status'   => $dmarc_status,
            'dmarc_errors'   => $dmarc_errors,
            'dmarc_warnings' => $dmarc_warnings,
            'dkim_status'    => $dkim_status,
            'dkim_errors'    => $dkim_errors,
            'dkim_warnings'  => $dkim_warnings,
            'mtasts_status'  => $mtasts_data['mtasts_status'],
            'mtasts_record'  => $mtasts_data['mtasts_record'],
            'mtasts_warning' => $mtasts_data['mtasts_warning'],
            'dnssec_status'  => $dnssec_status,
            'dnssec_enabled' => $dnssec_data['enabled'] ?? false,
            'dnssec_warning' => ($dnssec_status !== 'ok'),
            'dmarc_warning'  => ($dmarc_status !== 'ok'),
            'dkim_warning'   => ($dkim_status !== 'ok'),
            'error'          => '',
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
                'error'       => sprintf(
                    /* translators: %s: IP address */
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
     * Run full DNS analysis (SPF, DMARC, DKIM, MTA-STS, DNSSEC) and store results
     * in a transient for fast loading by the Monitors tab.
     *
     * This is called automatically after each email scan (manual or cron)
     * so that render_monitors() can display the complete check tables
     * without performing live DNS lookups on every admin page load.
     *
     * The transient has a TTL of 24 hours and is refreshed on every scan.
     *
     * @param string $email    The monitored email address (to extract the domain).
     * @param string $selector Optional DKIM selector.
     */
    public static function cache_dns_analysis(string $email, string $selector = ''): void {
        $domain = '';
        if (!empty($email) && is_email($email)) {
            $parts = explode('@', $email);
            $domain = strtolower(trim($parts[1]));
        }
        if (empty($domain)) {
            return;
        }

        $spf_data    = PN_Mailguard_SPF::analyze($domain);
        $dmarc_data  = PN_Mailguard_DMARC::analyze($domain);

        if (empty($selector)) {
            $selector = get_option('pn_mailguard_dkim_selector', '');
        }
        if (empty($selector) && !PN_Mailguard_DKIM::is_public_provider($domain)) {
            $d = PN_Mailguard_DKIM::autodetect($domain);
            if (!empty($d['selector'])) {
                $selector = $d['selector'];
                update_option('pn_mailguard_dkim_selector', $selector);
            }
        }
        $dkim_data = null;
        if (!empty($selector)) {
            $dkim_data = PN_Mailguard_DKIM::analyze($domain, $selector);
        }

        $mtasts_data = PN_Mailguard_MTA_STS::analyze($domain);
        $dnssec_data = PN_Mailguard_Dnssec::analyze($domain);

        // Store in a transient (stored in wp_options, auto-expires after 24h).
        // Plugin consumers read this via get_transient() to avoid blocking DNS lookups.
        set_transient(
            'pn_mailguard_dns_cache_' . $domain,
            [
                'spf'    => $spf_data,
                'dmarc'  => $dmarc_data,
                'dkim'   => $dkim_data,
                'mtasts' => $mtasts_data,
                'dnssec' => $dnssec_data,
            ],
            DAY_IN_SECONDS
        );
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
            self::cache_dns_analysis($email);
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