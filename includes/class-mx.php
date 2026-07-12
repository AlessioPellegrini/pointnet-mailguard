<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_MX
 *
 * Resolves the mail server IP from an email address domain.
 * Also detects whether the mail server shares the same IP as the WordPress server.
 *
 * Usage:
 *   $result = PN_Mailguard_MX::resolve('user@example.com');
 *
 * Returns array:
 *   [
 *     'email'         => 'user@example.com',
 *     'domain'        => 'example.com',
 *     'mx_host'       => 'mail.example.com',
 *     'mx_ip'         => '1.2.3.4',
 *     'wp_ip'         => '1.2.3.4',
 *     'shared_server' => true|false,
 *     'error'         => ''
 *   ]
 */
class PN_Mailguard_MX {

    /**
     * Resolve the mail server IP from an email address.
     *
     * @param string $email
     * @return array
     */
    public static function resolve($email): array {
        $result = [
            'email'         => $email,
            'domain'        => '',
            'mx_host'       => '',
            'mx_ip'         => '',
            'wp_ip'         => '',
            'shared_server' => false,
            'error'         => '',
        ];

        // Extract domain from email
        $parts = explode('@', $email);
        if (count($parts) !== 2 || empty($parts[1])) {
            $result['error'] = __('Invalid email address.', 'pointnet-mailguard');
            return $result;
        }
        $domain          = strtolower(trim($parts[1]));
        $result['domain'] = $domain;

        // Get WordPress server IP (forced IPv4)
        $wp_ip            = self::get_server_ip();
        $result['wp_ip']  = $wp_ip;

        // Query MX records for the domain
        $mx_records = dns_get_record($domain, DNS_MX);
        if (empty($mx_records)) {
            $result['error'] = sprintf(
                __('No MX records found for domain: %s', 'pointnet-mailguard'),
                $domain
            );
            return $result;
        }

        // Sort by priority (lowest = highest priority)
        usort($mx_records, fn($a, $b) => $a['pri'] - $b['pri']);

        $mx_host          = $mx_records[0]['target'];
        $result['mx_host'] = $mx_host;

        // Resolve MX hostname to IPv4
        $mx_ip = gethostbyname($mx_host);
        if ($mx_ip === $mx_host) {
            $result['error'] = sprintf(
                __('Could not resolve MX host to IP: %s', 'pointnet-mailguard'),
                $mx_host
            );
            return $result;
        }

        // Validate it resolved to an IPv4
        if (!filter_var($mx_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $result['error'] = sprintf(
                __('MX host did not resolve to a valid IPv4 address: %s', 'pointnet-mailguard'),
                $mx_ip
            );
            return $result;
        }

        $result['mx_ip']         = $mx_ip;
        $result['shared_server'] = (!empty($wp_ip) && $mx_ip === $wp_ip);

        return $result;
    }

    /**
     * Fetch the WordPress server's public IPv4 address via v4.ident.me.
     * Forces IPv4 to handle dual-stack servers (e.g. Hetzner).
     *
     * @return string IPv4 address or empty string on failure
     */
    public static function get_server_ip(): string {
        $response = wp_remote_get('https://v4.ident.me', ['timeout' => 5]);
        if (is_wp_error($response)) {
            return '';
        }
        $ip = trim(wp_remote_retrieve_body($response));
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? $ip : '';
    }

    /**
     * Validate that a string is a valid IPv4 address.
     *
     * @param string $ip
     * @return bool
     */
    public static function is_valid_ipv4(string $ip): bool {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }
}