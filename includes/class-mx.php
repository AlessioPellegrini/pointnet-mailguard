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
                /* translators: %s: domain name */
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
                /* translators: %s: MX hostname */
                __('Could not resolve MX host to IP: %s', 'pointnet-mailguard'),
                $mx_host
            );
            return $result;
        }

        // Validate it resolved to an IPv4
        if (!filter_var($mx_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $result['error'] = sprintf(
                /* translators: %s: resolved IP address */
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
     * Get sorted MX hosts for a domain.
     *
     * @param string $domain
     * @return array List of array('host' => string, 'priority' => int)
     */
    public static function get_mx_hosts(string $domain): array {
        $domain = strtolower(trim($domain));
        if (empty($domain)) {
            return [];
        }

        $records = @dns_get_record($domain, DNS_MX);
        if (empty($records)) {
            return [];
        }

        usort($records, fn($a, $b) => ($a['pri'] ?? 0) - ($b['pri'] ?? 0));

        $hosts = [];
        foreach ($records as $r) {
            if (!empty($r['target'])) {
                $hosts[] = [
                    'host'     => strtolower($r['target']),
                    'priority' => intval($r['pri'] ?? 0),
                ];
            }
        }
        return $hosts;
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

    /**
     * Test SMTP connectivity on port 25, negotiate STARTTLS, and validate the SSL/TLS certificate.
     *
     * Connects to the MX server, reads the initial 220 banner, issues EHLO and STARTTLS,
     * extracts certificate details (expiry, CN, SANs, issuer), and verifies MTA-STS compatibility.
     *
     * @param string $mx_host  Hostname or IP of the mail server
     * @param int    $port     Port to connect to (default 25)
     * @return array
     */
    public static function check_smtp_tls(string $mx_host, int $port = 25): array {
        $res = [
            'host'               => $mx_host,
            'port'               => $port,
            'connected'          => false,
            'banner'             => '',
            'banner_host'        => '',
            'starttls_supported' => false,
            'tls_active'         => false,
            'cert_valid'         => false,
            'cert_subject'       => '',
            'cert_issuer'        => '',
            'cert_valid_to'      => '',
            'days_remaining'     => 0,
            'is_expired'         => false,
            'san_list'           => [],
            'host_matches_cert'  => false,
            'error'              => '',
        ];

        if (empty($mx_host)) {
            $res['error'] = __('No MX host provided.', 'pointnet-mailguard');
            return $res;
        }

        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer'       => false, // Allow inspection of expired/self-signed certs
                'verify_peer_name'  => false,
                'allow_self_signed' => true,
            ],
        ]);

        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_client("tcp://{$mx_host}:{$port}", $errno, $errstr, 4, STREAM_CLIENT_CONNECT, $context);

        if (!$socket) {
            $res['error'] = !empty($errstr) ? $errstr : sprintf(__('Could not connect to %1$s on port %2$d (connection refused or port filtered).', 'pointnet-mailguard'), $mx_host, $port);
            return $res;
        }

        $res['connected'] = true;
        stream_set_timeout($socket, 3);

        // 1. Read initial 220 Banner
        $banner = fgets($socket, 1024);
        if ($banner !== false) {
            $res['banner'] = trim($banner);
            if (preg_match('/^220[ -]([a-zA-Z0-9.\-_]+)/i', $res['banner'], $m)) {
                $res['banner_host'] = strtolower($m[1]);
            }
        }

        // 2. Send EHLO
        fwrite($socket, "EHLO mailguard.test\r\n");
        $ehlo_response = '';
        while (!feof($socket)) {
            $line = fgets($socket, 1024);
            if ($line === false) break;
            $ehlo_response .= $line;
            // 250 is the last line of multi-line response (e.g. 250 HELP, not 250-HELP)
            if (preg_match('/^250 /', $line) || !preg_match('/^250-/', $line)) {
                break;
            }
        }

        // 3. Check for STARTTLS in EHLO response
        if (preg_match('/250[ -]STARTTLS/i', $ehlo_response)) {
            $res['starttls_supported'] = true;

            // Send STARTTLS command
            fwrite($socket, "STARTTLS\r\n");
            $starttls_resp = fgets($socket, 1024);

            if ($starttls_resp && str_starts_with(trim($starttls_resp), '220')) {
                // 4. Upgrade stream to TLS
                $crypto_method = STREAM_CRYPTO_METHOD_TLS_CLIENT;
                if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT')) {
                    $crypto_method |= STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
                }
                if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
                    $crypto_method |= STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
                }

                $crypto_ok = @stream_socket_enable_crypto($socket, true, $crypto_method);

                if ($crypto_ok) {
                    $res['tls_active'] = true;

                    // 5. Inspect peer certificate
                    $params = stream_context_get_params($socket);
                    $cert_resource = $params['options']['ssl']['peer_certificate'] ?? null;

                    if ($cert_resource) {
                        $cert_info = openssl_x509_parse($cert_resource);
                        if (is_array($cert_info)) {
                            $res['cert_subject'] = $cert_info['subject']['CN'] ?? '';
                            $res['cert_issuer']  = $cert_info['issuer']['O'] ?? ($cert_info['issuer']['CN'] ?? 'Unknown');

                            $valid_to = intval($cert_info['validTo_time_t'] ?? 0);
                            if ($valid_to > 0) {
                                $res['cert_valid_to']  = gmdate('Y-m-d H:i:s\Z', $valid_to);
                                $res['days_remaining'] = intval(($valid_to - time()) / 86400);
                                $res['is_expired']     = (time() > $valid_to);
                                $res['cert_valid']     = !$res['is_expired'];
                            }

                            // Extract SANs
                            $san_raw = $cert_info['extensions']['subjectAltName'] ?? '';
                            $sans = [];
                            if (!empty($san_raw)) {
                                $san_parts = explode(',', $san_raw);
                                foreach ($san_parts as $sp) {
                                    $sp = trim($sp);
                                    if (str_starts_with($sp, 'DNS:')) {
                                        $sans[] = strtolower(substr($sp, 4));
                                    }
                                }
                            }
                            $res['san_list'] = array_unique($sans);

                            // Check hostname match (against CN or SANs)
                            $patterns = $res['san_list'];
                            if (!empty($res['cert_subject'])) {
                                $patterns[] = strtolower($res['cert_subject']);
                            }

                            foreach ($patterns as $pat) {
                                if (self::hostname_matches_pattern($mx_host, $pat)) {
                                    $res['host_matches_cert'] = true;
                                    break;
                                }
                            }
                        }
                    }
                } else {
                    $res['error'] = __('STARTTLS handshake failed during crypto negotiation.', 'pointnet-mailguard');
                }
            }
        }

        // Send QUIT and close
        @fwrite($socket, "QUIT\r\n");
        @fclose($socket);

        return $res;
    }

    /**
     * Check if a hostname matches a certificate pattern (supporting wildcards like *.example.com).
     *
     * @param string $hostname
     * @param string $pattern
     * @return bool
     */
    public static function hostname_matches_pattern(string $hostname, string $pattern): bool {
        $hostname = strtolower(trim($hostname));
        $pattern  = strtolower(trim($pattern));
        if ($hostname === $pattern) {
            return true;
        }
        if (str_starts_with($pattern, '*.')) {
            $base = substr($pattern, 2);
            $parts = explode('.', $hostname);
            if (count($parts) >= 2) {
                array_shift($parts);
                return implode('.', $parts) === $base;
            }
        }
        return false;
    }
}