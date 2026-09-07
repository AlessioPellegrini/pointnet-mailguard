<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_PTR
 *
 * Checks the PTR (reverse DNS) record for an IPv4 address.
 * A missing PTR is a warning — not a blacklist issue — but can cause
 * email delivery problems with receiving servers that require a valid PTR.
 *
 * Usage:
 *   $result = PN_Mailguard_PTR::check('1.2.3.4');
 *
 * Returns array:
 *   [
 *     'ptr'         => 'mail.example.com',  // or 'PTR_ERROR' if lookup failed
 *     'ptr_warning' => true|false
 *   ]
 */
class PN_Mailguard_PTR {

    /**
     * Perform a reverse DNS (PTR) lookup and verify Forward-Confirmed Reverse DNS (FCrDNS).
     *
     * FCrDNS verifies that:
     *   1. The IP resolves to a hostname via PTR record (reverse lookup)
     *   2. That hostname resolves back to the original IP via A/AAAA record (forward lookup)
     *
     * @param string $ip
     * @return array
     */
    public static function check(string $ip): array {
        $ptr = gethostbyaddr($ip);

        // gethostbyaddr() returns false on failure, or the IP itself if no PTR record exists
        $ptr_warning = ($ptr === false || $ptr === $ip);

        $fcrdns_valid = false;
        $forward_ips  = [];
        $fcrdns_msg   = '';

        if (!$ptr_warning && !empty($ptr)) {
            // Forward lookup: resolve PTR hostname to IP(s)
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $dns_aaaa = dns_get_record($ptr, DNS_AAAA);
                if (!empty($dns_aaaa)) {
                    foreach ($dns_aaaa as $r) {
                        if (!empty($r['ipv6'])) {
                            $forward_ips[] = strtolower($r['ipv6']);
                        }
                    }
                }
                $fcrdns_valid = in_array(strtolower($ip), $forward_ips, true);
            } else {
                $ips = gethostbynamel($ptr);
                if (is_array($ips)) {
                    $forward_ips = $ips;
                    $fcrdns_valid = in_array($ip, $forward_ips, true);
                }
            }

            if ($fcrdns_valid) {
                $fcrdns_msg = sprintf(
                    /* translators: 1: IP address, 2: PTR hostname */
                    __('FCrDNS verified: %1$s ↔ %2$s resolves circularly.', 'pointnet-mailguard'),
                    $ip,
                    $ptr
                );
            } else {
                $fcrdns_msg = sprintf(
                    /* translators: 1: PTR hostname, 2: expected IP address */
                    __('FCrDNS mismatch: PTR %1$s does not resolve back to IP %2$s.', 'pointnet-mailguard'),
                    $ptr,
                    $ip
                );
            }
        } else {
            $fcrdns_msg = __('No PTR record found; cannot verify FCrDNS.', 'pointnet-mailguard');
        }

        return [
            'ptr'          => ($ptr === false) ? 'PTR_ERROR' : $ptr,
            'ptr_warning'  => $ptr_warning,
            'fcrdns_valid' => $fcrdns_valid,
            'forward_ips'  => $forward_ips,
            'fcrdns_msg'   => $fcrdns_msg,
        ];
    }
}