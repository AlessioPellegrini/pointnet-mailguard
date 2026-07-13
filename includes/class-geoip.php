<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_GeoIP
 *
 * Performs a geolocation lookup on an IPv4/IPv6 address using the free
 * ipwhois.app API (no API key required, 10k requests/month limit).
 *
 * Previously used ip-api.com which returned HTTP 403 from server IPs.
 *
 * Usage:
 *   $result = PN_Mailguard_GeoIP::lookup('1.2.3.4');
 *
 * Returns array:
 *   [
 *     'country'     => 'Italy',
 *     'countryCode' => 'IT',
 *     'region'      => 'Lazio',
 *     'city'        => 'Rome',
 *     'isp'         => 'Example ISP',
 *     'org'         => 'Example Organization',
 *     'as'          => 'AS12345 Example',
 *     'status'      => 'success',   // or 'error'
 *     'error'       => '',          // error message if any
 *   ]
 */
class PN_Mailguard_GeoIP {

    /**
     * Lookup geolocation data for the given IP address.
     *
     * @param string $ip
     * @return array
     */
    public static function lookup(string $ip): array {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return [
                'status' => 'error',
                /* translators: %s: IP address */
                'error'  => sprintf(__('Invalid IP address: %s', 'pointnet-mailguard'), $ip),
            ];
        }

        // Use ipwhois.app — free tier, 10k requests/month, no API key needed
        $url = 'https://ipwhois.app/json/' . urlencode($ip);

        $response = wp_remote_get($url, [
            'timeout' => 10,
            'headers' => [
                'Accept'     => 'application/json',
                'User-Agent' => 'PointNet-MailGuard/1.0',
            ],
        ]);

        if (is_wp_error($response)) {
            return [
                'status' => 'error',
                /* translators: %s: error message */
                'error'  => sprintf(
                    __('GeoIP lookup failed: %s', 'pointnet-mailguard'),
                    $response->get_error_message()
                ),
            ];
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code !== 200) {
            return [
                'status' => 'error',
                /* translators: %d: HTTP response code */
                'error'  => sprintf(
                    __('GeoIP lookup returned HTTP %d', 'pointnet-mailguard'),
                    $code
                ),
            ];
        }

        $body  = wp_remote_retrieve_body($response);
        $data  = json_decode($body, true);

        if (!is_array($data) || !empty($data['error'])) {
            return [
                'status' => 'error',
                'error'  => $data['error'] ?? __('Invalid response from GeoIP service.', 'pointnet-mailguard'),
            ];
        }

        if (!empty($data['success']) && $data['success'] === false) {
            return [
                'status' => 'error',
                'error'  => $data['message'] ?? __('IP address not found.', 'pointnet-mailguard'),
            ];
        }

        return [
            'status'       => 'success',
            'ip'           => $data['ip'] ?? $ip,
            'country'      => $data['country'] ?? '',
            'countryCode'  => $data['country_code'] ?? '',
            'region'       => $data['region'] ?? '',
            'regionCode'   => $data['region_code'] ?? '',
            'city'         => $data['city'] ?? '',
            'zip'          => $data['postal'] ?? '',
            'lat'          => $data['latitude'] ?? 0,
            'lon'          => $data['longitude'] ?? 0,
            'isp'          => $data['isp'] ?? '',
            'org'          => $data['org'] ?? '',
            'as'           => $data['asn'] ?? '',
            'error'        => '',
        ];
    }
}