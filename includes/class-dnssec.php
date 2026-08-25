<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Dnssec
 *
 * Analyzes DNSSEC (Domain Name System Security Extensions) deployment and validation status
 * for a domain using DNS-over-HTTPS (DoH) queries to verify DS and DNSKEY records and AD flags.
 */
class PN_Mailguard_Dnssec {

    /**
     * Perform DNSSEC analysis for a given domain.
     *
     * @param string $domain
     * @return array
     */
    public static function analyze(string $domain): array {
        $domain = strtolower(trim($domain));
        // Strip protocol/path if provided
        $domain = preg_replace('#^https?://#i', '', $domain);
        $domain = strtok($domain, '/');

        if (empty($domain) || !filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return [
                'domain'         => $domain,
                'record'         => '',
                'status'         => 'error',
                'enabled'        => false,
                'ad_flag'        => false,
                'ds_records'     => [],
                'dnskey_records' => [],
                'passed'         => 0,
                'warnings'       => 0,
                'errors'         => 1,
                'checks'         => [
                    [
                        'id'          => 'domain_format',
                        'status'      => 'error',
                        'title'       => __('Invalid Domain', 'pointnet-mailguard'),
                        'description' => __('Please provide a valid domain name.', 'pointnet-mailguard'),
                    ]
                ],
                'details'        => [
                    [
                        'check'   => 'Domain Format',
                        'status'  => 'error',
                        'label'   => __('Invalid Domain', 'pointnet-mailguard'),
                        'message' => __('Please provide a valid domain name.', 'pointnet-mailguard'),
                    ]
                ],
            ];
        }

        // Query DS (type 43) records
        $ds_res = self::query_doh($domain, 'DS');
        // Query DNSKEY (type 48) records
        $dnskey_res = self::query_doh($domain, 'DNSKEY');

        $ds_records     = [];
        $dnskey_records = [];
        $has_ds         = false;
        $has_dnskey     = false;
        $ad_flag        = !empty($ds_res['AD']) || !empty($dnskey_res['AD']);
        $servfail       = ($ds_res['Status'] ?? 0) === 2 || ($dnskey_res['Status'] ?? 0) === 2;

        if (!empty($ds_res['Answer']) && is_array($ds_res['Answer'])) {
            foreach ($ds_res['Answer'] as $ans) {
                if (($ans['type'] ?? 0) === 43) {
                    $has_ds = true;
                    $ds_records[] = [
                        'name' => $ans['name'] ?? $domain,
                        'ttl'  => $ans['TTL'] ?? 0,
                        'data' => $ans['data'] ?? '',
                    ];
                }
            }
        }

        if (!empty($dnskey_res['Answer']) && is_array($dnskey_res['Answer'])) {
            foreach ($dnskey_res['Answer'] as $ans) {
                if (($ans['type'] ?? 0) === 48) {
                    $has_dnskey = true;
                    $dnskey_records[] = [
                        'name' => $ans['name'] ?? $domain,
                        'ttl'  => $ans['TTL'] ?? 0,
                        'data' => $ans['data'] ?? '',
                    ];
                }
            }
        }

        $checks   = [];
        $passed   = 0;
        $warnings = 0;
        $errors   = 0;
        $status   = 'warning';
        $enabled  = false;

        if ($servfail) {
            $status  = 'error';
            $enabled = false;
            $errors++;
            $checks[] = [
                'id'          => 'dnssec_validation',
                'status'      => 'error',
                'title'       => __('DNSSEC Validation Failure (SERVFAIL)', 'pointnet-mailguard'),
                'description' => __('DNS server returned SERVFAIL. The DNSSEC signature chain is broken or invalid for this domain.', 'pointnet-mailguard'),
            ];
        } elseif ($has_ds && $ad_flag) {
            $status  = 'ok';
            $enabled = true;
            $passed++;
            $checks[] = [
                'id'          => 'dnssec_status',
                'status'      => 'ok',
                'title'       => __('DNSSEC Active & Validated', 'pointnet-mailguard'),
                'description' => __('DNSSEC is fully configured with valid DS records and authenticated data (AD) flag.', 'pointnet-mailguard'),
            ];
        } elseif ($has_ds) {
            $status  = 'ok';
            $enabled = true;
            $passed++;
            $checks[] = [
                'id'          => 'dnssec_status',
                'status'      => 'ok',
                'title'       => __('DNSSEC Active (DS Present)', 'pointnet-mailguard'),
                'description' => __('DS records found for domain.', 'pointnet-mailguard'),
            ];
        } else {
            $status  = 'warning';
            $enabled = false;
            $warnings++;
            $checks[] = [
                'id'          => 'dnssec_status',
                'status'      => 'warning',
                'title'       => __('DNSSEC Not Active', 'pointnet-mailguard'),
                'description' => __('No DS records found for this domain. Enable DNSSEC at your domain registrar and DNS provider for enhanced security.', 'pointnet-mailguard'),
            ];
        }

        // Add DS Record Detail
        if ($has_ds) {
            $passed++;
            $checks[] = [
                'id'          => 'ds_records',
                'status'      => 'ok',
                'title'       => sprintf(__('Found %d DS Record(s)', 'pointnet-mailguard'), count($ds_records)),
                'description' => __('Delegation Signer (DS) record is present at parent TLD registry.', 'pointnet-mailguard'),
            ];
        } else {
            $warnings++;
            $checks[] = [
                'id'          => 'ds_records',
                'status'      => 'warning',
                'title'       => __('Missing DS Record', 'pointnet-mailguard'),
                'description' => __('No DS record delegating DNSSEC trust to this domain.', 'pointnet-mailguard'),
            ];
        }

        // Add DNSKEY Detail
        if ($has_dnskey) {
            $passed++;
            $checks[] = [
                'id'          => 'dnskey_records',
                'status'      => 'ok',
                'title'       => sprintf(__('Found %d DNSKEY Record(s)', 'pointnet-mailguard'), count($dnskey_records)),
                'description' => __('Public Zone Signing Keys (ZSK/KSK) found in DNS.', 'pointnet-mailguard'),
            ];
        } else {
            $checks[] = [
                'id'          => 'dnskey_records',
                'status'      => 'info',
                'title'       => __('No Public DNSKEY Records', 'pointnet-mailguard'),
                'description' => __('DNSKEY records not returned in response.', 'pointnet-mailguard'),
            ];
        }

        $record_summary = '';
        if (!empty($ds_records)) {
            $record_summary = 'DS Record: ' . ($ds_records[0]['data'] ?? '');
        }

        return [
            'domain'         => $domain,
            'record'         => $record_summary,
            'status'         => $status,
            'enabled'        => $enabled,
            'ad_flag'        => $ad_flag,
            'ds_records'     => $ds_records,
            'dnskey_records' => $dnskey_records,
            'passed'         => $passed,
            'warnings'       => $warnings,
            'errors'         => $errors,
            'checks'         => $checks,
            'details'        => $checks,
        ];
    }

    /**
     * Query DNS-over-HTTPS (DoH) API.
     *
     * @param string $domain
     * @param string $type DS or DNSKEY
     * @return array
     */
    private static function query_doh(string $domain, string $type): array {
        // Try Google DoH first
        $url = 'https://dns.google/resolve?name=' . urlencode($domain) . '&type=' . urlencode($type);
        $res = wp_remote_get($url, [
            'timeout' => 5,
            'headers' => ['Accept' => 'application/json']
        ]);

        if (!is_wp_error($res) && wp_remote_retrieve_response_code($res) === 200) {
            $body = wp_remote_retrieve_body($res);
            $data = json_decode($body, true);
            if (is_array($data) && isset($data['Status'])) {
                return $data;
            }
        }

        // Fallback to Cloudflare DoH
        $cf_url = 'https://cloudflare-dns.com/dns-query?name=' . urlencode($domain) . '&type=' . urlencode($type);
        $cf_res = wp_remote_get($cf_url, [
            'timeout' => 5,
            'headers' => ['Accept' => 'application/dns-json']
        ]);

        if (!is_wp_error($cf_res) && wp_remote_retrieve_response_code($cf_res) === 200) {
            $body = wp_remote_retrieve_body($cf_res);
            $data = json_decode($body, true);
            if (is_array($data) && isset($data['Status'])) {
                return $data;
            }
        }

        return [];
    }
}
