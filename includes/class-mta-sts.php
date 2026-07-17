<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_MTA_STS
 *
 * MTA-STS (RFC 8461) record analyser.
 * Checks DNS TXT record on _mta-sts.domain and
 * attempts to fetch the policy file from
 * https://mta-sts.domain/.well-known/mta-sts.txt
 *
 * Usage:
 *   $result = PN_Mailguard_MTA_STS::analyze('example.com');
 *   $quick  = PN_Mailguard_MTA_STS::check('example.com');
 */
class PN_Mailguard_MTA_STS {

    /**
     * Full MTA-STS analysis for the Analyzer tab.
     *
     * @param string $input  Domain or email address
     * @return array
     */
    public static function analyze(string $input): array {
        $domain = self::extract_domain($input);

        $base = [
            'domain'     => $domain,
            'record'     => '',
            'status'     => 'missing',
            'checks'     => [],
            'passed'     => 0,
            'warnings'   => 0,
            'errors'     => 0,
            'mode'       => '',
            'mx'         => [],
            'max_age'    => 0,
            'policy_url' => '',
            'error'      => '',
        ];

        if (empty($domain)) {
            $base['error'] = 'Invalid domain or email address.';
            return $base;
        }

        $checks  = [];
        $passed  = $warnings = $errors = 0;

        // ---------------------------------------------------------------------
        // CHECK 1: DNS TXT record on _mta-sts.domain
        // ---------------------------------------------------------------------
        $mta_sts_domain = '_mta-sts.' . $domain;
        $txt_records    = dns_get_record($mta_sts_domain, DNS_TXT);

        if (empty($txt_records)) {
            $checks[] = self::result('dns_record', 'error',
                'No MTA-STS DNS record found',
                'No TXT record was found on _mta-sts.' . $domain . '. Without it, receiving servers cannot verify your MTA-STS policy. Publish a TXT record on _mta-sts.' . $domain . ' with value "v=STSv1; id=YYYYMMDDnn;"'
            );
            $errors++;
            $base['checks'] = $checks;
            $base['errors'] = $errors;
            return $base;
        }

        $dns_record = '';
        foreach ($txt_records as $rec) {
            if (!empty($rec['txt']) && str_starts_with(trim($rec['txt']), 'v=STSv1')) {
                $dns_record = trim($rec['txt']);
                break;
            }
        }

        if (empty($dns_record)) {
            $checks[] = self::result('dns_record', 'error',
                'Invalid MTA-STS DNS record',
                'A TXT record exists on _mta-sts.' . $domain . ' but it does not start with v=STSv1. The record is invalid and will be ignored.'
            );
            $errors++;
            $base['checks'] = $checks;
            $base['errors'] = $errors;
            return $base;
        }

        $checks[] = self::result('dns_record', 'ok',
            'MTA-STS DNS record found',
            'A valid TXT record starting with v=STSv1 was found on _mta-sts.' . $domain . '.'
        );
        $passed++;
        $base['record'] = $dns_record;

        // Parse id= from DNS record
        $id = '';
        if (preg_match('/\bid=([^\s;]+)/', $dns_record, $m)) {
            $id = $m[1];
        }

        // ---------------------------------------------------------------------
        // CHECK 2: DNS record syntax — id= present
        // ---------------------------------------------------------------------
        if (empty($id)) {
            $checks[] = self::result('dns_syntax', 'error',
                'Missing id= tag in DNS record',
                'The MTA-STS DNS record requires an id= tag (e.g. id=20240101). Without it, the record is invalid.'
            );
            $errors++;
        } else {
            $checks[] = self::result('dns_syntax', 'ok',
                'DNS record syntax valid (id=' . esc_html($id) . ')',
                'The DNS record contains the required id= tag with value: ' . esc_html($id) . '.'
            );
            $passed++;
        }

        // ---------------------------------------------------------------------
        // CHECK 3: Policy file accessible via HTTPS
        // ---------------------------------------------------------------------
        $policy_url = 'https://mta-sts.' . $domain . '/.well-known/mta-sts.txt';
        $base['policy_url'] = $policy_url;

        $response = wp_remote_get($policy_url, [
            'timeout'   => 10,
            'sslverify' => true,
            'headers'   => [
                'User-Agent' => 'PointNet-MailGuard/1.0',
            ],
        ]);

        if (is_wp_error($response)) {
            $checks[] = self::result('policy_accessible', 'error',
                'Policy file not accessible',
                'Could not fetch ' . $policy_url . '. Error: ' . esc_html($response->get_error_message())
            );
            $errors++;
        } else {
            $status_code = wp_remote_retrieve_response_code($response);
            if ($status_code === 200) {
                $body = wp_remote_retrieve_body($response);

                // Parse YAML-style key: value pairs from the policy file
                $policy = [];
                foreach (explode("\n", $body) as $line) {
                    $line = trim($line);
                    if (str_contains($line, ':')) {
                        $parts = explode(':', $line, 2);
                        $key = trim($parts[0]);
                        $val = trim($parts[1]);
                        $policy[$key] = $val;
                    }
                }

                if (empty($policy)) {
                    $checks[] = self::result('policy_accessible', 'error',
                        'Policy file is empty or unreadable (HTTP ' . $status_code . ')',
                        'The file at ' . $policy_url . ' returned HTTP ' . $status_code . ' but the content is empty or has no valid key: value pairs.'
                    );
                    $errors++;
                } else {
                    $checks[] = self::result('policy_accessible', 'ok',
                        'Policy file accessible (HTTP ' . $status_code . ')',
                        'The policy file at ' . $policy_url . ' is reachable and contains valid key: value pairs.'
                    );
                    $passed++;

                    // ---------------------------------------------------------------------
                    // CHECK 4: Policy version
                    // ---------------------------------------------------------------------
                    $version = trim($policy['version'] ?? '');
                    if ($version === 'STSv1') {
                        $checks[] = self::result('policy_version', 'ok',
                            'Policy version: STSv1',
                            'The policy file has the correct version identifier: STSv1.'
                        );
                        $passed++;
                    } else {
                        $checks[] = self::result('policy_version', 'error',
                            'Invalid policy version: ' . esc_html($version),
                            'The policy version must be "STSv1". Current value: "' . esc_html($version) . '".'
                        );
                        $errors++;
                    }

                    // ---------------------------------------------------------------------
                    // CHECK 5: Policy mode
                    // ---------------------------------------------------------------------
                    $mode = strtolower(trim($policy['mode'] ?? ''));
                    $base['mode'] = $mode;
                    if ($mode === 'enforce') {
                        $checks[] = self::result('policy_mode', 'ok',
                            'Policy mode: enforce (strict)',
                            'enforce means receiving servers MUST use TLS when delivering email to your domain. Best protection — but make sure your mail server has valid TLS configured.'
                        );
                        $passed++;
                    } elseif ($mode === 'testing') {
                        $checks[] = self::result('policy_mode', 'warning',
                            'Policy mode: testing',
                            'testing means receiving servers report issues via TLS-RPT but still deliver even without TLS. Recommended during initial setup — switch to enforce once verified.'
                        );
                        $warnings++;
                    } elseif ($mode === 'none') {
                        $checks[] = self::result('policy_mode', 'warning',
                            'Policy mode: none (disabled)',
                            'none means the policy exists but is inactive — no enforcement or reporting. Either the policy is being rolled back or retired.'
                        );
                        $warnings++;
                    } else {
                        $checks[] = self::result('policy_mode', 'error',
                            'Invalid policy mode: ' . esc_html($mode),
                            'The mode must be one of: enforce, testing, or none. Current value: "' . esc_html($mode) . '"'
                        );
                        $errors++;
                    }

                    // ---------------------------------------------------------------------
                    // CHECK 6: MX list
                    // ---------------------------------------------------------------------
                    $mx_raw = trim($policy['mx'] ?? '');
                    $mx_list = [];
                    if (!empty($mx_raw)) {
                        // Handle both comma-separated and space-separated MX entries
                        $mx_parts = str_contains($mx_raw, ',') ? explode(',', $mx_raw) : explode(' ', $mx_raw);
                        foreach ($mx_parts as $mx_entry) {
                            $mx_entry = trim($mx_entry);
                            if (!empty($mx_entry)) {
                                $mx_list[] = $mx_entry;
                                $base['mx'][] = $mx_entry;
                            }
                        }
                    }

                    if (empty($mx_list)) {
                        $checks[] = self::result('policy_mx', 'error',
                            'No MX hosts listed in policy',
                            'The policy file must contain at least one mx: entry. Without it, no mail servers are authorised to receive email for your domain.'
                        );
                        $errors++;
                    } else {
                        // Check for wildcard
                        $has_wildcard = false;
                        foreach ($mx_list as $mx_entry) {
                            if (str_contains($mx_entry, '*')) {
                                $has_wildcard = true;
                            }
                        }
                        if ($has_wildcard) {
                            $checks[] = self::result('policy_mx', 'warning',
                                'Wildcard MX pattern detected',
                                'The MX list contains a wildcard (*.example.com). This is permissive — consider listing exact mail server hostnames for tighter security.'
                            );
                            $warnings++;
                        } else {
                            $checks[] = self::result('policy_mx', 'ok',
                                'MX hosts listed (' . count($mx_list) . ' entries)',
                                'The policy file lists ' . count($mx_list) . ' MX host(s). MX entries: ' . esc_html(implode(', ', $mx_list))
                            );
                            $passed++;
                        }
                    }

                    // ---------------------------------------------------------------------
                    // CHECK 7: max_age
                    // ---------------------------------------------------------------------
                    $max_age = intval(trim($policy['max_age'] ?? '0'));
                    $base['max_age'] = $max_age;
                    if ($max_age <= 0) {
                        $checks[] = self::result('policy_max_age', 'error',
                            'Invalid max_age: ' . $max_age,
                            'max_age must be a positive integer (recommended: 86400 for 1 day, or up to 31536000 for 1 year). Current value: ' . $max_age
                        );
                        $errors++;
                    } elseif ($max_age < 86400) {
                        $checks[] = self::result('policy_max_age', 'warning',
                            'Low max_age: ' . $max_age . ' seconds',
                            'max_age of ' . $max_age . ' seconds (less than 1 day) means the policy is re-fetched frequently. Consider increasing to at least 86400 (1 day) for caching efficiency.'
                        );
                        $warnings++;
                    } elseif ($max_age > 31536000) {
                        $checks[] = self::result('policy_max_age', 'warning',
                            'High max_age: ' . $max_age . ' seconds',
                            'max_age of ' . $max_age . ' seconds exceeds 1 year. If you change your MX hosts, it will take this long for all servers to update their cache.'
                        );
                        $warnings++;
                    } else {
                        $checks[] = self::result('policy_max_age', 'ok',
                            'max_age is reasonable (' . $max_age . ' seconds)',
                            'max_age of ' . $max_age . ' seconds falls within the recommended range (86400 - 31536000).'
                        );
                        $passed++;
                    }
                }
            } elseif ($status_code === 404) {
                $checks[] = self::result('policy_accessible', 'error',
                    'Policy file not found (HTTP 404)',
                    'The file at ' . $policy_url . ' returned HTTP 404. Even with a valid DNS record, the policy file must be published at this URL for MTA-STS to work.'
                );
                $errors++;
            } else {
                $checks[] = self::result('policy_accessible', 'error',
                    'Policy file returned HTTP ' . $status_code,
                    'The file at ' . $policy_url . ' returned HTTP ' . $status_code . '. Expected a 200 response.'
                );
                $errors++;
            }
        }

        // Overall status
        $status = match (true) {
            $errors > 0   => 'error',
            $warnings > 0 => 'warning',
            default       => 'ok',
        };

        $base['status']   = $status;
        $base['checks']   = $checks;
        $base['passed']   = $passed;
        $base['warnings'] = $warnings;
        $base['errors']   = $errors;

        return $base;
    }

    /**
     * Quick check used by the Email Monitor scanner.
     *
     * @param string $domain
     * @return array
     */
    public static function check(string $domain): array {
        $r = self::analyze($domain);
        $status = match ($r['status']) {
            'missing' => 'missing',
            'ok'      => 'ok',
            default   => 'warning',
        };
        $warn = ($status === 'missing' || $status === 'error');
        return [
            'mtasts_record'  => $r['record'],
            'mtasts_status'  => $status,
            'mtasts_warning' => $warn,
        ];
    }

    /**
     * Extract domain from email or domain string.
     */
    private static function extract_domain(string $input): string {
        $input = trim(strtolower($input));
        if (str_contains($input, '@')) {
            $parts = explode('@', $input);
            return trim($parts[1]);
        }
        return $input;
    }

    /**
     * Build a single check result array.
     */
    private static function result(string $id, string $status, string $title, string $description): array {
        return [
            'id'          => $id,
            'status'      => $status,
            'title'       => $title,
            'description' => $description,
        ];
    }
}