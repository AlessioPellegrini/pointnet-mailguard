<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Tlsrpt_Parser
 *
 * Decompresses and parses RFC 8460 SMTP TLS Reporting (TLSRPT) JSON Reports.
 * Supports raw JSON, GZIP (.json.gz, .gz), and ZIP (.zip) inputs.
 *
 * Usage:
 *   $result = PN_Mailguard_Tlsrpt_Parser::parse($filePathOrBinaryString);
 */
class PN_Mailguard_Tlsrpt_Parser {

    /**
     * Parse a TLSRPT report from file path or binary/string content.
     *
     * @param string $input File path or file content string
     * @return array Result array with success flag, metadata, policies, summary, and failure details
     */
    public static function parse(string $input): array {
        if (empty($input)) {
            return self::error_response('Empty input provided to TLSRPT parser.');
        }

        // If input is a path to an existing file, read its content
        $content = $input;
        if (@is_file($input)) {
            $file_content = @file_get_contents($input);
            if ($file_content === false) {
                return self::error_response('Unable to read TLSRPT report file: ' . esc_html($input));
            }
            $content = $file_content;
        }

        // Decompress content if needed
        $json_content = self::decompress($content);
        if ($json_content === false) {
            return self::error_response('Failed to decompress TLSRPT report. Format must be JSON, GZIP (.gz/.json.gz) or ZIP (.zip).');
        }

        // Parse JSON content
        return self::parse_json($json_content);
    }

    /**
     * Attempt decompression on binary data (GZIP, ZIP, or plain JSON).
     *
     * @param string $data Raw content bytes
     * @return string|false Uncompressed JSON string or false on failure
     */
    public static function decompress(string $data): string|false {
        $raw = ltrim($data);

        // Check if already JSON
        if (str_starts_with($raw, '{') && str_contains($raw, 'organization-name')) {
            return $data;
        }

        // 1. GZIP check (magic bytes \x1f\x8b)
        if (str_starts_with($raw, "\x1f\x8b") || str_starts_with($data, "\x1f\x8b")) {
            $gz_data = str_starts_with($raw, "\x1f\x8b") ? $raw : $data;
            if (function_exists('gzdecode')) {
                $decompressed = @gzdecode($gz_data);
                if ($decompressed !== false) {
                    return $decompressed;
                }
            }
            if (function_exists('gzinflate') && strlen($gz_data) > 10) {
                $decompressed = @gzinflate(substr($gz_data, 10));
                if ($decompressed !== false) {
                    return $decompressed;
                }
            }
        }

        // 2. ZIP check (magic bytes PK\x03\x04)
        if ((str_starts_with($raw, "PK\x03\x04") || str_starts_with($data, "PK\x03\x04")) && class_exists('ZipArchive')) {
            $zip_data = str_starts_with($raw, "PK\x03\x04") ? $raw : $data;
            $tmp = tempnam(sys_get_temp_dir(), 'tlsrpt_zip_');
            if ($tmp !== false) {
                file_put_contents($tmp, $zip_data);
                $zip = new ZipArchive();
                $json = false;

                if ($zip->open($tmp) === true) {
                    for ($i = 0; $i < $zip->numFiles; $i++) {
                        $filename = $zip->getNameIndex($i);
                        if (preg_match('/\.json$/i', $filename) || str_contains($filename, 'json')) {
                            $json = $zip->getFromIndex($i);
                            break;
                        }
                    }
                    if ($json === false && $zip->numFiles > 0) {
                        $json = $zip->getFromIndex(0);
                    }
                    $zip->close();
                }
                @unlink($tmp);

                if ($json !== false) {
                    return $json;
                }
            }
        }

        // Fallback: If string starts with {, return as-is
        if (str_starts_with($trimmed, '{')) {
            return $data;
        }

        return false;
    }

    /**
     * Safely parse RFC 8460 TLSRPT JSON string into structured data array.
     *
     * @param string $json_string
     * @return array
     */
    private static function parse_json(string $json_string): array {
        $decoded = json_decode($json_string, true);
        if (!is_array($decoded)) {
            return self::error_response('Invalid TLSRPT report format: Payload is not valid JSON.');
        }

        if (empty($decoded['organization-name']) && empty($decoded['report-id']) && empty($decoded['policies'])) {
            return self::error_response('Invalid TLSRPT report schema: Missing organization-name or policies root attributes.');
        }

        // --- 1. Report Metadata ---
        $org_name     = strval($decoded['organization-name'] ?? 'Unknown');
        $contact_info = strval($decoded['contact-info'] ?? '');
        $report_id    = strval($decoded['report-id'] ?? '');

        $date_range   = $decoded['date-range'] ?? [];
        $start_time   = strval($date_range['start-datetime'] ?? '');
        $end_time     = strval($date_range['end-datetime'] ?? '');

        $metadata = [
            'org_name'     => $org_name,
            'contact_info' => $contact_info,
            'report_id'    => $report_id,
            'date_begin'   => $start_time,
            'date_end'     => $end_time,
        ];

        // --- 2. Policies & Summaries ---
        $policies_raw     = $decoded['policies'] ?? [];
        $policies_parsed  = [];
        $records          = [];
        $total_successful = 0;
        $total_failed     = 0;
        $primary_domain   = '';

        if (is_array($policies_raw)) {
            foreach ($policies_raw as $p_item) {
                $policy        = $p_item['policy'] ?? [];
                $policy_type   = strval($policy['policy-type'] ?? 'sts');
                $policy_domain = strval($policy['policy-domain'] ?? '');
                if (empty($primary_domain) && !empty($policy_domain)) {
                    $primary_domain = $policy_domain;
                }

                $policy_strings = $policy['policy-string'] ?? [];
                if (is_array($policy_strings)) {
                    $policy_strings = array_map('strval', $policy_strings);
                } else {
                    $policy_strings = [];
                }

                $mx_hosts = $policy['mx-host'] ?? [];
                if (is_array($mx_hosts)) {
                    $mx_hosts = array_map('strval', $mx_hosts);
                } else {
                    $mx_hosts = [];
                }

                $summary    = $p_item['summary'] ?? [];
                $successful = intval($summary['total-successful-session-count'] ?? 0);
                $failed     = intval($summary['total-failure-session-count'] ?? 0);

                $total_successful += $successful;
                $total_failed     += $failed;

                // Extract Failure Details
                $failures_raw = $p_item['failure-details'] ?? [];
                $failures     = [];
                if (is_array($failures_raw)) {
                    foreach ($failures_raw as $f) {
                        $failures[] = [
                            'result_type'          => strval($f['result-type'] ?? 'unknown'),
                            'sending_mta_ip'       => strval($f['sending-mta-ip'] ?? ''),
                            'receiving_ip'         => strval($f['receiving-ip'] ?? ''),
                            'receiving_mx_hostname'=> strval($f['receiving-mx-hostname'] ?? ''),
                            'failed_session_count' => intval($f['failed-session-count'] ?? 1),
                            'additional_info'      => strval($f['additional-information'] ?? ''),
                        ];
                    }
                }

                $policy_entry = [
                    'policy_type'    => $policy_type,
                    'policy_domain'  => $policy_domain,
                    'policy_string'  => $policy_strings,
                    'mx_hosts'       => $mx_hosts,
                    'successful'     => $successful,
                    'failed'         => $failed,
                    'failures'       => $failures,
                ];

                $policies_parsed[] = $policy_entry;

                $records[] = [
                    'policy_type'    => $policy_type,
                    'policy_domain'  => $policy_domain,
                    'successful'     => $successful,
                    'failed'         => $failed,
                    'failures_count' => count($failures),
                    'failures'       => $failures,
                ];
            }
        }

        $total_sessions = $total_successful + $total_failed;
        $success_rate   = $total_sessions > 0 ? round(($total_successful / $total_sessions) * 100, 1) : 100.0;

        return [
            'success'   => true,
            'metadata'  => $metadata,
            'domain'    => $primary_domain,
            'summary'   => [
                'total_sessions'       => $total_sessions,
                'successful_sessions' => $total_successful,
                'failed_sessions'     => $total_failed,
                'success_rate_percent'=> $success_rate,
                'policies_count'       => count($policies_parsed),
            ],
            'policies'  => $policies_parsed,
            'records'   => $records,
            'error'     => '',
        ];
    }

    /**
     * Standard error response helper.
     *
     * @param string $message
     * @return array
     */
    private static function error_response(string $message): array {
        return [
            'success'  => false,
            'metadata' => [],
            'domain'   => '',
            'summary'  => [
                'total_sessions'       => 0,
                'successful_sessions' => 0,
                'failed_sessions'     => 0,
                'success_rate_percent'=> 0.0,
                'policies_count'       => 0,
            ],
            'policies' => [],
            'records'  => [],
            'error'    => $message,
        ];
    }
}
