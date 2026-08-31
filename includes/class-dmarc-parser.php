<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Dmarc_Parser
 *
 * Decompresses and parses RFC 7489 DMARC Aggregate (RUA) XML Reports.
 * Supports raw XML, GZIP (.xml.gz, .gz), and ZIP (.zip) inputs.
 * Uses SimpleXML when available, with a zero-dependency fallback parser.
 *
 * Usage:
 *   $result = PN_Mailguard_Dmarc_Parser::parse($filePathOrBinaryString);
 */
class PN_Mailguard_Dmarc_Parser {

    /**
     * Parse a DMARC aggregate report from file path or binary/string content.
     *
     * @param string $input File path or file content string
     * @return array Result array with success flag, metadata, policy, records and summary statistics
     */
    public static function parse(string $input): array {
        if (empty($input)) {
            return self::error_response('Empty input provided to DMARC parser.');
        }

        // If input is a path to an existing file, read its content
        $content = $input;
        if (@is_file($input)) {
            $file_content = @file_get_contents($input);
            if ($file_content === false) {
                return self::error_response('Unable to read DMARC report file: ' . esc_html($input));
            }
            $content = $file_content;
        }

        // Decompress content if needed
        $xml_content = self::decompress($content);
        if ($xml_content === false) {
            return self::error_response('Failed to decompress DMARC report. Format must be XML, GZIP (.gz/.xml.gz) or ZIP (.zip).');
        }

        // Parse XML string safely
        return self::parse_xml($xml_content);
    }

    /**
     * Attempt decompression on binary data (GZIP, ZIP, or plain XML).
     *
     * @param string $data Raw content bytes
     * @return string|false Uncompressed XML string or false on failure
     */
    public static function decompress(string $data): string|false {
        $raw = ltrim($data);

        // Check if already XML
        if (str_starts_with($raw, '<?xml') || str_contains($raw, '<feedback')) {
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
            // Fallback via gzinflate if gzdecode fails
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
            $tmp = tempnam(sys_get_temp_dir(), 'dmarc_zip_');
            if ($tmp !== false) {
                file_put_contents($tmp, $zip_data);
                $zip = new ZipArchive();
                $xml = false;

                if ($zip->open($tmp) === true) {
                    for ($i = 0; $i < $zip->numFiles; $i++) {
                        $filename = $zip->getNameIndex($i);
                        if (preg_match('/\.xml$/i', $filename) || str_contains($filename, 'xml')) {
                            $xml = $zip->getFromIndex($i);
                            break;
                        }
                    }
                    if ($xml === false && $zip->numFiles > 0) {
                        // Fallback: get first file in zip
                        $xml = $zip->getFromIndex(0);
                    }
                    $zip->close();
                }
                @unlink($tmp);

                if ($xml !== false) {
                    return $xml;
                }
            }
        }

        return false;
    }

    /**
     * Safely parse DMARC report XML content according to RFC 7489 schema.
     *
     * @param string $xml_string XML content
     * @return array
     */
    private static function parse_xml(string $xml_string): array {
        if (!function_exists('simplexml_load_string')) {
            return self::parse_xml_fallback($xml_string);
        }

        // Prevent XXE vulnerabilities
        $use_errors = libxml_use_internal_errors(true);
        $entity_loader = function_exists('libxml_disable_entity_loader') ? @libxml_disable_entity_loader(true) : null;

        $xml = simplexml_load_string($xml_string, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOENT);

        if ($entity_loader !== null && function_exists('libxml_disable_entity_loader')) {
            @libxml_disable_entity_loader($entity_loader);
        }

        if ($xml === false) {
            $errors = libxml_get_errors();
            libxml_clear_errors();
            libxml_use_internal_errors($use_errors);
            // If SimpleXML fails or has issues, fallback to string parser
            return self::parse_xml_fallback($xml_string);
        }

        libxml_use_internal_errors($use_errors);

        // Ensure root element is feedback
        if ($xml->getName() !== 'feedback') {
            return self::error_response('Invalid DMARC report format: Root node must be <feedback>.');
        }

        // --- 1. Report Metadata ---
        $meta_node = $xml->report_metadata ?? null;
        $date_begin_ts = intval($meta_node->date_range->begin ?? 0);
        $date_end_ts   = intval($meta_node->date_range->end ?? 0);

        $metadata = [
            'org_name'           => strval($meta_node->org_name ?? 'Unknown'),
            'email'              => strval($meta_node->email ?? ''),
            'extra_contact_info' => strval($meta_node->extra_contact_info ?? ''),
            'report_id'          => strval($meta_node->report_id ?? ''),
            'date_begin'         => $date_begin_ts ? gmdate('Y-m-d H:i:s', $date_begin_ts) : '',
            'date_end'           => $date_end_ts ? gmdate('Y-m-d H:i:s', $date_end_ts) : '',
            'date_begin_ts'      => $date_begin_ts,
            'date_end_ts'        => $date_end_ts,
        ];

        // --- 2. Published Policy ---
        $policy_node = $xml->policy_published ?? null;
        $policy = [
            'domain' => strval($policy_node->domain ?? ''),
            'adkim'  => strval($policy_node->adkim ?? 'r'),
            'aspf'   => strval($policy_node->aspf ?? 'r'),
            'p'      => strval($policy_node->p ?? 'none'),
            'sp'     => strval($policy_node->sp ?? ''),
            'pct'    => isset($policy_node->pct) ? intval($policy_node->pct) : 100,
            'fo'     => strval($policy_node->fo ?? '0'),
        ];

        // --- 3. Records ---
        $records = [];
        $total_messages  = 0;
        $passed_messages = 0;
        $failed_messages = 0;

        if (isset($xml->record)) {
            foreach ($xml->record as $rec) {
                $row = $rec->row ?? null;
                $source_ip = strval($row->source_ip ?? '');
                $count     = intval($row->count ?? 0);

                $policy_eval = $row->policy_evaluated ?? null;
                $disposition = strval($policy_eval->disposition ?? 'none');
                $dkim_eval   = strval($policy_eval->dkim ?? 'fail');
                $spf_eval    = strval($policy_eval->spf ?? 'fail');

                // Reasons for policy override
                $reasons = [];
                if (isset($policy_eval->reason)) {
                    foreach ($policy_eval->reason as $r) {
                        $reasons[] = [
                            'type'    => strval($r->type ?? ''),
                            'comment' => strval($r->comment ?? ''),
                        ];
                    }
                }

                // Identifiers
                $identifiers   = $rec->identifiers ?? null;
                $header_from   = strval($identifiers->header_from ?? '');
                $envelope_from = strval($identifiers->envelope_from ?? '');
                $envelope_to   = strval($identifiers->envelope_to ?? '');

                // Auth Results: DKIM
                $dkim_results = [];
                if (isset($rec->auth_results->dkim)) {
                    foreach ($rec->auth_results->dkim as $dkim_item) {
                        $dkim_results[] = [
                            'domain'       => strval($dkim_item->domain ?? ''),
                            'result'       => strval($dkim_item->result ?? ''),
                            'selector'     => strval($dkim_item->selector ?? ''),
                            'human_result' => strval($dkim_item->human_result ?? ''),
                        ];
                    }
                }

                // Auth Results: SPF
                $spf_results = [];
                if (isset($rec->auth_results->spf)) {
                    foreach ($rec->auth_results->spf as $spf_item) {
                        $spf_results[] = [
                            'domain' => strval($spf_item->domain ?? ''),
                            'result' => strval($spf_item->result ?? ''),
                            'scope'  => strval($spf_item->scope ?? 'mfrom'),
                        ];
                    }
                }

                // Alignment determination
                $is_pass = ($dkim_eval === 'pass' && $spf_eval === 'pass')
                           || ($dkim_eval === 'pass' || $spf_eval === 'pass' && $disposition === 'none');

                $total_messages += $count;
                if ($dkim_eval === 'pass' && $spf_eval === 'pass') {
                    $passed_messages += $count;
                } elseif ($dkim_eval === 'pass' || $spf_eval === 'pass') {
                    $passed_messages += $count;
                } else {
                    $failed_messages += $count;
                }

                $records[] = [
                    'source_ip'     => $source_ip,
                    'count'         => $count,
                    'disposition'   => $disposition,
                    'dkim_eval'     => $dkim_eval,
                    'spf_eval'      => $spf_eval,
                    'reasons'       => $reasons,
                    'header_from'   => $header_from,
                    'envelope_from' => $envelope_from,
                    'envelope_to'   => $envelope_to,
                    'dkim_results'  => $dkim_results,
                    'spf_results'   => $spf_results,
                    'is_aligned'    => $is_pass,
                ];
            }
        }

        $pass_rate = $total_messages > 0 ? round(($passed_messages / $total_messages) * 100, 1) : 0.0;

        return [
            'success'          => true,
            'metadata'         => $metadata,
            'policy_published' => $policy,
            'summary'          => [
                'total_messages'    => $total_messages,
                'passed_messages'   => $passed_messages,
                'failed_messages'   => $failed_messages,
                'pass_rate_percent' => $pass_rate,
                'records_count'     => count($records),
            ],
            'records'          => $records,
            'error'            => '',
        ];
    }

    /**
     * Fallback XML parser using regex/string matching when SimpleXML/DOM extensions are missing.
     *
     * @param string $xml
     * @return array
     */
    private static function parse_xml_fallback(string $xml): array {
        // Extract tag value helper
        $get_val = function(string $tag, string $str, string $default = ''): string {
            if (preg_match('/<' . preg_quote($tag, '/') . '[^>]*>(.*?)<\/' . preg_quote($tag, '/') . '>/is', $str, $m)) {
                return trim(strip_tags($m[1]));
            }
            return $default;
        };

        // Check root element
        if (!preg_match('/<feedback\b[^>]*>(.*?)<\/feedback>/is', $xml, $feedback_match)) {
            return self::error_response('Invalid DMARC report format: Root node must be <feedback>.');
        }
        $fb_content = $feedback_match[1];

        // 1. Report Metadata
        $meta_str = '';
        if (preg_match('/<report_metadata\b[^>]*>(.*?)<\/report_metadata>/is', $fb_content, $m)) {
            $meta_str = $m[1];
        }
        $date_begin_ts = intval($get_val('begin', $meta_str, '0'));
        $date_end_ts   = intval($get_val('end', $meta_str, '0'));

        $metadata = [
            'org_name'           => $get_val('org_name', $meta_str, 'Unknown'),
            'email'              => $get_val('email', $meta_str, ''),
            'extra_contact_info' => $get_val('extra_contact_info', $meta_str, ''),
            'report_id'          => $get_val('report_id', $meta_str, ''),
            'date_begin'         => $date_begin_ts ? gmdate('Y-m-d H:i:s', $date_begin_ts) : '',
            'date_end'           => $date_end_ts ? gmdate('Y-m-d H:i:s', $date_end_ts) : '',
            'date_begin_ts'      => $date_begin_ts,
            'date_end_ts'        => $date_end_ts,
        ];

        // 2. Published Policy
        $policy_str = '';
        if (preg_match('/<policy_published\b[^>]*>(.*?)<\/policy_published>/is', $fb_content, $m)) {
            $policy_str = $m[1];
        }
        $pct_raw = $get_val('pct', $policy_str, '100');
        $policy = [
            'domain' => $get_val('domain', $policy_str, ''),
            'adkim'  => $get_val('adkim', $policy_str, 'r'),
            'aspf'   => $get_val('aspf', $policy_str, 'r'),
            'p'      => $get_val('p', $policy_str, 'none'),
            'sp'     => $get_val('sp', $policy_str, ''),
            'pct'    => is_numeric($pct_raw) ? intval($pct_raw) : 100,
            'fo'     => $get_val('fo', $policy_str, '0'),
        ];

        // 3. Records
        $records = [];
        $total_messages  = 0;
        $passed_messages = 0;
        $failed_messages = 0;

        preg_match_all('/<record\b[^>]*>(.*?)<\/record>/is', $fb_content, $rec_matches);
        if (!empty($rec_matches[1])) {
            foreach ($rec_matches[1] as $rec_str) {
                // Row
                $row_str = '';
                if (preg_match('/<row\b[^>]*>(.*?)<\/row>/is', $rec_str, $rm)) {
                    $row_str = $rm[1];
                }
                $source_ip = $get_val('source_ip', $row_str, '');
                $count     = intval($get_val('count', $row_str, '0'));

                // Policy evaluated
                $pol_eval_str = '';
                if (preg_match('/<policy_evaluated\b[^>]*>(.*?)<\/policy_evaluated>/is', $row_str, $pm)) {
                    $pol_eval_str = $pm[1];
                }
                $disposition = $get_val('disposition', $pol_eval_str, 'none');
                $dkim_eval   = $get_val('dkim', $pol_eval_str, 'fail');
                $spf_eval    = $get_val('spf', $pol_eval_str, 'fail');

                // Reasons
                $reasons = [];
                preg_match_all('/<reason\b[^>]*>(.*?)<\/reason>/is', $pol_eval_str, $reason_matches);
                if (!empty($reason_matches[1])) {
                    foreach ($reason_matches[1] as $r_str) {
                        $reasons[] = [
                            'type'    => $get_val('type', $r_str, ''),
                            'comment' => $get_val('comment', $r_str, ''),
                        ];
                    }
                }

                // Identifiers
                $ident_str = '';
                if (preg_match('/<identifiers\b[^>]*>(.*?)<\/identifiers>/is', $rec_str, $im)) {
                    $ident_str = $im[1];
                }
                $header_from   = $get_val('header_from', $ident_str, '');
                $envelope_from = $get_val('envelope_from', $ident_str, '');
                $envelope_to   = $get_val('envelope_to', $ident_str, '');

                // Auth Results
                $auth_str = '';
                if (preg_match('/<auth_results\b[^>]*>(.*?)<\/auth_results>/is', $rec_str, $am)) {
                    $auth_str = $am[1];
                }

                $dkim_results = [];
                preg_match_all('/<dkim\b[^>]*>(.*?)<\/dkim>/is', $auth_str, $dkim_matches);
                if (!empty($dkim_matches[1])) {
                    foreach ($dkim_matches[1] as $d_str) {
                        $dkim_results[] = [
                            'domain'       => $get_val('domain', $d_str, ''),
                            'result'       => $get_val('result', $d_str, ''),
                            'selector'     => $get_val('selector', $d_str, ''),
                            'human_result' => $get_val('human_result', $d_str, ''),
                        ];
                    }
                }

                $spf_results = [];
                preg_match_all('/<spf\b[^>]*>(.*?)<\/spf>/is', $auth_str, $spf_matches);
                if (!empty($spf_matches[1])) {
                    foreach ($spf_matches[1] as $s_str) {
                        $spf_results[] = [
                            'domain' => $get_val('domain', $s_str, ''),
                            'result' => $get_val('result', $s_str, ''),
                            'scope'  => $get_val('scope', $s_str, 'mfrom'),
                        ];
                    }
                }

                $is_pass = ($dkim_eval === 'pass' && $spf_eval === 'pass')
                           || ($dkim_eval === 'pass' || $spf_eval === 'pass' && $disposition === 'none');

                $total_messages += $count;
                if ($dkim_eval === 'pass' && $spf_eval === 'pass') {
                    $passed_messages += $count;
                } elseif ($dkim_eval === 'pass' || $spf_eval === 'pass') {
                    $passed_messages += $count;
                } else {
                    $failed_messages += $count;
                }

                $records[] = [
                    'source_ip'     => $source_ip,
                    'count'         => $count,
                    'disposition'   => $disposition,
                    'dkim_eval'     => $dkim_eval,
                    'spf_eval'      => $spf_eval,
                    'reasons'       => $reasons,
                    'header_from'   => $header_from,
                    'envelope_from' => $envelope_from,
                    'envelope_to'   => $envelope_to,
                    'dkim_results'  => $dkim_results,
                    'spf_results'   => $spf_results,
                    'is_aligned'    => $is_pass,
                ];
            }
        }

        $pass_rate = $total_messages > 0 ? round(($passed_messages / $total_messages) * 100, 1) : 0.0;

        return [
            'success'          => true,
            'metadata'         => $metadata,
            'policy_published' => $policy,
            'summary'          => [
                'total_messages'    => $total_messages,
                'passed_messages'   => $passed_messages,
                'failed_messages'   => $failed_messages,
                'pass_rate_percent' => $pass_rate,
                'records_count'     => count($records),
            ],
            'records'          => $records,
            'error'            => '',
        ];
    }

    /**
     * Standard error structure helper.
     *
     * @param string $message
     * @return array
     */
    private static function error_response(string $message): array {
        return [
            'success'          => false,
            'metadata'         => [],
            'policy_published' => [],
            'summary'          => [
                'total_messages'    => 0,
                'passed_messages'   => 0,
                'failed_messages'   => 0,
                'pass_rate_percent' => 0.0,
                'records_count'     => 0,
            ],
            'records'          => [],
            'error'            => $message,
        ];
    }
}
