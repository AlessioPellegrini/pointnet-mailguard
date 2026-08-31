<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Imap_Fetcher
 *
 * Connects securely to an IMAP mailbox using native PHP sockets (SSL/TLS on port 993 or STARTTLS/143),
 * fetches DMARC aggregate XML and TLSRPT JSON report email attachments (.zip, .gz, .xml, .json),
 * and imports them automatically into PointNet Mail Guard database tables.
 */
class PN_Mailguard_Imap_Fetcher {

    /**
     * Get configured IMAP settings from WordPress options.
     *
     * @return array
     */
    public static function get_config(): array {
        return [
            'host'         => get_option('pn_mailguard_imap_host', ''),
            'port'         => intval(get_option('pn_mailguard_imap_port', 993)),
            'encryption'   => get_option('pn_mailguard_imap_encryption', 'ssl'), // ssl, tls, none
            'username'     => get_option('pn_mailguard_imap_username', ''),
            'password'     => PN_Mailguard_Crypto::decrypt(get_option('pn_mailguard_imap_password', '')),
            'mailbox'      => get_option('pn_mailguard_imap_mailbox', 'INBOX'),
            'auto_fetch'   => get_option('pn_mailguard_imap_auto_fetch', '0') === '1',
            'action_after' => get_option('pn_mailguard_imap_action_after', 'delete'), // delete, mark_read
        ];
    }

    /**
     * Test IMAP connection with provided or saved configuration.
     *
     * @param array|null $config Optional custom config array for testing unsaved settings
     * @return array Result array with success flag and message
     */
    public static function test_connection(?array $config = null): array {
        $cfg = $config ?? self::get_config();

        if (empty($cfg['host']) || empty($cfg['username']) || empty($cfg['password'])) {
            return [
                'success' => false,
                'message' => __('IMAP Host, Username, and Password are required.', 'pointnet-mailguard'),
            ];
        }

        $stream = self::connect($cfg, $err_msg);
        if (!$stream) {
            return [
                'success' => false,
                'message' => sprintf(__('IMAP Connection Failed: %s', 'pointnet-mailguard'), $err_msg),
            ];
        }

        self::disconnect($stream);

        return [
            'success' => true,
            'message' => __('Successfully connected and authenticated to IMAP server!', 'pointnet-mailguard'),
        ];
    }

    /**
     * Fetch unread report emails from IMAP mailbox and import attachments.
     *
     * @param array|null $config
     * @return array Result summary with counts of imported, skipped, failed reports
     */
    public static function fetch_reports(?array $config = null): array {
        @set_time_limit(180);
        $cfg = $config ?? self::get_config();

        if (empty($cfg['host']) || empty($cfg['username']) || empty($cfg['password'])) {
            return [
                'success' => false,
                'message' => __('IMAP configuration is incomplete. Please configure Host, Username, and Password.', 'pointnet-mailguard'),
            ];
        }

        $stream = self::connect($cfg, $err_msg);
        if (!$stream) {
            return [
                'success' => false,
                'message' => sprintf(__('IMAP Connection Failed: %s', 'pointnet-mailguard'), $err_msg),
            ];
        }

        // Search for UNSEEN (unread) messages
        $tag = self::send_command($stream, 'SEARCH UNSEEN');
        $response = self::read_until_tag($stream, $tag);
        
        $msg_numbers = [];
        foreach ($response as $line) {
            if (str_starts_with(strtoupper($line), '* SEARCH')) {
                $parts = explode(' ', trim(substr($line, 8)));
                foreach ($parts as $p) {
                    if (is_numeric($p) && intval($p) > 0) {
                        $msg_numbers[] = intval($p);
                    }
                }
            }
        }

        if (empty($msg_numbers)) {
            self::disconnect($stream);
            self::update_fetch_status(0, 0, 0, []);
            return [
                'success'   => true,
                'message'   => __('No new unread report emails found in mailbox.', 'pointnet-mailguard'),
                'imported'  => 0,
                'duplicates'=> 0,
                'failed'    => 0,
            ];
        }

        $imported = 0;
        $duplicates = 0;
        $failed = 0;
        $errors = [];

        foreach ($msg_numbers as $msg_num) {
            try {
                // Fetch raw email RFC822 content without marking as read immediately (peek)
                $tag = self::send_command($stream, "FETCH {$msg_num} (BODY.PEEK[])");
                $raw_email = self::read_literal_response($stream, $tag);

                if (empty($raw_email)) {
                    // Fallback to standard BODY[] if server rejects or doesn't support PEEK
                    $tag = self::send_command($stream, "FETCH {$msg_num} (BODY[])");
                    $raw_email = self::read_literal_response($stream, $tag);
                }

                if (empty($raw_email)) {
                    $failed++;
                    $errors[] = "Msg #{$msg_num}: Failed to fetch email payload from IMAP server.";
                    continue;
                }

                // Extract attachments from raw MIME message
                $attachments = self::extract_attachments($raw_email);

                if (empty($attachments)) {
                    $failed++;
                    $len = strlen($raw_email);
                    $preview = substr(preg_replace('/\s+/', ' ', trim($raw_email)), 0, 70);
                    $errors[] = sprintf("Msg #%d (%d bytes, \"%s...\"): No valid DMARC or TLSRPT attachment found.", $msg_num, $len, $preview);
                    continue;
                }

                $email_has_success = false;

                foreach ($attachments as $att) {
                    $filename = $att['filename'];
                    $content  = $att['content'];

                    if (empty($content)) continue;

                    // Process attachment with DMARC and TLSRPT parsers
                    $res = self::import_attachment($content);
                    if ($res['status'] === 'success') {
                        $imported++;
                        $email_has_success = true;
                    } elseif ($res['status'] === 'duplicate') {
                        $duplicates++;
                        $email_has_success = true;
                    } else {
                        $failed++;
                        $errors[] = "File {$filename}: " . ($res['message'] ?? 'Import failed');
                    }
                }

                // Apply action after import (delete vs mark read) - only when successfully processed
                if ($email_has_success) {
                    if ($cfg['action_after'] === 'delete') {
                        self::mark_deleted($stream, $msg_num);
                    } else {
                        self::mark_seen($stream, $msg_num);
                    }
                }
            } catch (\Throwable $e) {
                $failed++;
                $errors[] = "Msg #{$msg_num} Exception: " . $e->getMessage();
            }
        }

        // Expunge if messages were marked as deleted
        if ($cfg['action_after'] === 'delete') {
            $tag = self::send_command($stream, 'EXPUNGE');
            self::read_until_tag($stream, $tag);
        }

        self::disconnect($stream);

        self::update_fetch_status($imported, $duplicates, $failed, $errors);

        $msg = sprintf(
            __('IMAP Fetch Completed: %d report(s) imported, %d duplicate(s) skipped, %d error(s).', 'pointnet-mailguard'),
            $imported,
            $duplicates,
            $failed
        );

        return [
            'success'   => true,
            'message'   => $msg,
            'imported'  => $imported,
            'duplicates'=> $duplicates,
            'failed'    => $failed,
            'errors'    => $errors,
        ];
    }

    /**
     * Import a single attachment payload into DB via DMARC or TLSRPT parser.
     *
     * @param string $raw_bytes
     * @return array ['status' => 'success'|'duplicate'|'failed', 'message' => '...']
     */
    private static function import_attachment(string $raw_bytes): array {
        global $wpdb;

        // Check if TLSRPT JSON or DMARC XML
        $decompressed = PN_Mailguard_Tlsrpt_Parser::decompress($raw_bytes);
        $is_tlsrpt = false;

        if ($decompressed !== false) {
            $trimmed = ltrim($decompressed);
            if (str_starts_with($trimmed, '{') && (str_contains($trimmed, 'organization-name') || str_contains($trimmed, 'policies'))) {
                $is_tlsrpt = true;
            }
        }

        if ($is_tlsrpt) {
            $parsed = PN_Mailguard_Tlsrpt_Parser::parse($raw_bytes);
            if (!$parsed['success']) {
                return ['status' => 'failed', 'message' => $parsed['error']];
            }

            $table_tls_rep = $wpdb->prefix . PN_Mailguard_Installer::TABLE_TLS_REPORTS;
            $table_tls_rec = $wpdb->prefix . PN_Mailguard_Installer::TABLE_TLS_RECORDS;
            $meta = $parsed['metadata'];
            $sum  = $parsed['summary'];

            if (!empty($meta['report_id'])) {
                $exists = $wpdb->get_var(
                    $wpdb->prepare("SELECT id FROM %i WHERE report_id = %s AND org_name = %s LIMIT 1", $table_tls_rep, $meta['report_id'], $meta['org_name'])
                );
                if ($exists) {
                    return ['status' => 'duplicate', 'message' => 'Already imported'];
                }
            }

            $inserted = $wpdb->insert(
                $table_tls_rep,
                [
                    'report_id'           => $meta['report_id'],
                    'org_name'            => $meta['org_name'],
                    'contact_info'        => $meta['contact_info'],
                    'domain'              => $parsed['domain'],
                    'date_begin'          => $meta['date_begin'] ?: null,
                    'date_end'            => $meta['date_end'] ?: null,
                    'successful_sessions' => $sum['successful_sessions'],
                    'failed_sessions'     => $sum['failed_sessions'],
                    'success_rate'        => $sum['success_rate_percent'],
                    'policies_json'       => wp_json_encode($parsed['policies']),
                    'created_at'          => current_time('mysql'),
                ]
            );

            if (!$inserted) {
                return ['status' => 'failed', 'message' => 'Failed to save TLSRPT report to database'];
            }

            $report_db_id = $wpdb->insert_id;

            foreach ($parsed['records'] as $rec) {
                $wpdb->insert(
                    $table_tls_rec,
                    [
                        'report_id_fk'         => $report_db_id,
                        'policy_type'          => $rec['policy_type'],
                        'policy_domain'        => $rec['policy_domain'],
                        'successful_count'     => $rec['successful'],
                        'failed_count'         => $rec['failed'],
                        'failure_details_json' => wp_json_encode($rec['failures']),
                    ]
                );
            }

            return ['status' => 'success', 'message' => 'TLSRPT imported'];
        } else {
            // DMARC XML
            $parsed = PN_Mailguard_Dmarc_Parser::parse($raw_bytes);
            if (!$parsed['success']) {
                return ['status' => 'failed', 'message' => $parsed['error']];
            }

            $table_reports = $wpdb->prefix . PN_Mailguard_Installer::TABLE_DMARC_REPORTS;
            $table_records = $wpdb->prefix . PN_Mailguard_Installer::TABLE_DMARC_RECORDS;
            $meta   = $parsed['metadata'];
            $policy = $parsed['policy_published'];
            $sum    = $parsed['summary'];

            if (!empty($meta['report_id'])) {
                $exists = $wpdb->get_var(
                    $wpdb->prepare("SELECT id FROM %i WHERE report_id = %s AND org_name = %s LIMIT 1", $table_reports, $meta['report_id'], $meta['org_name'])
                );
                if ($exists) {
                    return ['status' => 'duplicate', 'message' => 'Already imported'];
                }
            }

            $inserted = $wpdb->insert(
                $table_reports,
                [
                    'report_id'        => $meta['report_id'],
                    'org_name'         => $meta['org_name'],
                    'email'            => $meta['email'],
                    'domain'           => $policy['domain'],
                    'date_begin'       => $meta['date_begin'] ?: null,
                    'date_end'         => $meta['date_end'] ?: null,
                    'total_messages'   => $sum['total_messages'],
                    'passed_messages'  => $sum['passed_messages'],
                    'failed_messages'  => $sum['failed_messages'],
                    'pass_rate'        => $sum['pass_rate_percent'],
                    'policy_published' => wp_json_encode($policy),
                    'created_at'       => current_time('mysql'),
                ]
            );

            if (!$inserted) {
                return ['status' => 'failed', 'message' => 'Failed to save DMARC report to database'];
            }

            $report_db_id = $wpdb->insert_id;

            foreach ($parsed['records'] as $rec) {
                $wpdb->insert(
                    $table_records,
                    [
                        'report_id_fk'  => $report_db_id,
                        'source_ip'     => $rec['source_ip'],
                        'count'         => $rec['count'],
                        'disposition'   => $rec['disposition'],
                        'dkim_eval'     => $rec['dkim_eval'],
                        'spf_eval'      => $rec['spf_eval'],
                        'header_from'   => $rec['header_from'],
                        'envelope_from' => $rec['envelope_from'],
                        'envelope_to'   => $rec['envelope_to'],
                        'country_code'  => '',
                        'auth_details'  => wp_json_encode([
                            'dkim' => $rec['dkim_results'],
                            'spf'  => $rec['spf_results'],
                        ]),
                    ]
                );
            }

            return ['status' => 'success', 'message' => 'DMARC imported'];
        }
    }

    /**
     * Connect to IMAP server using native PHP stream sockets and authenticate.
     *
     * @param array $cfg
     * @param string|null $err_msg
     * @return resource|false
     */
    private static function connect(array $cfg, ?string &$err_msg = null) {
        $host = $cfg['host'];
        $port = intval($cfg['port'] ?: 993);
        $enc  = strtolower($cfg['encryption']);

        $remote = $host;
        if ($enc === 'ssl') {
            $remote = 'ssl://' . $host;
        }

        $context = stream_context_create([
            'ssl' => [
                'verify_peer'      => false,
                'verify_peer_name' => false,
            ]
        ]);

        $errno = 0;
        $errstr = '';
        $stream = @stream_socket_client($remote . ':' . $port, $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $context);

        if (!$stream) {
            $err_msg = "Could not connect to {$remote}:{$port} ({$errstr})";
            return false;
        }

        stream_set_timeout($stream, 20);

        // Read server greeting
        $greeting = fgets($stream);
        if (!$greeting || !str_starts_with(trim($greeting), '* OK')) {
            $err_msg = "Invalid server greeting: " . trim($greeting ?: 'No response');
            fclose($stream);
            return false;
        }

        // STARTTLS if requested
        if ($enc === 'tls' || $enc === 'starttls') {
            $tag = self::send_command($stream, 'STARTTLS');
            $res = self::read_until_tag($stream, $tag);
            $ok = false;
            foreach ($res as $l) {
                if (str_contains($l, "{$tag} OK")) { $ok = true; break; }
            }
            if (!$ok || !@stream_socket_enable_crypto($stream, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT)) {
                $err_msg = "STARTTLS negotiation failed.";
                fclose($stream);
                return false;
            }
        }

        // LOGIN
        $user_escaped = str_replace(['\\', '"'], ['\\\\', '\"'], $cfg['username']);
        $pass_escaped = str_replace(['\\', '"'], ['\\\\', '\"'], $cfg['password']);

        $tag = self::send_command($stream, "LOGIN \"{$user_escaped}\" \"{$pass_escaped}\"");
        $res = self::read_until_tag($stream, $tag);

        $login_ok = false;
        foreach ($res as $line) {
            if (str_starts_with($line, "{$tag} OK")) {
                $login_ok = true;
                break;
            }
        }

        if (!$login_ok) {
            $err_msg = "Authentication failed for user {$cfg['username']}";
            fclose($stream);
            return false;
        }

        // SELECT Mailbox
        $mailbox = $cfg['mailbox'] ?: 'INBOX';
        $tag = self::send_command($stream, "SELECT \"{$mailbox}\"");
        $res = self::read_until_tag($stream, $tag);

        $select_ok = false;
        foreach ($res as $line) {
            if (str_starts_with($line, "{$tag} OK")) {
                $select_ok = true;
                break;
            }
        }

        if (!$select_ok) {
            $err_msg = "Unable to select mailbox \"{$mailbox}\"";
            fclose($stream);
            return false;
        }

        return $stream;
    }

    /**
     * Send an IMAP command with auto-generated tag.
     */
    private static function send_command($stream, string $command): string {
        static $counter = 0;
        $counter++;
        $tag = sprintf("A%04d", $counter);
        fwrite($stream, "{$tag} {$command}\r\n");
        return $tag;
    }

    /**
     * Read IMAP socket response lines until the completion tag is returned.
     */
    private static function read_until_tag($stream, string $tag): array {
        $lines = [];
        while (!feof($stream)) {
            $line = fgets($stream);
            if ($line === false) break;
            $trimmed = trim($line);
            $lines[] = $trimmed;
            if (str_starts_with($trimmed, "{$tag} OK") || str_starts_with($trimmed, "{$tag} NO") || str_starts_with($trimmed, "{$tag} BAD")) {
                break;
            }
        }
        return $lines;
    }

    /**
     * Read literal response for FETCH BODY payload with stream_select to prevent busy-wait and timeouts.
     * Supports both RFC 3501 ({size}) and RFC 7888 ({size+}) literal indicators.
     */
    private static function read_literal_response($stream, string $tag): string {
        $buffer = '';

        while (!feof($stream)) {
            $line = fgets($stream);
            if ($line === false) break;

            if (preg_match('/\{(\d+)\+?\}\s*$/', $line, $m)) {
                $literal_bytes = intval($m[1]);
                $read_so_far = 0;
                while ($read_so_far < $literal_bytes && !feof($stream)) {
                    $to_read = min(8192, $literal_bytes - $read_so_far);
                    $chunk = fread($stream, $to_read);
                    if ($chunk === false) {
                        break;
                    }
                    if ($chunk === '') {
                        $read_fds = [$stream];
                        $write_fds = null;
                        $except_fds = null;
                        $num_changed = @stream_select($read_fds, $write_fds, $except_fds, 5);
                        if ($num_changed === false || $num_changed === 0) {
                            // Socket timed out waiting for next packet
                            break;
                        }
                        continue;
                    }
                    $buffer .= $chunk;
                    $read_so_far += strlen($chunk);
                }
                continue;
            }

            $trimmed = trim($line);
            if (str_starts_with($trimmed, "{$tag} OK") || str_starts_with($trimmed, "{$tag} NO") || str_starts_with($trimmed, "{$tag} BAD")) {
                break;
            }
        }

        return $buffer;
    }

    /**
     * Mark IMAP message as \Seen.
     */
    private static function mark_seen($stream, int $msg_num): void {
        $tag = self::send_command($stream, "STORE {$msg_num} +FLAGS (\\Seen)");
        self::read_until_tag($stream, $tag);
    }

    /**
     * Mark IMAP message as \Deleted.
     */
    private static function mark_deleted($stream, int $msg_num): void {
        $tag = self::send_command($stream, "STORE {$msg_num} +FLAGS (\\Deleted \\Seen)");
        self::read_until_tag($stream, $tag);
    }

    /**
     * Disconnect cleanly from IMAP server.
     */
    private static function disconnect($stream): void {
        if ($stream) {
            $tag = self::send_command($stream, 'LOGOUT');
            self::read_until_tag($stream, $tag);
            @fclose($stream);
        }
    }

    /**
     * Extract attachment files from a raw RFC822 MIME message string.
     * Supports multipart/report (RFC 7489), multipart/mixed, multipart/alternative,
     * and single-part payloads (.zip, .gz, .xml, .json) in a safe, non-recursive manner.
     *
     * @param string $raw_mime
     * @return array Array of ['filename' => string, 'content' => string]
     */
    private static function extract_attachments(string $raw_mime): array {
        $attachments = [];

        // Collect all unique MIME boundaries in the message
        $boundaries = [];
        if (preg_match_all('/boundary=[\'"]?([^\'";\r\n]+)[\'"]?/i', $raw_mime, $all_bm)) {
            foreach ($all_bm[1] as $b) {
                $b = trim($b);
                if (!empty($b) && !in_array($b, $boundaries, true)) {
                    $boundaries[] = $b;
                }
            }
        }

        // If no boundary found, handle as single-part payload
        if (empty($boundaries)) {
            $header_body_split = preg_split('/\r?\n\r?\n/', $raw_mime, 2);
            $headers = $header_body_split[0] ?? '';
            $body    = $header_body_split[1] ?? $raw_mime;

            $encoding = '';
            if (preg_match('/content-transfer-encoding:\s*([a-z0-9\-]+)/i', $headers, $em)) {
                $encoding = strtolower(trim($em[1]));
            }

            $content = $body;
            if ($encoding === 'base64') {
                $clean = preg_replace('/--\s*$/', '', trim($body));
                $clean = preg_replace('/[^A-Za-z0-9+\/=]/', '', $clean);
                $content = base64_decode($clean);
            } elseif ($encoding === 'quoted-printable') {
                $content = quoted_printable_decode($body);
            }

            $trimmed = ltrim($content);
            if (str_starts_with($content, "\x1f\x8b") || str_starts_with($content, "PK\x03\x04") || str_starts_with($trimmed, '<?xml') || str_starts_with($trimmed, '{') || str_contains($trimmed, '<feedback')) {
                $attachments[] = ['filename' => 'report_payload', 'content' => $content];
            }
            return $attachments;
        }

        // Split message iteratively across all discovered boundaries
        $raw_parts = [$raw_mime];
        foreach ($boundaries as $b) {
            $next_parts = [];
            foreach ($raw_parts as $rp) {
                if (str_contains($rp, '--' . $b)) {
                    $splits = explode('--' . $b, $rp);
                    foreach ($splits as $s) {
                        $s_trimmed = trim($s);
                        if (!empty($s_trimmed) && !str_starts_with($s_trimmed, '--')) {
                            $next_parts[] = $s;
                        }
                    }
                } else {
                    $next_parts[] = $rp;
                }
            }
            $raw_parts = $next_parts;
        }

        foreach ($raw_parts as $part) {
            $trimmed_part = ltrim($part);
            if (empty($trimmed_part)) {
                continue;
            }

            $header_body_split = preg_split('/\r?\n\r?\n/', $trimmed_part, 2);
            if (count($header_body_split) < 2) {
                $headers = '';
                $body    = $trimmed_part;
            } else {
                $headers = $header_body_split[0];
                $body    = $header_body_split[1];
            }

            // Look for attachment filename or Content-Type matching report formats
            $filename = '';
            if (preg_match('/filename=[\'"]?([^\'";\r\n]+)[\'"]?/i', $headers, $fnm)) {
                $filename = trim($fnm[1]);
            } elseif (preg_match('/name=[\'"]?([^\'";\r\n]+)[\'"]?/i', $headers, $nm)) {
                $filename = trim($nm[1]);
            }

            $is_report = false;
            if (!empty($filename) && preg_match('/\.(xml|json|gz|zip|z)$/i', $filename)) {
                $is_report = true;
            } elseif (preg_match('/content-type:\s*(application\/zip|application\/x-zip|application\/x-zip-compressed|application\/gzip|application\/x-gzip|application\/octet-stream|application\/xml|text\/xml|application\/json|application\/tlsrpt\+gzip|application\/tlsrpt\+json)/i', $headers)) {
                $is_report = true;
                if (empty($filename)) {
                    $filename = 'report_attachment';
                }
            }

            // Check transfer encoding
            $encoding = '';
            if (preg_match('/content-transfer-encoding:\s*([a-z0-9\-]+)/i', $headers, $em)) {
                $encoding = strtolower(trim($em[1]));
            }

            // Decode payload cleanly
            if ($encoding === 'base64') {
                $clean = preg_replace('/--\s*$/', '', trim($body));
                $clean = preg_replace('/[^A-Za-z0-9+\/=]/', '', $clean);
                $content = base64_decode($clean);
            } elseif ($encoding === 'quoted-printable') {
                $content = quoted_printable_decode($body);
            } else {
                $clean = preg_replace('/--\s*$/', '', trim($body));
                $clean_b64 = preg_replace('/[^A-Za-z0-9+\/=]/', '', $clean);
                $try_b64 = (!empty($clean_b64) && strlen($clean_b64) % 4 === 0) ? base64_decode($clean_b64) : false;
                if ($try_b64 !== false && (str_starts_with($try_b64, "\x1f\x8b") || str_starts_with($try_b64, "PK\x03\x04") || str_contains($try_b64, '<feedback'))) {
                    $content = $try_b64;
                    $is_report = true;
                } else {
                    $content = $body;
                }
            }

            // If not marked by headers, verify if payload itself is GZIP, ZIP, XML or JSON
            if (!$is_report) {
                $raw_trim = ltrim($content);
                if (str_starts_with($content, "\x1f\x8b") || str_starts_with($content, "PK\x03\x04") || str_starts_with($raw_trim, '<?xml') || str_contains($raw_trim, '<feedback') || (str_starts_with($raw_trim, '{') && str_contains($raw_trim, 'organization-name'))) {
                    $is_report = true;
                    if (empty($filename)) {
                        $filename = 'report_payload';
                    }
                }
            }

            if ($is_report && !empty($content)) {
                $attachments[] = [
                    'filename' => $filename,
                    'content'  => $content,
                ];
            }
        }

        // Universal Fallback 1: Direct scan for Base64 ZIP archives (UEsDB is PK\x03\x04 in Base64)
        if (empty($attachments)) {
            if (preg_match_all('/(UEsDB[A-Za-z0-9+\/=\r\n\s]{30,})/s', $raw_mime, $zip_matches)) {
                foreach ($zip_matches[1] as $zm) {
                    $clean = preg_replace('/[^A-Za-z0-9+\/=]/', '', $zm);
                    $decoded = base64_decode($clean);
                    if ($decoded !== false && str_starts_with($decoded, "PK\x03\x04")) {
                        $attachments[] = [
                            'filename' => 'dmarc_report.zip',
                            'content'  => $decoded,
                        ];
                    }
                }
            }
        }

        // Universal Fallback 2: Direct scan for Base64 GZIP archives (H4sI is \x1f\x8b\x08 in Base64)
        if (empty($attachments)) {
            if (preg_match_all('/(H4sI[A-Za-z0-9+\/=\r\n\s]{30,})/s', $raw_mime, $gz_matches)) {
                foreach ($gz_matches[1] as $gm) {
                    $clean = preg_replace('/[^A-Za-z0-9+\/=]/', '', $gm);
                    $decoded = base64_decode($clean);
                    if ($decoded !== false && str_starts_with($decoded, "\x1f\x8b")) {
                        $attachments[] = [
                            'filename' => 'dmarc_report.xml.gz',
                            'content'  => $decoded,
                        ];
                    }
                }
            }
        }

        // Universal Fallback 3: Direct scan for embedded XML feedback element
        if (empty($attachments)) {
            if (preg_match('/(<feedback[\s>].*?<\/feedback>)/is', $raw_mime, $xml_m)) {
                $attachments[] = [
                    'filename' => 'dmarc_report.xml',
                    'content'  => $xml_m[1],
                ];
            }
        }

        return $attachments;
    }

    /**
     * Store status of last fetch operation in WP options.
     */
    private static function update_fetch_status(int $imported, int $duplicates, int $failed, array $errors): void {
        update_option('pn_mailguard_imap_last_fetch_time', current_time('mysql'));
        update_option('pn_mailguard_imap_last_fetch_summary', [
            'imported'   => $imported,
            'duplicates' => $duplicates,
            'failed'     => $failed,
            'errors'     => $errors,
        ]);
    }
}
