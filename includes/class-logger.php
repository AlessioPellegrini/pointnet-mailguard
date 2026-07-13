<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Logger
 *
 * Saves scan results to the database and handles automatic cleanup.
 * Uses two separate tables — one for email scans, one for IP scans.
 *
 * Usage:
 *   PN_Mailguard_Logger::save($data, 'email');
 *   PN_Mailguard_Logger::save($data, 'ip');
 *   PN_Mailguard_Logger::render_rows('email');
 *   PN_Mailguard_Logger::render_rows('ip');
 */
class PN_Mailguard_Logger {

    /**
     * Resolve the correct table name for the given scan type.
     *
     * @param string $type  'email' or 'ip'
     * @return string
     */
    private static function table(string $type): string {
        global $wpdb;
        $suffix = ($type === 'ip') ? PN_Mailguard_Installer::TABLE_IP : PN_Mailguard_Installer::TABLE_EMAIL;
        return $wpdb->prefix . $suffix;
    }

    /**
     * Save a scan result to the appropriate log table.
     *
     * @param array  $data  Result array from PN_Mailguard_Scanner::run()
     * @param string $type  'email' or 'ip'
     */
    public static function save(array $data, string $type = 'email'): void {
        global $wpdb;
        $table_name = self::table($type);
        $status     = self::build_status($data);
        $details    = self::build_details($data, $type);
        $ip         = ($type === 'ip') ? $data['ip'] : $data['mx_ip'];

        $wpdb->insert($table_name, [
            'ip_address' => sanitize_text_field($ip),
            'status'     => $status,
            'details'    => sanitize_text_field($details),
        ]);

        // Automatic cleanup: remove entries older than 30 days
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM `{$table_name}` WHERE scan_date < %s",
                gmdate('Y-m-d H:i:s', strtotime('-30 days'))
            )
        );
    }

    /**
     * Retrieve the most recent log rows for the given scan type.
     *
     * @param string $type   'email' or 'ip'
     * @param int    $limit
     * @return array|null
     */
    public static function get_rows(string $type = 'email', int $limit = 10): ?array {
        global $wpdb;
        $table_name = self::table($type);
        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM `{$table_name}` ORDER BY scan_date DESC LIMIT %d",
                $limit
            )
        );
    }

    /**
     * Render the log table rows as HTML.
     *
     * @param string $type  'email' or 'ip'
     */
    public static function render_rows(string $type = 'email'): void {
        $logs = self::get_rows($type, 10);
        if ($logs) {
            foreach ($logs as $log) {
                $color = self::status_color($log->status);
                echo '<tr>';
                echo '<td>' . esc_html($log->scan_date) . '</td>';
                echo '<td style="color:' . esc_attr($color) . ';font-weight:bold;">' . esc_html($log->status) . '</td>';
                echo '<td style="font-family:monospace; font-size:11px; line-height:1.6;">' . self::format_terminal_details($log->details) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- format_terminal_details() escapes HTML internally
                echo '</tr>';
            }
        } else {
            echo '<tr><td colspan="3">' . esc_html__('No logs found.', 'pointnet-mailguard') . '</td></tr>';
        }
    }

    /**
     * Build the status label from scan result data.
     *
     * @param array $data
     * @return string
     */
    public static function build_status(array $data): string {
        if (!empty($data['error'])) {
            return 'ERROR';
        }
        $status = $data['is_alert'] ? 'ALERT' : 'CLEAN';
        if (!empty($data['ptr_warning'])) {
            $status = ($status === 'ALERT') ? 'ALERT + PTR' : 'PTR WARNING';
        }
        if (!empty($data['spf_warning'])) {
            $status = ($status === 'CLEAN') ? 'SPF WARNING' : $status . ' + SPF';
        }
        return $status;
    }

    /**
     * Build the human-readable details string.
     *
     * @param array  $data
     * @param string $type  'email' or 'ip'
     * @return string
     */
    private static function build_details(array $data, string $type): string {
        if (!empty($data['error'])) {
            return 'Error: ' . $data['error'];
        }

        $parts = [];

        if ($type === 'email') {
            $parts[] = 'Email: ' . $data['email'];
            $parts[] = 'MX: ' . $data['mx_host'] . ' (' . $data['mx_ip'] . ')';
            $parts[] = 'WP IP: ' . $data['wp_ip'];
            $parts[] = 'Server: ' . ($data['shared_server'] ? 'SHARED' : 'SEPARATE');
            $parts[] = 'SPF: ' . strtoupper($data['spf_status'])
                . (!empty($data['spf_record']) ? ' (' . $data['spf_record'] . ')' : '');
        } else {
            $parts[] = 'IP: ' . $data['ip'];
        }

        foreach ($data['dnsbl'] as $name => $val) {
            $parts[] = $name . ': ' . $val;
        }

        $parts[] = 'PTR: ' . $data['ptr'];

        return implode(' | ', $parts);
    }

    /**
     * Format pipe-separated details into colored HTML lines (terminal-style).
     * Each segment gets a color based on its content (CLEAN/OK → green, LISTED/ERROR → red, WARNING/SHARED → yellow).
     *
     * @param string $details The pipe-separated details string.
     * @return string
     */
    public static function format_terminal_details(string $details): string {
        if (empty($details)) {
            return '';
        }
        $lines = explode(' | ', $details);
        $html = '';
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) continue;
            if (str_contains($line, 'LISTED') || str_contains($line, 'ERROR') || str_contains($line, 'ALERT')) {
                $color = '#f38ba8';
            } elseif (str_contains($line, 'WARNING') || str_contains($line, 'SHARED')) {
                $color = '#f9e2af';
            } elseif (str_contains($line, 'CLEAN') || str_contains($line, 'OK') || str_contains($line, 'PASS') || str_contains($line, 'SEPARATE')) {
                $color = '#a6e3a1';
            } else {
                $color = '#cdd6f4';
            }
            $html .= '<span style="color:' . $color . ';">' . esc_html($line) . '</span><br>';
        }
        return $html;
    }

    /**
     * Return the hex color for a given status label.
     *
     * @param string $status
     * @return string
     */
    public static function status_color(string $status): string {
        if (str_contains($status, 'ERROR') || str_contains($status, 'ALERT')) {
            // But if it's only CLEAN with SPF warning, it's yellow
            if ($status === 'SPF WARNING') {
                return '#dba617';
            }
            return '#d63638';
        }
        // Any warning → yellow
        if (str_contains($status, 'WARNING')) {
            return '#dba617';
        }
        // Everything else → green
        return '#00a32a';
    }
}