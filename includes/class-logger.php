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
    private static function table($type) {
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
    public static function save(array $data, $type = 'email') {
        global $wpdb;
        $table_name = self::table($type);
        $status     = self::build_status($data);
        $details    = self::build_details($data, $type);
        $ip         = ($type === 'ip') ? $data['ip'] : $data['mx_ip'];

        $wpdb->insert($table_name, array(
            'ip_address' => sanitize_text_field($ip),
            'status'     => $status,
            'details'    => sanitize_text_field($details),
        ));

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
    public static function get_rows($type = 'email', $limit = 10) {
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
    public static function render_rows($type = 'email') {
        $logs = self::get_rows($type, 10);
        if ($logs) {
            foreach ($logs as $log) {
                $color = self::status_color($log->status);
                echo '<tr>';
                echo '<td>' . esc_html($log->scan_date) . '</td>';
                echo '<td style="color:' . esc_attr($color) . ';font-weight:bold;">' . esc_html($log->status) . '</td>';
                echo '<td>' . esc_html($log->details) . '</td>';
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
    public static function build_status(array $data) {
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
    private static function build_details(array $data, $type) {
        if (!empty($data['error'])) {
            return 'Error: ' . $data['error'];
        }

        $parts = array();

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
     * Return the hex color for a given status label.
     *
     * @param string $status
     * @return string
     */
    public static function status_color($status) {
        switch ($status) {
            case 'ALERT':
            case 'ALERT + PTR':
            case 'ERROR':
                return '#d63638';
            case 'PTR WARNING':
                return '#dba617';
            default:
                return '#00a32a';
        }
    }
}
