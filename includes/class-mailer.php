<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Mailer
 *
 * Composes and sends alert emails when problems are detected.
 * All strings use __() so they are translated in the site language.
 */
class PN_Mailguard_Mailer {

    public static function maybe_send(array $data, $type = 'email') {
        if (empty($data['error']) && empty($data['is_alert']) && empty($data['ptr_warning'])) {
            return;
        }

        $to      = get_option('pn_mailguard_email_alert', get_option('admin_email'));
        $subject = self::build_subject($data, $type);
        $body    = self::build_body($data, $type);

        wp_mail($to, $subject, $body);
    }

    private static function build_subject(array $data, $type) {
        $label = ($type === 'ip') ? $data['ip'] : $data['mx_ip'];

        if (!empty($data['error'])) {
            $source = ($type === 'ip') ? $data['ip'] : $data['email'];
            return sprintf(
                __('⚠️ PointNet ALERT: scan error for %s', 'pointnet-mailguard'),
                $source
            );
        }

        if ($data['is_alert'] && $data['ptr_warning']) {
            return sprintf(
                __('⚠️ PointNet ALERT: %s — blacklist + PTR issue', 'pointnet-mailguard'),
                $label
            );
        } elseif ($data['is_alert']) {
            return sprintf(
                __('⚠️ PointNet ALERT: %s is listed on a blacklist', 'pointnet-mailguard'),
                $label
            );
        } else {
            return sprintf(
                __('⚠️ PointNet ALERT: %s — PTR (reverse DNS) not configured', 'pointnet-mailguard'),
                $label
            );
        }
    }

    private static function build_body(array $data, $type) {
        $sep  = "======================================\n\n";
        $body = __('PointNet Mail Guard AI — ALERT', 'pointnet-mailguard') . "\n" . $sep;

        if (!empty($data['error'])) {
            $source = ($type === 'ip') ? $data['ip'] : $data['email'];
            $body .= __('Scan error', 'pointnet-mailguard') . ' : ' . $data['error'] . "\n";
            $body .= __('Target',     'pointnet-mailguard') . '     : ' . $source . "\n";
            return $body;
        }

        if ($type === 'email') {
            $body .= __('Email checked',  'pointnet-mailguard') . '  : ' . $data['email']   . "\n";
            $body .= __('Domain',         'pointnet-mailguard') . '         : ' . $data['domain']   . "\n";
            $body .= __('Mail server',    'pointnet-mailguard') . '    : ' . $data['mx_host'] . "\n";
            $body .= __('Mail server IP', 'pointnet-mailguard') . ' : ' . $data['mx_ip']   . "\n";
            $body .= __('WordPress IP',   'pointnet-mailguard') . '   : ' . $data['wp_ip']   . "\n";
            $body .= __('Server setup',   'pointnet-mailguard') . '   : ';
            $body .= $data['shared_server']
                ? __('SHARED (mail and WordPress on same server)', 'pointnet-mailguard')
                : __('SEPARATE (dedicated mail server)',           'pointnet-mailguard');
            $body .= "\n";
        } else {
            $body .= __('IP address', 'pointnet-mailguard') . '     : ' . $data['ip'] . "\n";
        }

        $body .= __('Scan time', 'pointnet-mailguard') . '      : ' . current_time('mysql') . "\n\n";

        if ($data['is_alert'])    $body .= '🔴 ' . __('IP is listed on one or more blacklists.', 'pointnet-mailguard') . "\n";
        if ($data['ptr_warning']) $body .= '🟡 ' . __('PTR (reverse DNS) is not configured.',    'pointnet-mailguard') . "\n";
        if (!empty($data['spf_warning'])) {
            $body .= '🟡 ' . ($data['spf_status'] === 'missing'
                ? __('SPF record is missing.', 'pointnet-mailguard')
                : __('SPF record is invalid.', 'pointnet-mailguard')
            ) . "\n";
        }

        $body .= "\n" . __('DNSBL Results', 'pointnet-mailguard') . ":\n";
        foreach ($data['dnsbl'] as $name => $val) {
            $body .= '  - ' . $name . ': ' . $val . "\n";
        }

        $body .= "\n" . __('PTR Check', 'pointnet-mailguard') . ":\n";
        $body .= $data['ptr_warning']
            ? '  - PTR: ' . $data['ptr'] . ' (' . __('WARNING: not configured', 'pointnet-mailguard') . ')' . "\n"
            : '  - PTR: ' . $data['ptr'] . "\n";

        if (isset($data['spf_status'])) {
            $body .= "\n" . __('SPF Check', 'pointnet-mailguard') . ":\n";
            if ($data['spf_status'] === 'ok') {
                $body .= '  - SPF: ' . $data['spf_record'] . "\n";
            } elseif ($data['spf_status'] === 'missing') {
                $body .= '  - SPF: ' . __('MISSING — no SPF record found', 'pointnet-mailguard') . "\n";
            } else {
                $body .= '  - SPF: ' . __('INVALID', 'pointnet-mailguard') . ' — ' . $data['spf_record'] . "\n";
            }
        }

        return $body;
    }
}
