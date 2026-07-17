<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Mailer
 *
 * Composes and sends alert emails when problems are detected.
 * All strings use __() so they are translated in the site language.
 */
class PN_Mailguard_Mailer {

    public static function maybe_send(array $data, string $type = 'email'): void {
        if (empty($data['error']) && empty($data['is_alert']) && empty($data['ptr_warning']) && empty($data['spf_warning']) && empty($data['dmarc_warning']) && empty($data['dkim_warning']) && empty($data['mtasts_warning'])) {
            return;
        }

        $to      = get_option('pn_mailguard_email_alert', get_option('admin_email'));
        $subject = self::build_subject($data, $type);
        $body    = self::build_body($data, $type);

        wp_mail($to, $subject, $body);
    }

    private static function build_subject(array $data, string $type): string {
        $label = ($type === 'ip') ? $data['ip'] : $data['mx_ip'];

        if (!empty($data['error'])) {
            $source = ($type === 'ip') ? $data['ip'] : $data['email'];
            return sprintf(
                /* translators: %s: source email or IP that had the error */
                __('⚠️ PointNet ALERT: scan error for %s', 'pointnet-mailguard'),
                $source
            );
        }

        $parts = [];
        if ($data['is_alert'])    $parts[] = 'blacklist';
        if ($data['ptr_warning']) $parts[] = 'PTR missing';
        if (!empty($data['spf_warning'])) $parts[] = 'SPF ' . $data['spf_status'];
        if (!empty($data['dmarc_warning'])) $parts[] = 'DMARC';
        if (!empty($data['dkim_warning'])) $parts[] = 'DKIM error';
        if (!empty($data['mtasts_warning'])) $parts[] = 'MTA-STS';

        if (count($parts) >= 2) {
            return sprintf(
                /* translators: 1: IP address, 2: space-separated list of issues (blacklist, PTR, SPF) */
                __('⚠️ PointNet ALERT: %1$s — %2$s', 'pointnet-mailguard'),
                $label,
                implode(' + ', $parts)
            );
        } elseif (!empty($parts[0])) {
            return sprintf(
                /* translators: 1: IP address, 2: issue description */
                __('⚠️ PointNet ALERT: %1$s — %2$s', 'pointnet-mailguard'),
                $label,
                $parts[0]
            );
        }

        return sprintf(
            /* translators: %s: IP address with detected issue */
            __('⚠️ PointNet ALERT: %s — issue detected', 'pointnet-mailguard'),
            $label
        );
    }

    private static function build_body(array $data, string $type): string {
        $sep  = "======================================\n\n";
        $body = __('PointNet Mail Guard — ALERT', 'pointnet-mailguard') . "\n" . $sep;

        if (!empty($data['error'])) {
            $source = ($type === 'ip') ? $data['ip'] : $data['email'];
            $body .= __('Scan error', 'pointnet-mailguard') . ' : ' . $data['error'] . "\n";
            $body .= __('Target',     'pointnet-mailguard') . '     : ' . $source . "\n";
            return $body;
        }

        if ($type === 'email') {
            $body .= __('Email checked',  'pointnet-mailguard') . '  : ' . $data['email']   . "\n";
            $body .= __('Domain',         'pointnet-mailguard') . '         : ' . $data['domain']   . "\n";
            $body .= __('Mail server',    'pointnet-mailguard') . '    : ' . sanitize_text_field($data['mx_host']) . "\n";
            $body .= __('Mail server IP', 'pointnet-mailguard') . ' : ' . sanitize_text_field($data['mx_ip'])   . "\n";
            $body .= __('WordPress IP',   'pointnet-mailguard') . '   : ' . sanitize_text_field($data['wp_ip'])   . "\n";
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
        if (!empty($data['dmarc_warning'])) {
            $body .= '🟡 ' . __('DMARC configuration has issues.', 'pointnet-mailguard') . "\n";
        }
        if (!empty($data['dkim_warning'])) {
            $body .= '🔴 ' . __('DKIM key problem detected.', 'pointnet-mailguard') . "\n";
        }
        if (isset($data['mtasts_status'])) {
            if ($data['mtasts_status'] === 'missing') {
                $body .= '🔴 ' . __('MTA-STS policy is missing.', 'pointnet-mailguard') . "\n";
            } elseif (!empty($data['mtasts_warning'])) {
                $body .= '🟡 ' . __('MTA-STS policy has warnings.', 'pointnet-mailguard') . "\n";
            }
        }

        $body .= "\n" . __('DNSBL Results', 'pointnet-mailguard') . ":\n";
        foreach ($data['dnsbl'] as $name => $val) {
            $body .= '  - ' . sanitize_text_field($name) . ': ' . sanitize_text_field($val) . "\n";
        }

        $body .= "\n" . __('PTR Check', 'pointnet-mailguard') . ":\n";
        $body .= $data['ptr_warning']
            ? '  - PTR: ' . sanitize_text_field($data['ptr']) . ' (' . __('WARNING: not configured', 'pointnet-mailguard') . ')' . "\n"
            : '  - PTR: ' . sanitize_text_field($data['ptr']) . "\n";

        if (isset($data['spf_status'])) {
            $body .= "\n" . __('SPF Check', 'pointnet-mailguard') . ":\n";
            if ($data['spf_status'] === 'ok') {
                $body .= '  - SPF: ' . sanitize_text_field($data['spf_record']) . "\n";
            } elseif ($data['spf_status'] === 'missing') {
                $body .= '  - SPF: ' . __('MISSING — no SPF record found', 'pointnet-mailguard') . "\n";
            } else {
                $body .= '  - SPF: ' . __('INVALID', 'pointnet-mailguard') . ' — ' . $data['spf_record'] . "\n";
            }
        }

        if (isset($data['dmarc_status'])) {
            $body .= "\n" . __('DMARC Check', 'pointnet-mailguard') . ":\n";
            $dmarc_icon = $data['dmarc_status'] === 'ok' ? '✅' : '⚠️';
            $body .= '  - ' . $dmarc_icon . ' DMARC: ' . strtoupper($data['dmarc_status']);
            if (!empty($data['dmarc_errors']))   $body .= ' (errors: ' . intval($data['dmarc_errors']) . ')';
            if (!empty($data['dmarc_warnings'])) $body .= ' (warnings: ' . intval($data['dmarc_warnings']) . ')';
            $body .= "\n";
        }

        if (isset($data['dkim_status'])) {
            $body .= "\n" . __('DKIM Check', 'pointnet-mailguard') . ":\n";
            $dkim_icon = $data['dkim_status'] === 'ok' ? '✅' : '⚠️';
            $body .= '  - ' . $dkim_icon . ' DKIM: ' . strtoupper($data['dkim_status']);
            if (!empty($data['dkim_errors']))    $body .= ' (errors: ' . intval($data['dkim_errors']) . ')';
            if (!empty($data['dkim_warnings']))  $body .= ' (warnings: ' . intval($data['dkim_warnings']) . ')';
            $body .= "\n";
        }

        if (isset($data['mtasts_status'])) {
            $body .= "\n" . __('MTA-STS Check', 'pointnet-mailguard') . ":\n";
            $mtasts_icon = $data['mtasts_status'] === 'ok' ? '✅' : '⚠️';
            $body .= '  - ' . $mtasts_icon . ' MTA-STS: ' . strtoupper($data['mtasts_status']);
            if (!empty($data['mtasts_record']))  $body .= ' (record: ' . sanitize_text_field($data['mtasts_record']) . ')';
            $body .= "\n";
        }

        return $body;
    }
}