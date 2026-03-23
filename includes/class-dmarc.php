<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_DMARC
 *
 * Full DMARC record analyser.
 * Checks presence, syntax, policy strength and report configuration
 * following RFC 7489.
 *
 * Usage:
 *   $result = PN_Mailguard_DMARC::analyze('example.com');
 */
class PN_Mailguard_DMARC {

    /**
     * Analyze the DMARC record for the given domain or email address.
     *
     * @param string $input  Domain or email address
     * @return array
     */
    public static function analyze($input) {
        $domain = self::extract_domain($input);

        $base = array(
            'domain'  => $domain,
            'record'  => '',
            'status'  => 'missing',
            'checks'  => array(),
            'passed'  => 0,
            'warnings'=> 0,
            'errors'  => 0,
            'tags'    => array(),
            'error'   => '',
        );

        if (empty($domain)) {
            $base['error'] = 'Invalid domain or email address.';
            return $base;
        }

        // DMARC record lives on _dmarc.domain
        $dmarc_domain = '_dmarc.' . $domain;
        $txt_records  = @dns_get_record($dmarc_domain, DNS_TXT);

        $checks  = array();
        $passed  = $warnings = $errors = 0;

        // CHECK 1: Record present
        if (empty($txt_records)) {
            $checks[] = self::result('record_present', 'error',
                'No DMARC record found',
                'No DMARC TXT record was found on _dmarc.' . $domain . '. Without DMARC, anyone can spoof your domain and you receive no reports about email abuse. Add a DMARC record to start protecting your domain.'
            );
            $errors++;
            $base['checks'] = $checks;
            $base['errors'] = $errors;
            return $base;
        }

        // Find the DMARC record
        $record = '';
        foreach ($txt_records as $rec) {
            if (!empty($rec['txt']) && stripos(trim($rec['txt']), 'v=DMARC1') === 0) {
                $record = trim($rec['txt']);
                break;
            }
        }

        if (empty($record)) {
            $checks[] = self::result('record_present', 'error',
                'No valid DMARC record found',
                'A TXT record exists on _dmarc.' . $domain . ' but it does not start with v=DMARC1. The record is invalid and will be ignored by mail servers.'
            );
            $errors++;
            $base['checks'] = $checks;
            $base['errors'] = $errors;
            return $base;
        }

        $checks[] = self::result('record_present', 'ok',
            'DMARC record found',
            'A valid DMARC TXT record starting with v=DMARC1 was found on _dmarc.' . $domain . '.'
        );
        $passed++;
        $base['record'] = $record;

        // Parse tags
        $tags = self::parse_tags($record);
        $base['tags'] = $tags;

        // CHECK 2: Syntax — required tags
        if (empty($tags['p'])) {
            $checks[] = self::result('syntax', 'error',
                'Missing required tag: p=',
                'The p= tag defines the policy (none, quarantine, reject) and is mandatory in every DMARC record. Without it the record is invalid.'
            );
            $errors++;
        } else {
            $checks[] = self::result('syntax', 'ok',
                'Record syntax valid',
                'The record contains all required tags and is syntactically correct.'
            );
            $passed++;
        }

        // CHECK 3: Policy strength
        $policy = strtolower($tags['p'] ?? '');
        if ($policy === 'none') {
            $checks[] = self::result('policy', 'warning',
                'Policy too weak: p=none',
                'p=none means DMARC is in monitoring mode only — no action is taken on failing emails. It is useful when first setting up DMARC, but you should move to p=quarantine or p=reject once you are confident your SPF and DKIM are correctly configured.'
            );
            $warnings++;
        } elseif ($policy === 'quarantine') {
            $checks[] = self::result('policy', 'warning',
                'Policy moderate: p=quarantine',
                'p=quarantine sends failing emails to the spam folder. Good intermediate step — consider moving to p=reject for maximum protection once you have verified all legitimate senders pass DMARC.'
            );
            $warnings++;
        } elseif ($policy === 'reject') {
            $checks[] = self::result('policy', 'ok',
                'Policy strict: p=reject',
                'p=reject instructs receiving servers to reject emails that fail DMARC. This is the strongest protection against spoofing and phishing.'
            );
            $passed++;
        } elseif (!empty($policy)) {
            $checks[] = self::result('policy', 'error',
                'Invalid policy value: p=' . esc_html($policy),
                'The p= tag must be one of: none, quarantine, reject. The current value is not recognised.'
            );
            $errors++;
        }

        // CHECK 4: Percentage
        $pct = isset($tags['pct']) ? intval($tags['pct']) : 100;
        if ($pct < 100) {
            $checks[] = self::result('pct', 'warning',
                'Policy applies to ' . $pct . '% of emails only',
                'pct=' . $pct . ' means the DMARC policy is applied to only ' . $pct . '% of messages. This is useful during gradual rollout but should be increased to pct=100 for full protection.'
            );
            $warnings++;
        } else {
            $checks[] = self::result('pct', 'ok',
                'Policy applies to 100% of emails',
                'pct=100 (or not set, which defaults to 100) — the policy applies to all messages.'
            );
            $passed++;
        }

        // CHECK 5: Aggregate report address (rua)
        if (empty($tags['rua'])) {
            $checks[] = self::result('rua', 'warning',
                'No aggregate report address (rua)',
                'Without rua= you will never receive DMARC reports. These reports show you which servers are sending email as your domain — legitimate and illegitimate. Add rua=mailto:youraddress@yourdomain.com to start receiving them.'
            );
            $warnings++;
        } else {
            $checks[] = self::result('rua', 'ok',
                'Aggregate reports configured',
                'rua=' . esc_html($tags['rua']) . ' — you will receive aggregate reports about email authentication results for your domain.'
            );
            $passed++;
        }

        // CHECK 6: Subdomain policy (sp)
        if (empty($tags['sp'])) {
            $checks[] = self::result('sp', 'info',
                'No subdomain policy (sp)',
                'sp= is not set — subdomains will inherit the main domain policy (p=' . esc_html($policy) . '). This is usually correct. Set sp= only if you want a different policy for subdomains.'
            );
        } else {
            $sp = strtolower($tags['sp']);
            if ($sp === 'reject' || $sp === 'quarantine') {
                $checks[] = self::result('sp', 'ok',
                    'Subdomain policy set: sp=' . esc_html($sp),
                    'Subdomains have their own explicit policy: ' . esc_html($sp) . '.'
                );
                $passed++;
            } else {
                $checks[] = self::result('sp', 'warning',
                    'Weak subdomain policy: sp=' . esc_html($sp),
                    'Subdomains use p=none — consider setting sp=quarantine or sp=reject to protect your subdomains from spoofing.'
                );
                $warnings++;
            }
        }

        // CHECK 7: Alignment
        $aspf  = strtolower($tags['aspf'] ?? 'r');
        $adkim = strtolower($tags['adkim'] ?? 'r');
        if ($aspf === 's' || $adkim === 's') {
            $checks[] = self::result('alignment', 'ok',
                'Strict alignment configured',
                'adkim=' . esc_html($adkim) . ' aspf=' . esc_html($aspf) . ' — strict alignment requires an exact domain match. More secure but less forgiving of legitimate third-party senders.'
            );
            $passed++;
        } else {
            $checks[] = self::result('alignment', 'info',
                'Relaxed alignment (default)',
                'adkim=r aspf=r (relaxed) — the authenticated domain only needs to match the organisational domain, not the exact subdomain. This is the recommended default for most organisations.'
            );
        }

        // CHECK 8: SPF correlation
        $spf_result = PN_Mailguard_SPF::analyze($domain);
        if ($spf_result['status'] === 'missing') {
            $checks[] = self::result('spf_correlation', 'error',
                'SPF record missing — DMARC effectiveness reduced',
                'DMARC works best when both SPF and DKIM are configured. Your domain has no SPF record — fix this to maximise DMARC protection.'
            );
            $errors++;
        } elseif ($spf_result['status'] === 'error') {
            $checks[] = self::result('spf_correlation', 'warning',
                'SPF record has errors — DMARC effectiveness reduced',
                'Your SPF record has configuration errors. Fix SPF to ensure DMARC can use it for authentication.'
            );
            $warnings++;
        } elseif ($policy === 'reject' && $spf_result['status'] === 'warning') {
            $checks[] = self::result('spf_correlation', 'warning',
                'DMARC policy is strict but SPF has warnings',
                'You have p=reject but your SPF record has warnings (e.g. ~all or ?all). For maximum effectiveness, align your SPF to use -all.'
            );
            $warnings++;
        } else {
            $checks[] = self::result('spf_correlation', 'ok',
                'SPF and DMARC are consistent',
                'Your SPF record is correctly configured and consistent with your DMARC policy.'
            );
            $passed++;
        }

        // Overall status
        $status = $errors > 0 ? 'error' : ($warnings > 0 ? 'warning' : 'ok');

        $base['status']   = $status;
        $base['checks']   = $checks;
        $base['passed']   = $passed;
        $base['warnings'] = $warnings;
        $base['errors']   = $errors;

        return $base;
    }

    /**
     * Parse DMARC record tags into key => value array.
     *
     * @param string $record
     * @return array
     */
    private static function parse_tags($record) {
        $tags  = array();
        $parts = explode(';', $record);
        foreach ($parts as $part) {
            $part = trim($part);
            if (strpos($part, '=') !== false) {
                list($key, $val) = explode('=', $part, 2);
                $tags[trim(strtolower($key))] = trim($val);
            }
        }
        return $tags;
    }

    /**
     * Extract domain from email or domain string.
     *
     * @param string $input
     * @return string
     */
    private static function extract_domain($input) {
        $input = trim(strtolower($input));
        if (strpos($input, '@') !== false) {
            $parts = explode('@', $input);
            return trim($parts[1]);
        }
        return $input;
    }

    /**
     * Build a single check result array.
     *
     * @param string $id
     * @param string $status  'ok' | 'warning' | 'error' | 'info'
     * @param string $title
     * @param string $description
     * @return array
     */
    private static function result($id, $status, $title, $description) {
        return array(
            'id'          => $id,
            'status'      => $status,
            'title'       => $title,
            'description' => $description,
        );
    }
}
