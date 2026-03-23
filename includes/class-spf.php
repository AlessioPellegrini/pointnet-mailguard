<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_SPF
 *
 * Full SPF record analyser — RFC 7208 compliant.
 * Used both by the Email Monitor tab (quick check) and the SPF Analyzer tab (full analysis).
 *
 * Usage:
 *   $result = PN_Mailguard_SPF::analyze('example.com');
 *   $quick  = PN_Mailguard_SPF::check('example.com');
 */
class PN_Mailguard_SPF {

    private static $providers = array(
        '_spf.google.com'            => 'Google Workspace',
        'googlemail.com'             => 'Gmail',
        '_spf.mail.yahoo.com'        => 'Yahoo Mail',
        'amazonses.com'              => 'Amazon SES',
        'mailgun.org'                => 'Mailgun',
        'sendgrid.net'               => 'SendGrid',
        'spf.mandrillapp.com'        => 'Mailchimp / Mandrill',
        'mailchimp.com'              => 'Mailchimp',
        'spf.protection.outlook.com' => 'Microsoft 365',
        'protection.outlook.com'     => 'Microsoft 365',
        'mktomail.com'               => 'Marketo',
        'salesforce.com'             => 'Salesforce',
        'exacttarget.com'            => 'Salesforce Marketing Cloud',
        '_spf.aruba.it'              => 'Aruba',
        'relay.aruba.it'             => 'Aruba',
        'spf.sendinblue.com'         => 'Brevo (Sendinblue)',
        'spf.brevo.com'              => 'Brevo',
        'spf.sparkpostmail.com'      => 'SparkPost',
        'mailersend.com'             => 'MailerSend',
        'zoho.com'                   => 'Zoho Mail',
        'postmarkapp.com'            => 'Postmark',
        'rsgsv.net'                  => 'Mailchimp',
        'mcsv.net'                   => 'Mailchimp',
    );

    /**
     * Full SPF analysis for the SPF Analyzer tab.
     */
    public static function analyze($input) {
        $domain = self::extract_domain($input);

        $base = array(
            'domain'      => $domain,
            'record'      => '',
            'status'      => 'missing',
            'checks'      => array(),
            'passed'      => 0,
            'warnings'    => 0,
            'errors'      => 0,
            'dns_lookups' => 0,
            'providers'   => array(),
            'error'       => '',
        );

        if (empty($domain)) {
            $base['error'] = 'Invalid domain or email address.';
            return $base;
        }

        $txt_records = @dns_get_record($domain, DNS_TXT);
        if ($txt_records === false) {
            $base['error'] = 'DNS query failed for domain: ' . $domain;
            return $base;
        }

        $spf_records = array();
        foreach ($txt_records as $rec) {
            if (!empty($rec['txt']) && stripos(trim($rec['txt']), 'v=spf1') === 0) {
                $spf_records[] = trim($rec['txt']);
            }
        }

        $checks = array();
        $passed = $warnings = $errors = 0;

        // CHECK 1: Record present
        if (empty($spf_records)) {
            $checks[] = self::result('record_present', 'error',
                'No SPF record found',
                'No TXT record starting with v=spf1 was found on this domain. Without SPF, receiving servers cannot verify your senders and may reject or mark your email as spam.'
            );
            $errors++;
            $base['checks'] = $checks;
            $base['errors'] = $errors;
            return $base;
        }
        $checks[] = self::result('record_present', 'ok',
            'SPF record found',
            'A valid TXT record starting with v=spf1 was found on the domain.'
        );
        $passed++;

        $record = $spf_records[0];
        $base['record'] = $record;

        // CHECK 2: Single record
        if (count($spf_records) > 1) {
            $checks[] = self::result('single_record', 'error',
                'Multiple SPF records found (' . count($spf_records) . ')',
                'Only one SPF record is allowed per domain (RFC 7208). Multiple records cause a permanent error (permerror) and result in immediate rejection by many mail servers. Delete all but one.'
            );
            $errors++;
        } else {
            $checks[] = self::result('single_record', 'ok',
                'Single SPF record',
                'Only one SPF record exists on the domain, as required by RFC 7208.'
            );
            $passed++;
        }

        // CHECK 3: Record length
        $len = strlen($record);
        if ($len > 255) {
            $checks[] = self::result('record_length', 'warning',
                'Record is long (' . $len . ' chars)',
                'The SPF record exceeds 255 characters. Some DNS implementations have trouble with long TXT records. Consider consolidating include: mechanisms or using ip4:/ip6: directly.'
            );
            $warnings++;
        } else {
            $checks[] = self::result('record_length', 'ok',
                'Record length ok (' . $len . ' chars)',
                'The record is within the recommended 255-character limit.'
            );
            $passed++;
        }

        // Parse mechanisms
        $parts        = preg_split('/\s+/', trim($record));
        $mechanisms   = array_slice($parts, 1);
        $dns_lookups  = 0;
        $void_lookups = 0;
        $includes     = array();
        $has_ptr      = false;
        $has_exists   = false;
        $has_plus_all = false;
        $qualifier    = null;
        $providers    = array();

        foreach ($mechanisms as $mech) {
            if (preg_match('/^([+\-~?])all$/i', $mech, $m)) {
                $qualifier = $m[1];
                if ($m[1] === '+') $has_plus_all = true;
                continue;
            }
            if (preg_match('/^all$/i', $mech)) {
                $qualifier    = '+';
                $has_plus_all = true;
                continue;
            }
            if (preg_match('/^[+\-~?]?(include):(.+)$/i', $mech, $m)) {
                $dns_lookups++;
                $inc = strtolower($m[2]);
                $includes[] = $inc;
                $res = @dns_get_record($inc, DNS_TXT);
                if (empty($res)) $void_lookups++;
                foreach (self::$providers as $pattern => $name) {
                    if (stripos($inc, $pattern) !== false) {
                        if (!in_array($name, $providers)) $providers[] = $name;
                        break;
                    }
                }
            } elseif (preg_match('/^[+\-~?]?(a|mx)(:.*)?$/i', $mech)) {
                $dns_lookups++;
            } elseif (preg_match('/^[+\-~?]?exists(:.*)?$/i', $mech)) {
                $dns_lookups++;
                $has_exists = true;
            } elseif (preg_match('/^[+\-~?]?ptr(:.*)?$/i', $mech)) {
                $dns_lookups++;
                $has_ptr = true;
            }
        }

        $base['dns_lookups'] = $dns_lookups;
        $base['providers']   = $providers;

        // CHECK 4: Final qualifier
        if ($qualifier === null) {
            $checks[] = self::result('qualifier', 'error',
                'Missing final qualifier (all)',
                'The SPF record has no final qualifier. RFC 7208 requires ending with -all, ~all or ?all. Without it, behaviour is undefined and enforcement is impossible.'
            );
            $errors++;
        } elseif ($qualifier === '+') {
            $checks[] = self::result('qualifier', 'error',
                'Dangerous qualifier: +all',
                '+all means any server in the world is authorised to send email as your domain. This completely defeats SPF. Change it to -all or ~all immediately.'
            );
            $errors++;
        } elseif ($qualifier === '-') {
            $checks[] = self::result('qualifier', 'ok',
                'Strict qualifier: -all (hardfail)',
                'Unauthorised senders are rejected outright. This is the recommended setting for domains with a complete and tested sender list.'
            );
            $passed++;
        } elseif ($qualifier === '~') {
            $checks[] = self::result('qualifier', 'warning',
                'Permissive qualifier: ~all (softfail)',
                'Emails from unauthorised IPs are accepted but flagged as suspicious. Useful during initial SPF setup — consider switching to -all once all legitimate senders are listed.'
            );
            $warnings++;
        } elseif ($qualifier === '?') {
            $checks[] = self::result('qualifier', 'warning',
                'Neutral qualifier: ?all',
                '?all means the domain makes no assertion about unauthorised senders — effectively disabling SPF enforcement. Use -all or ~all instead.'
            );
            $warnings++;
        }

        // CHECK 5: DNS lookup count
        if ($dns_lookups > 10) {
            $checks[] = self::result('dns_lookups', 'error',
                'Too many DNS lookups (' . $dns_lookups . '/10)',
                'RFC 7208 limits SPF evaluation to 10 DNS-querying mechanisms. Exceeding this causes a permanent error (permerror) and email rejection. Consolidate your include: entries or use ip4:/ip6: directly.'
            );
            $errors++;
        } elseif ($dns_lookups >= 8) {
            $checks[] = self::result('dns_lookups', 'warning',
                'DNS lookups near limit (' . $dns_lookups . '/10)',
                'You are approaching the RFC 7208 limit of 10 DNS lookups. Adding more include: mechanisms may cause a permerror. Consider consolidating senders.'
            );
            $warnings++;
        } else {
            $checks[] = self::result('dns_lookups', 'ok',
                'DNS lookup count ok (' . $dns_lookups . '/10)',
                'Well within the RFC 7208 limit of 10 DNS-querying mechanisms.'
            );
            $passed++;
        }

        // CHECK 6: Void lookups
        if ($void_lookups > 2) {
            $checks[] = self::result('void_lookups', 'error',
                'Too many void lookups (' . $void_lookups . ')',
                'RFC 7208 limits void lookups (DNS queries returning no results) to 2. Exceeding this causes a permerror. Check that all include: domains are correctly configured.'
            );
            $errors++;
        } elseif ($void_lookups > 0) {
            $checks[] = self::result('void_lookups', 'warning',
                'Void lookups detected (' . $void_lookups . ')',
                'One or more include: domains returned no DNS results. This wastes lookup budget and may indicate stale or incorrect entries.'
            );
            $warnings++;
        } else {
            $checks[] = self::result('void_lookups', 'ok',
                'No void lookups',
                'All include: domains resolve correctly.'
            );
            $passed++;
        }

        // CHECK 7: PTR mechanism
        if ($has_ptr) {
            $checks[] = self::result('ptr_mechanism', 'warning',
                'Deprecated ptr mechanism found',
                'The ptr mechanism is explicitly discouraged by RFC 7208. It is slow, unreliable and wastes DNS lookups. Replace it with ip4: or ip6: pointing directly to your mail server IP addresses.'
            );
            $warnings++;
        } else {
            $checks[] = self::result('ptr_mechanism', 'ok',
                'No ptr mechanism',
                'The deprecated ptr mechanism is not used — good.'
            );
            $passed++;
        }

        // CHECK 8: exists mechanism
        if ($has_exists) {
            $checks[] = self::result('exists_mechanism', 'warning',
                'Unusual exists mechanism found',
                'The exists mechanism is rare and complex. Make sure it is intentional and correctly configured — it is often a sign of an overly complicated SPF setup.'
            );
            $warnings++;
        } else {
            $checks[] = self::result('exists_mechanism', 'ok',
                'No exists mechanism',
                'The exists mechanism is not present.'
            );
            $passed++;
        }

        // CHECK 9: +all
        if (!$has_plus_all) {
            $checks[] = self::result('plus_all', 'ok',
                'No +all detected',
                '+all would authorise every server in the world to send email as your domain. Not present — good.'
            );
            $passed++;
        }

        $status = $errors > 0 ? 'error' : ($warnings > 0 ? 'warning' : 'ok');

        $base['status']   = $status;
        $base['checks']   = $checks;
        $base['passed']   = $passed;
        $base['warnings'] = $warnings;
        $base['errors']   = $errors;

        return $base;
    }

    /**
     * Quick check used by the Email Monitor scanner.
     */
    public static function check($domain) {
        $r = self::analyze($domain);
        return array(
            'spf_record'  => $r['record'],
            'spf_status'  => $r['status'] === 'missing' ? 'missing' : ($r['status'] === 'ok' ? 'ok' : 'invalid'),
            'spf_warning' => $r['status'] !== 'ok',
        );
    }

    private static function extract_domain($input) {
        $input = trim(strtolower($input));
        if (strpos($input, '@') !== false) {
            $parts = explode('@', $input);
            return trim($parts[1]);
        }
        return $input;
    }

    private static function result($id, $status, $title, $description) {
        return array(
            'id'          => $id,
            'status'      => $status,
            'title'       => $title,
            'description' => $description,
        );
    }
}
