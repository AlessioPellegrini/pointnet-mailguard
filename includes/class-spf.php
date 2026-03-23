<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_SPF
 *
 * Checks the SPF (Sender Policy Framework) DNS record for a domain.
 * SPF defines which mail servers are authorised to send email on behalf of a domain.
 * A missing or misconfigured SPF record can cause email to be rejected or marked as spam.
 *
 * Usage:
 *   $result = PN_Mailguard_SPF::check('example.com');
 *
 * Returns array:
 *   [
 *     'spf_record'  => 'v=spf1 include:_spf.google.com ~all',  // raw record or empty string
 *     'spf_status'  => 'ok' | 'missing' | 'invalid',
 *     'spf_warning' => true|false   // true = missing or invalid
 *   ]
 */
class PN_Mailguard_SPF {

    /**
     * Check the SPF record for the given domain.
     *
     * @param string $domain
     * @return array
     */
    public static function check($domain) {
        $records = dns_get_record($domain, DNS_TXT);

        if (empty($records)) {
            return array(
                'spf_record'  => '',
                'spf_status'  => 'missing',
                'spf_warning' => true,
            );
        }

        // Look for a TXT record starting with "v=spf1"
        $spf_record = '';
        foreach ($records as $record) {
            if (!empty($record['txt']) && stripos($record['txt'], 'v=spf1') === 0) {
                $spf_record = $record['txt'];
                break;
            }
        }

        if (empty($spf_record)) {
            return array(
                'spf_record'  => '',
                'spf_status'  => 'missing',
                'spf_warning' => true,
            );
        }

        // Basic validation: must contain a valid mechanism and a qualifier at the end
        $valid = self::is_valid($spf_record);

        return array(
            'spf_record'  => $spf_record,
            'spf_status'  => $valid ? 'ok' : 'invalid',
            'spf_warning' => !$valid,
        );
    }

    /**
     * Basic SPF record validation.
     * Checks that the record starts with v=spf1 and ends with a recognised qualifier.
     *
     * @param string $record
     * @return bool
     */
    private static function is_valid($record) {
        // Must start with v=spf1
        if (stripos($record, 'v=spf1') !== 0) {
            return false;
        }

        // Must end with a recognised all-qualifier: -all, ~all, +all, ?all
        // or a redirect= mechanism
        if (preg_match('/[+\-~?]all\s*$/i', $record)) {
            return true;
        }
        if (stripos($record, 'redirect=') !== false) {
            return true;
        }

        return false;
    }
}
