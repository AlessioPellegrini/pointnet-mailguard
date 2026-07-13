<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_DNSBL
 *
 * Checks an IPv4 address against DNSBL blacklist zones.
 *
 * Usage:
 *   $result = PN_Mailguard_DNSBL::check('1.2.3.4');
 *
 * Returns array:
 *   [
 *     'results'  => [ 'SpamCop' => 'CLEAN', 'Barracuda' => 'LISTED', ... ],
 *     'is_alert' => true|false
 *   ]
 *
 * To add a new DNSBL zone in future: add it to the $zones array below.
 */
class PN_Mailguard_DNSBL {

    /**
     * DNSBL zones to check.
     * Key = DNS zone, Value = human-readable name shown in UI and logs.
     *
     * Selection criteria: widely used, reliable, low false positives, free for plugin use.
     * Spamhaus (zen.spamhaus.org) is intentionally excluded — their terms prohibit
     * use in distributed software without a paid Data Query Service (DQS) license.
     *
     * @var array<string, string>
     */
    private static array $zones = [
        'bl.spamcop.net'         => 'SpamCop',
        'b.barracudacentral.org' => 'Barracuda',
        'dnsbl.sorbs.net'        => 'SORBS',
        'dnsbl-1.uceprotect.net' => 'UCEProtect L1',
        'psbl.surriel.com'       => 'PSBL',
        'combined.abuse.ch'      => 'Abusix',
        'dnsbl.spfbl.net'        => 'SPFBL',
        'dnsbl.dronebl.org'      => 'DroneBL',
        'ubl.lashback.com'       => 'LashBack UBL',
    ];

    /**
     * Check an IPv4 address against all configured DNSBL zones.
     *
     * @param string $ip
     * @return array
     */
    public static function check($ip): array {
        $results  = [];
        $is_alert = false;

        foreach (self::$zones as $zone => $name) {
            $status          = self::query($ip, $zone);
            $results[$name]  = $status;
            if ($status === 'LISTED') {
                $is_alert = true;
            }
        }

        return [
            'results'  => $results,
            'is_alert' => $is_alert,
        ];
    }

    /**
     * Query a single DNSBL zone for the given IPv4 address.
     *
     * @param string $ip
     * @param string $zone
     * @return string 'LISTED' or 'CLEAN'
     */
    private static function query(string $ip, string $zone): string {
        $reversed = implode('.', array_reverse(explode('.', $ip)));
        $query    = $reversed . '.' . $zone;
        // gethostbyname() returns the input string unchanged if the host does not resolve (= CLEAN)
        return ($query !== gethostbyname($query)) ? 'LISTED' : 'CLEAN';
    }
}