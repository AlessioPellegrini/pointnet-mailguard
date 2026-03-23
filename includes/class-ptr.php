<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_PTR
 *
 * Checks the PTR (reverse DNS) record for an IPv4 address.
 * A missing PTR is a warning — not a blacklist issue — but can cause
 * email delivery problems with receiving servers that require a valid PTR.
 *
 * Usage:
 *   $result = PN_Mailguard_PTR::check('1.2.3.4');
 *
 * Returns array:
 *   [
 *     'ptr'         => 'mail.example.com',  // or 'PTR_ERROR' if lookup failed
 *     'ptr_warning' => true|false            // true = PTR missing or not configured
 *   ]
 */
class PN_Mailguard_PTR {

    /**
     * Perform a reverse DNS (PTR) lookup on the given IPv4 address.
     *
     * @param string $ip
     * @return array
     */
    public static function check($ip) {
        $ptr = gethostbyaddr($ip);

        // gethostbyaddr() returns false on failure, or the IP itself if no PTR record exists
        $ptr_warning = ($ptr === false || $ptr === $ip);

        return array(
            'ptr'         => ($ptr === false) ? 'PTR_ERROR' : $ptr,
            'ptr_warning' => $ptr_warning,
        );
    }
}
