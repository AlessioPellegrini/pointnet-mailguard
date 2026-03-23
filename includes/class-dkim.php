<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_DKIM
 *
 * DKIM record analyser.
 * Auto-detects common selectors, falls back to manual input.
 * Checks syntax, algorithm, key presence, key length and test mode.
 *
 * Usage:
 *   $result = PN_Mailguard_DKIM::analyze('example.com', 'google');
 *   $found  = PN_Mailguard_DKIM::autodetect('example.com');
 */
class PN_Mailguard_DKIM {

    /**
     * Common selectors to try during auto-detection.
     */
    /**
     * Public email providers that do not expose DKIM records in public DNS.
     */
    private static $public_providers = array(
        'gmail.com', 'googlemail.com',
        'outlook.com', 'hotmail.com', 'hotmail.it', 'live.com', 'live.it', 'msn.com',
        'yahoo.com', 'yahoo.it', 'yahoo.co.uk', 'yahoo.fr', 'yahoo.de',
        'icloud.com', 'me.com', 'mac.com',
        'protonmail.com', 'proton.me',
        'libero.it', 'virgilio.it', 'tin.it', 'alice.it',
        'tiscali.it', 'fastwebnet.it',
        'aol.com',
    );

    /**
     * Check if a domain is a public email provider.
     *
     * @param string $domain
     * @return bool
     */
    public static function is_public_provider($domain) {
        return in_array(strtolower($domain), self::$public_providers, true);
    }

    private static $common_selectors = array(
        'google', 'google1', 'google2',
        'selector1', 'selector2',
        'k1', 'k2', 'k3',
        's1', 's2',
        'mail', 'mail1', 'mail2',
        'default', 'dkim', 'dkim1',
        'smtp', 'email', 'mailing',
        'mandrill', 'sendgrid',
        'mailgun', 'mg',
        'amazonses', 'ses',
        'pm', 'postmark',
        'brevo', 'sendinblue',
        'zoho',
    );

    /**
     * Try to auto-detect a working DKIM selector for the given domain.
     *
     * @param string $domain
     * @return array  ['selector' => '...', 'record' => '...'] or ['selector' => '', 'record' => '']
     */
    public static function autodetect($domain) {
        foreach (self::$common_selectors as $selector) {
            $host    = $selector . '._domainkey.' . $domain;
            $records = @dns_get_record($host, DNS_TXT);
            if (!empty($records)) {
                foreach ($records as $rec) {
                    if (!empty($rec['txt']) && stripos($rec['txt'], 'v=DKIM1') !== false) {
                        return array(
                            'selector' => $selector,
                            'record'   => trim($rec['txt']),
                        );
                    }
                }
            }
        }
        return array('selector' => '', 'record' => '');
    }

    /**
     * Analyze a DKIM record for the given domain and selector.
     *
     * @param string $domain
     * @param string $selector
     * @return array
     */
    public static function analyze($domain, $selector) {
        $base = array(
            'domain'   => $domain,
            'selector' => $selector,
            'record'   => '',
            'status'   => 'missing',
            'checks'   => array(),
            'passed'   => 0,
            'warnings' => 0,
            'errors'   => 0,
            'error'    => '',
        );

        if (empty($domain) || empty($selector)) {
            $base['error'] = 'Domain and selector are required.';
            return $base;
        }

        $host    = $selector . '._domainkey.' . $domain;
        $records = @dns_get_record($host, DNS_TXT);

        $checks  = array();
        $passed  = $warnings = $errors = 0;

        // CHECK 1: Record present
        if (empty($records)) {
            $checks[] = self::result('record_present', 'error',
                'No DKIM record found for selector ' . esc_html($selector),
                'No TXT record was found on ' . esc_html($host) . '. Check that the selector is correct and that the DKIM record has been published in your DNS.'
            );
            $errors++;
            $base['checks'] = $checks;
            $base['errors'] = $errors;
            return $base;
        }

        // Find valid DKIM record
        $record = '';
        foreach ($records as $rec) {
            if (!empty($rec['txt'])) {
                $txt = trim($rec['txt']);
                if (stripos($txt, 'v=DKIM1') !== false || stripos($txt, 'p=') !== false) {
                    $record = $txt;
                    break;
                }
            }
        }

        if (empty($record)) {
            $checks[] = self::result('record_present', 'error',
                'TXT record found but not a valid DKIM record',
                'A TXT record exists on ' . esc_html($host) . ' but it does not appear to be a valid DKIM record. It should contain v=DKIM1 and a p= tag.'
            );
            $errors++;
            $base['checks'] = $checks;
            $base['errors'] = $errors;
            return $base;
        }

        $checks[] = self::result('record_present', 'ok',
            'DKIM record found (selector: ' . esc_html($selector) . ')',
            'A valid DKIM TXT record was found on ' . esc_html($host) . '.'
        );
        $passed++;
        $base['record'] = $record;

        // Parse tags
        $tags = self::parse_tags($record);

        // CHECK 2: Version tag
        if (empty($tags['v']) || strtoupper($tags['v']) !== 'DKIM1') {
            $checks[] = self::result('version', 'warning',
                'Missing or unexpected version tag (v=)',
                'The v=DKIM1 tag is recommended as the first tag in a DKIM record. Some mail servers may reject records without it.'
            );
            $warnings++;
        } else {
            $checks[] = self::result('version', 'ok',
                'Version tag valid: v=DKIM1',
                'The record correctly identifies itself as a DKIM version 1 record.'
            );
            $passed++;
        }

        // CHECK 3: Key type
        $key_type = strtolower($tags['k'] ?? 'rsa');
        if ($key_type === 'rsa') {
            $checks[] = self::result('key_type', 'ok',
                'Key type: RSA',
                'RSA is the most widely supported DKIM key type and is compatible with all major mail servers.'
            );
            $passed++;
        } elseif ($key_type === 'ed25519') {
            $checks[] = self::result('key_type', 'ok',
                'Key type: Ed25519',
                'Ed25519 is a modern elliptic curve algorithm — more efficient than RSA and equally secure. Well supported by major providers.'
            );
            $passed++;
        } else {
            $checks[] = self::result('key_type', 'warning',
                'Unknown key type: k=' . esc_html($key_type),
                'The key type ' . esc_html($key_type) . ' is not a standard DKIM key type. Expected rsa or ed25519.'
            );
            $warnings++;
        }

        // CHECK 4: Public key present and not revoked
        $pubkey = $tags['p'] ?? '';
        if (empty($pubkey)) {
            $checks[] = self::result('public_key', 'error',
                'Public key is empty — record is revoked',
                'An empty p= tag means this DKIM key has been intentionally revoked. Emails signed with the corresponding private key will fail DKIM verification. Publish a new key pair to restore DKIM signing.'
            );
            $errors++;
        } else {
            $checks[] = self::result('public_key', 'ok',
                'Public key present',
                'The p= tag contains a public key. The record is active and not revoked.'
            );
            $passed++;

            // CHECK 5: Key length (RSA only)
            if ($key_type === 'rsa') {
                $key_length = self::estimate_rsa_key_length($pubkey);
                if ($key_length > 0) {
                    if ($key_length < 1024) {
                        $checks[] = self::result('key_length', 'error',
                            'RSA key too short (' . $key_length . ' bits)',
                            'Keys shorter than 1024 bits are considered insecure and are rejected by many mail servers. Generate a new 2048-bit key pair immediately.'
                        );
                        $errors++;
                    } elseif ($key_length < 2048) {
                        $checks[] = self::result('key_length', 'warning',
                            'RSA key is ' . $key_length . ' bits (recommended: 2048)',
                            'A 1024-bit key is still accepted by most servers but is no longer considered best practice. Consider upgrading to a 2048-bit key for better long-term security.'
                        );
                        $warnings++;
                    } else {
                        $checks[] = self::result('key_length', 'ok',
                            'RSA key length ok (' . $key_length . ' bits)',
                            'A ' . $key_length . '-bit RSA key meets current security recommendations.'
                        );
                        $passed++;
                    }
                }
            }
        }

        // CHECK 6: Flags (t=)
        $flags = strtolower($tags['t'] ?? '');
        if (strpos($flags, 'y') !== false) {
            $checks[] = self::result('test_mode', 'warning',
                'Test mode active (t=y)',
                't=y means DKIM is in test mode — receivers should not treat DKIM failures differently from unsigned messages. Remove the t=y flag when you are confident DKIM is working correctly.'
            );
            $warnings++;
        } elseif (strpos($flags, 's') !== false) {
            $checks[] = self::result('test_mode', 'ok',
                'Strict flag set (t=s)',
                't=s means this key cannot be used by subdomains — the i= identity must match the d= domain exactly. This is the recommended setting for most configurations.'
            );
            $passed++;
        } else {
            $checks[] = self::result('test_mode', 'ok',
                'No test mode flag',
                'The t= flag is not set or does not include y — DKIM is active and not in test mode.'
            );
            $passed++;
        }

        // CHECK 7: Hash algorithms (h=)
        $hash = strtolower($tags['h'] ?? '');
        if (!empty($hash) && $hash === 'sha1') {
            $checks[] = self::result('hash_algorithm', 'warning',
                'Weak hash algorithm: h=sha1',
                'SHA-1 is deprecated for DKIM. If possible, configure your mail server to sign with SHA-256 instead.'
            );
            $warnings++;
        } elseif (!empty($hash)) {
            $checks[] = self::result('hash_algorithm', 'ok',
                'Hash algorithm: h=' . esc_html($hash),
                'The specified hash algorithm is acceptable.'
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
     * Estimate RSA key length in bits from a base64-encoded public key.
     * Works for most standard RSA keys without requiring OpenSSL extension.
     *
     * @param string $b64
     * @return int  Key length in bits, or 0 if estimation fails
     */
    private static function estimate_rsa_key_length($b64) {
        $decoded = base64_decode($b64, true);
        if ($decoded === false) return 0;
        // Rough estimation: RSA key bytes ≈ key length / 8
        // The DER-encoded public key contains the modulus as the largest element
        // Length of decoded bytes gives a good approximation
        $bytes = strlen($decoded);
        if ($bytes < 100)  return 512;
        if ($bytes < 200)  return 1024;
        if ($bytes < 400)  return 2048;
        if ($bytes < 600)  return 3072;
        return 4096;
    }

    /**
     * Parse DKIM record tags into key => value array.
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
    public static function extract_domain($input) {
        $input = trim(strtolower($input));
        if (strpos($input, '@') !== false) {
            $parts = explode('@', $input);
            return trim($parts[1]);
        }
        return $input;
    }

    /**
     * Build a single check result array.
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
