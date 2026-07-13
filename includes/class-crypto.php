<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Crypto
 *
 * Encrypts and decrypts sensitive data (API keys) stored in wp_options.
 * Uses AES-256-CBC via OpenSSL, deriving the encryption key from
 * WordPress SECURE_AUTH_KEY (fallback to AUTH_KEY, then to a site-specific
 * salted hash if neither is set — though this should never happen).
 *
 * Encrypted values are stored as: base64( random_iv(16) + ciphertext )
 * which includes the IV for decryption and is safe for database storage.
 */
class PN_Mailguard_Crypto {

    const string METHOD = 'aes-256-cbc';

    /**
     * Derive a 256-bit (32-byte) encryption key from WordPress salts.
     *
     * @return string 32-byte binary key for openssl_encrypt/decrypt.
     */
    private static function key(): string {
        if (defined('SECURE_AUTH_KEY') && !empty(SECURE_AUTH_KEY)) {
            $salt = SECURE_AUTH_KEY;
        } elseif (defined('AUTH_KEY') && !empty(AUTH_KEY)) {
            $salt = AUTH_KEY;
        } else {
            // Extreme fallback — uses a site-specific hash so it's not trivially guessable.
            $salt = 'pn-mailguard-' . md5(ABSPATH . NONCE_SALT);
        }
        return hash('sha256', $salt, true); // 32 bytes
    }

    /**
     * Encrypt a plaintext string.
     *
     * @param string $plaintext The value to encrypt (e.g. Gemini API key).
     * @return string           base64-encoded IV + ciphertext, or empty string on failure.
     */
    public static function encrypt(string $plaintext): string {
        if (empty($plaintext)) {
            return '';
        }

        $iv_length = openssl_cipher_iv_length(self::METHOD);
        $iv        = openssl_random_pseudo_bytes($iv_length);

        if ($iv === false) {
            return '';
        }

        $ciphertext = openssl_encrypt($plaintext, self::METHOD, self::key(), OPENSSL_RAW_DATA, $iv);

        if ($ciphertext === false) {
            return '';
        }

        // Prepend IV so we can decrypt later, then base64 encode for safe DB storage
        return base64_encode($iv . $ciphertext);
    }

    /**
     * Decrypt an encrypted string previously produced by encrypt().
     *
     * @param string $encrypted The base64-encoded IV + ciphertext.
     * @return string           The plaintext value, or empty string on failure.
     */
    public static function decrypt(string $encrypted): string {
        if (empty($encrypted)) {
            return '';
        }

        $decoded = base64_decode($encrypted, true);

        if ($decoded === false) {
            return '';
        }

        $iv_length = openssl_cipher_iv_length(self::METHOD);

        if (strlen($decoded) <= $iv_length) {
            return '';
        }

        $iv         = substr($decoded, 0, $iv_length);
        $ciphertext = substr($decoded, $iv_length);

        $plaintext = openssl_decrypt($ciphertext, self::METHOD, self::key(), OPENSSL_RAW_DATA, $iv);

        return $plaintext !== false ? $plaintext : '';
    }

    /**
     * Check whether a stored value is already encrypted.
     *
     * The encrypted format is base64 with a minimum length of 24 bytes
     * (IV + tiny ciphertext). A typical plaintext API key is < 64 chars.
     *
     * @param string $value The value retrieved from the database.
     * @return bool
     */
    public static function is_encrypted(string $value): bool {
        if (empty($value)) {
            return false;
        }
        // Must be valid base64 and at least 32 chars (16 bytes IV + at least 16 bytes ciphertext)
        if (strlen($value) < 32 || !preg_match('/^[A-Za-z0-9+\/=]+$/', $value)) {
            return false;
        }
        $decoded = base64_decode($value, true);
        if ($decoded === false || strlen($decoded) < 32) {
            return false;
        }
        return true;
    }
}