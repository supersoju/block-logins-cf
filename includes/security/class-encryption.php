<?php
/**
 * Encryption utility class
 *
 * @package BlockLoginsCF\Security
 */

namespace BlockLoginsCF\Security;

use BlockLoginsCF\Utils\Logger;

/**
 * Handles encryption and decryption of sensitive data using WordPress security constants
 */
class Encryption {

    /**
     * Encrypt sensitive data using WordPress security keys
     *
     * @param string $data Data to encrypt
     * @return string Encrypted data or original data if encryption fails
     */
    public static function encrypt($data) {
        if (empty($data)) {
            return '';
        }

        // Use WordPress security constants as encryption key
        $key = self::get_encryption_key();
        if (!$key) {
            Logger::error("No encryption key available, storing data as plaintext");
            return $data; // Fallback to plaintext if no key available
        }

        try {
            // Use a simple but secure encryption method
            $iv = openssl_random_pseudo_bytes(16);
            $encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);

            if ($encrypted === false) {
                Logger::error("Encryption failed, storing data as plaintext");
                return $data; // Fallback to plaintext
            }

            // Prepend IV and base64 encode the result
            return base64_encode($iv . $encrypted);

        } catch (Exception $e) {
            Logger::error("Encryption error: " . $e->getMessage());
            return $data; // Fallback to plaintext
        }
    }

    /**
     * Decrypt sensitive data
     *
     * @param string $encrypted_data Encrypted data to decrypt
     * @return string Decrypted data or original data if decryption fails
     */
    public static function decrypt($encrypted_data) {
        if (empty($encrypted_data)) {
            return '';
        }

        $key = self::get_encryption_key();
        if (!$key) {
            // No encryption key available, assume data is plaintext
            return $encrypted_data;
        }

        try {
            // Check if this looks like encrypted data (base64 encoded)
            $decoded = base64_decode($encrypted_data, true);
            if ($decoded === false || strlen($decoded) < 16) {
                // Not encrypted data, return as-is (backward compatibility)
                return $encrypted_data;
            }

            // Extract IV and encrypted content
            $iv = substr($decoded, 0, 16);
            $encrypted = substr($decoded, 16);

            $decrypted = openssl_decrypt($encrypted, 'aes-256-cbc', $key, 0, $iv);

            if ($decrypted === false) {
                Logger::error("Decryption failed, assuming plaintext data");
                return $encrypted_data; // Fallback to original data
            }

            return $decrypted;

        } catch (Exception $e) {
            Logger::error("Decryption error: " . $e->getMessage());
            return $encrypted_data; // Fallback to original data
        }
    }

    /**
     * Encrypt API credentials array
     *
     * @param array $settings Settings array containing credentials
     * @return array Settings array with encrypted credentials
     */
    public static function encrypt_api_credentials($settings) {
        if (!self::is_available()) {
            return $settings; // Return as-is if encryption not available
        }

        $sensitive_fields = ['api_key', 'email', 'zone_id'];

        foreach ($sensitive_fields as $field) {
            if (isset($settings[$field]) && !empty($settings[$field])) {
                $settings[$field] = self::encrypt($settings[$field]);
            }
        }

        // Mark that these credentials are encrypted
        $settings['_credentials_encrypted'] = true;

        return $settings;
    }

    /**
     * Decrypt API credentials array
     *
     * @param array $settings Settings array containing encrypted credentials
     * @return array Settings array with decrypted credentials
     */
    public static function decrypt_api_credentials($settings) {
        if (empty($settings['_credentials_encrypted'])) {
            return $settings; // Not encrypted
        }

        if (!self::is_available()) {
            Logger::error("Cannot decrypt credentials - encryption not available");
            return $settings; // Return as-is, might fail but won't crash
        }

        $sensitive_fields = ['api_key', 'email', 'zone_id'];

        foreach ($sensitive_fields as $field) {
            if (isset($settings[$field]) && !empty($settings[$field])) {
                $settings[$field] = self::decrypt($settings[$field]);
            } else {
                $settings[$field] = ''; // Ensure field exists with empty value
            }
        }

        return $settings;
    }

    /**
     * Generate encryption key from WordPress security constants
     *
     * @return string|false Binary encryption key or false if unavailable
     */
    private static function get_encryption_key() {
        // Use WordPress security constants to generate a consistent key
        $key_components = [];

        if (defined('AUTH_KEY') && AUTH_KEY) {
            $key_components[] = AUTH_KEY;
        }
        if (defined('SECURE_AUTH_KEY') && SECURE_AUTH_KEY) {
            $key_components[] = SECURE_AUTH_KEY;
        }
        if (defined('LOGGED_IN_KEY') && LOGGED_IN_KEY) {
            $key_components[] = LOGGED_IN_KEY;
        }
        if (defined('NONCE_KEY') && NONCE_KEY) {
            $key_components[] = NONCE_KEY;
        }

        if (empty($key_components)) {
            return false; // No WordPress security keys available
        }

        // Create a consistent 32-byte key from the available keys
        $combined_key = implode('', $key_components);
        return hash('sha256', $combined_key, true);
    }

    /**
     * Check if encryption is available and working
     *
     * @return bool True if encryption is available
     */
    public static function is_available() {
        return function_exists('openssl_encrypt') &&
               function_exists('openssl_decrypt') &&
               self::get_encryption_key() !== false;
    }
}