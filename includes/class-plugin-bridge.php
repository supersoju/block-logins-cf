<?php
/**
 * Bridge between old function-based code and new class-based architecture
 * This allows gradual migration while maintaining backward compatibility
 *
 * @package BlockLoginsCF
 */

namespace BlockLoginsCF;

use BlockLoginsCF\Utils\Logger;
use BlockLoginsCF\Security\Encryption;
use BlockLoginsCF\Security\IpValidator;
use BlockLoginsCF\Api\CloudflareClient;

/**
 * Plugin bridge for backward compatibility during refactoring
 */
class PluginBridge {

    /**
     * Initialize the plugin bridge
     * This replaces some global functions with class-based implementations
     */
    public static function init() {
        // Don't initialize during tests unless specifically requested
        if (defined('CF_PLUGIN_TESTING') && CF_PLUGIN_TESTING) {
            return;
        }

        // Set up autoloader if not already done
        self::setup_autoloader();
    }

    /**
     * Setup autoloader for the plugin classes
     */
    private static function setup_autoloader() {
        static $autoloader_registered = false;

        if (!$autoloader_registered) {
            require_once __DIR__ . '/class-autoloader.php';
            $autoloader = new Autoloader('BlockLoginsCF\\', __DIR__ . '/');
            $autoloader->register();
            $autoloader_registered = true;
        }
    }

    /**
     * Replacement for cf_log_error using new Logger class
     *
     * @param string $message Error message
     * @param array  $context Additional context
     */
    public static function log_error($message, $context = []) {
        Logger::error($message, $context);
    }

    /**
     * Replacement for cf_get_user_ip using new IpValidator class
     *
     * @return string User's IP address
     */
    public static function get_user_ip() {
        return IpValidator::get_user_ip();
    }

    /**
     * Replacement for cf_validate_and_sanitize_ip using new IpValidator class
     *
     * @param string $ip IP address to validate
     * @return string|false Valid IP or false
     */
    public static function validate_and_sanitize_ip($ip) {
        return IpValidator::validate_and_sanitize($ip);
    }

    /**
     * Replacement for cf_get_subnet using new IpValidator class
     *
     * @param string $ip IP address
     * @return string|false Subnet in CIDR notation
     */
    public static function get_subnet($ip) {
        return IpValidator::get_subnet($ip);
    }

    /**
     * Replacement for cf_ip_in_range using new IpValidator class
     *
     * @param string $ip IP address
     * @param string $range CIDR range
     * @return bool True if IP is in range
     */
    public static function ip_in_range($ip, $range) {
        return IpValidator::ip_in_range($ip, $range);
    }

    /**
     * Replacement for cf_encrypt_data using new Encryption class
     *
     * @param string $data Data to encrypt
     * @return string Encrypted data
     */
    public static function encrypt_data($data) {
        return Encryption::encrypt($data);
    }

    /**
     * Replacement for cf_decrypt_data using new Encryption class
     *
     * @param string $encrypted_data Encrypted data
     * @return string Decrypted data
     */
    public static function decrypt_data($encrypted_data) {
        return Encryption::decrypt($encrypted_data);
    }

    /**
     * Replacement for cf_encrypt_api_credentials using new Encryption class
     *
     * @param array $settings Settings array
     * @return array Settings with encrypted credentials
     */
    public static function encrypt_api_credentials($settings) {
        return Encryption::encrypt_api_credentials($settings);
    }

    /**
     * Replacement for cf_decrypt_api_credentials using new Encryption class
     *
     * @param array $settings Settings array
     * @return array Settings with decrypted credentials
     */
    public static function decrypt_api_credentials($settings) {
        return Encryption::decrypt_api_credentials($settings);
    }

    /**
     * Replacement for cf_get_api_credentials using new Encryption class
     *
     * @return array Decrypted API credentials
     */
    public static function get_api_credentials() {
        $settings = get_option('cfblocklogins_settings', []);
        return Encryption::decrypt_api_credentials($settings);
    }

    /**
     * Replacement for cf_is_encryption_available using new Encryption class
     *
     * @return bool True if encryption is available
     */
    public static function is_encryption_available() {
        return Encryption::is_available();
    }

    /**
     * Replacement for cf_validate_api_response using new CloudflareClient class
     *
     * @param mixed  $response HTTP response
     * @param string $context  Context for logging
     * @return mixed Parsed response or false
     */
    public static function validate_api_response($response, $context = '') {
        // Create a temporary client just for validation
        $client = new CloudflareClient([]);
        return $client->validate_api_response($response, $context);
    }

    /**
     * Enhanced block IP function using new CloudflareClient class
     *
     * @param string $ip IP address to block
     * @return bool True if successful
     */
    public static function block_ip_via_api($ip) {
        $client = CloudflareClient::from_settings();
        if (!$client) {
            Logger::error("Cannot create Cloudflare client - missing credentials", ['ip' => $ip]);
            return false;
        }

        return $client->block_ip($ip);
    }

    /**
     * Enhanced block subnet function using new CloudflareClient class
     *
     * @param string $subnet Subnet to block
     * @return bool True if successful
     */
    public static function block_subnet_via_api($subnet) {
        $client = CloudflareClient::from_settings();
        if (!$client) {
            Logger::error("Cannot create Cloudflare client - missing credentials", ['subnet' => $subnet]);
            return false;
        }

        return $client->block_subnet($subnet);
    }
}