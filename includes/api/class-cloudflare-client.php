<?php
/**
 * Cloudflare API client
 *
 * @package BlockLoginsCF\Api
 */

namespace BlockLoginsCF\Api;

use BlockLoginsCF\Utils\Logger;

/**
 * Handles communication with Cloudflare API
 */
class CloudflareClient {

    /**
     * API base URL
     */
    const API_BASE = 'https://api.cloudflare.com/client/v4';

    /**
     * API credentials
     *
     * @var array
     */
    private $credentials;

    /**
     * Constructor
     *
     * @param array $credentials API credentials (email, api_key, zone_id)
     */
    public function __construct($credentials) {
        $this->credentials = $credentials;
    }

    /**
     * Validate API credentials
     *
     * @return bool True if credentials are valid
     */
    public function validate_credentials() {
        if (empty($this->credentials['api_key'])) {
            return false;
        }

        $url = self::API_BASE . '/user/tokens/verify';
        $response = wp_remote_get($url, [
            'headers' => [
                'Authorization' => 'Bearer ' . $this->credentials['api_key'],
                'Content-Type' => 'application/json',
            ],
            'timeout' => 10,
        ]);

        return $this->validate_api_response($response, 'token_verify');
    }

    /**
     * Block an IP address via Cloudflare firewall
     *
     * @param string $ip IP address to block
     * @return bool True if successful
     */
    public function block_ip($ip) {
        if (!$this->has_valid_credentials()) {
            Logger::error("Missing Cloudflare credentials for IP block", ['ip' => $ip]);
            return false;
        }

        $url = self::API_BASE . '/zones/' . $this->credentials['zone_id'] . '/firewall/access_rules/rules';

        $data = [
            'mode'          => 'block',
            'configuration' => [
                'target' => 'ip',
                'value'  => $ip
            ],
            'notes' => 'Blocked by Block Logins CF Plugin - IP: ' . $ip . ' at ' . current_time('mysql')
        ];

        $response = wp_remote_post($url, [
            'headers' => [
                'X-Auth-Email' => $this->credentials['email'],
                'X-Auth-Key'   => $this->credentials['api_key'],
                'Content-Type' => 'application/json',
            ],
            'body'    => wp_json_encode($data),
            'timeout' => 15,
        ]);

        if ($this->validate_api_response($response, 'block_ip')) {
            Logger::info("Successfully blocked IP via Cloudflare", ['ip' => $ip]);
            return true;
        }

        Logger::error("Failed to block IP via Cloudflare", [
            'ip' => $ip,
            'response' => wp_remote_retrieve_body($response)
        ]);
        return false;
    }

    /**
     * Block a subnet via Cloudflare firewall
     *
     * @param string $subnet Subnet in CIDR notation
     * @return bool True if successful
     */
    public function block_subnet($subnet) {
        if (!$this->has_valid_credentials()) {
            Logger::error("Missing Cloudflare credentials for subnet block", ['subnet' => $subnet]);
            return false;
        }

        $url = self::API_BASE . '/zones/' . $this->credentials['zone_id'] . '/firewall/access_rules/rules';

        $data = [
            'mode'          => 'block',
            'configuration' => [
                'target' => 'ip_range',
                'value'  => $subnet
            ],
            'notes' => 'Blocked by Block Logins CF Plugin - Subnet: ' . $subnet . ' at ' . current_time('mysql')
        ];

        $response = wp_remote_post($url, [
            'headers' => [
                'X-Auth-Email' => $this->credentials['email'],
                'X-Auth-Key'   => $this->credentials['api_key'],
                'Content-Type' => 'application/json',
            ],
            'body'    => wp_json_encode($data),
            'timeout' => 15,
        ]);

        if ($this->validate_api_response($response, 'block_subnet')) {
            Logger::info("Successfully blocked subnet via Cloudflare", ['subnet' => $subnet]);
            return true;
        }

        Logger::error("Failed to block subnet via Cloudflare", [
            'subnet' => $subnet,
            'response' => wp_remote_retrieve_body($response)
        ]);
        return false;
    }

    /**
     * Validate API response
     *
     * @param mixed  $response WordPress HTTP API response
     * @param string $context  Context for logging
     * @return mixed Parsed response data or false on failure
     */
    public function validate_api_response($response, $context = '') {
        if (is_wp_error($response)) {
            Logger::error("API request failed", [
                'context' => $context,
                'error'   => $response->get_error_message()
            ]);
            return false;
        }

        $response_code = wp_remote_retrieve_response_code($response);
        if ($response_code !== 200) {
            Logger::error("API request returned non-200 status", [
                'context' => $context,
                'status'  => $response_code,
                'body'    => wp_remote_retrieve_body($response)
            ]);
            return false;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            Logger::error("API response contains invalid JSON", [
                'context' => $context,
                'error'   => json_last_error_msg(),
                'body'    => substr($body, 0, 200)
            ]);
            return false;
        }

        if (empty($data['success']) || $data['success'] === 'false' || $data['success'] === false) {
            $error_msg = isset($data['errors']) ? wp_json_encode($data['errors']) : 'Unknown error';
            Logger::error("API request unsuccessful", [
                'context' => $context,
                'errors'  => $error_msg
            ]);
            return false;
        }

        return $data;
    }

    /**
     * Check if we have valid credentials
     *
     * @return bool True if credentials are present
     */
    private function has_valid_credentials() {
        return !empty($this->credentials['email']) &&
               !empty($this->credentials['api_key']) &&
               !empty($this->credentials['zone_id']);
    }

    /**
     * Create a new CloudflareClient instance from plugin settings
     *
     * @return self|false CloudflareClient instance or false if no credentials
     */
    public static function from_settings() {
        $settings = get_option('cfblocklogins_settings', []);

        // Decrypt credentials if they exist
        if (class_exists('BlockLoginsCF\Security\Encryption')) {
            $settings = \BlockLoginsCF\Security\Encryption::decrypt_api_credentials($settings);
        }

        if (empty($settings['email']) || empty($settings['api_key']) || empty($settings['zone_id'])) {
            return false;
        }

        return new self([
            'email'   => $settings['email'],
            'api_key' => $settings['api_key'],
            'zone_id' => $settings['zone_id']
        ]);
    }
}