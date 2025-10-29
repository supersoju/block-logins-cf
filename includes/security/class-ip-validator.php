<?php
/**
 * IP validation and utilities
 *
 * @package BlockLoginsCF\Security
 */

namespace BlockLoginsCF\Security;

/**
 * Handles IP address validation, sanitization, and trusted proxy detection
 */
class IpValidator {

    /**
     * Get user IP with enhanced security validation
     *
     * @return string User's IP address or '0.0.0.0' as safe fallback
     */
    public static function get_user_ip() {
        // Get the direct connection IP as fallback
        $remote_addr = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';

        // Define trusted proxy sources
        $trusted_proxies = self::get_trusted_proxies();

        // Check if we're behind a trusted proxy
        $is_trusted_proxy = self::is_trusted_proxy($remote_addr, $trusted_proxies);

        // If behind trusted proxy, validate and use proxy headers
        if ($is_trusted_proxy) {
            // Cloudflare CF-Connecting-IP header (highest priority for Cloudflare users)
            if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
                $ip = self::validate_and_sanitize(sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP'])));
                if ($ip) return $ip;
            }

            // X-Forwarded-For header (standard proxy header)
            if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                $forwarded_ips = explode(',', sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR'])));
                // Get the leftmost (original client) IP, skipping any trusted proxies
                foreach ($forwarded_ips as $forwarded_ip) {
                    $ip = self::validate_and_sanitize(trim($forwarded_ip));
                    if ($ip && !self::is_trusted_proxy($ip, $trusted_proxies)) {
                        return $ip;
                    }
                }
            }

            // X-Real-IP header (some proxy configurations)
            if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
                $ip = self::validate_and_sanitize(sanitize_text_field(wp_unslash($_SERVER['HTTP_X_REAL_IP'])));
                if ($ip) return $ip;
            }
        }

        // If not behind trusted proxy or no valid proxy headers, use direct connection IP
        $ip = self::validate_and_sanitize($remote_addr);
        return $ip ?: '0.0.0.0'; // Fallback to safe default
    }

    /**
     * Validate and sanitize IP address
     *
     * @param string $ip IP address to validate
     * @return string|false Valid IP address or false if invalid
     */
    public static function validate_and_sanitize($ip) {
        if (empty($ip)) {
            return false;
        }

        // Remove any whitespace
        $ip = trim($ip);

        // Basic format validation
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // Reject private/reserved IP ranges when not in trusted proxy scenario
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return $ip;
        }

        // Allow private IPs only if explicitly configured (for development/internal networks)
        $allow_private = self::allow_private_ips();
        if ($allow_private && filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }

        return false;
    }

    /**
     * Get subnet from IP address
     *
     * @param string $ip IP address
     * @return string|false Subnet in CIDR notation or false if invalid
     */
    public static function get_subnet($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        $ip_parts = explode('.', $ip);
        if (count($ip_parts) !== 4) {
            return false;
        }

        // Use /24 subnet (255.255.255.0)
        return $ip_parts[0] . '.' . $ip_parts[1] . '.' . $ip_parts[2] . '.0/24';
    }

    /**
     * Check if IP is in CIDR range
     *
     * @param string $ip IP address to check
     * @param string $range CIDR range or single IP
     * @return bool True if IP is in range
     */
    public static function ip_in_range($ip, $range) {
        if (strpos($range, '/') === false) {
            // Single IP comparison
            return $ip === $range;
        }

        list($subnet, $bits) = explode('/', $range);

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) &&
            filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // IPv4 CIDR check
            $ip_long = ip2long($ip);
            $subnet_long = ip2long($subnet);
            $mask = -1 << (32 - $bits);

            return ($ip_long & $mask) === ($subnet_long & $mask);
        }

        // IPv6 support could be added here in the future
        return false;
    }

    /**
     * Get list of trusted proxy IP ranges
     *
     * @return array Array of CIDR ranges
     */
    public static function get_trusted_proxies() {
        // Default Cloudflare IP ranges
        $cloudflare_ipv4 = [
            '173.245.48.0/20',
            '103.21.244.0/22',
            '103.22.200.0/22',
            '103.31.4.0/22',
            '141.101.64.0/18',
            '108.162.192.0/18',
            '190.93.240.0/20',
            '188.114.96.0/20',
            '197.234.240.0/22',
            '198.41.128.0/17',
            '162.158.0.0/15',
            '104.16.0.0/13',
            '104.24.0.0/14',
            '172.64.0.0/13',
            '131.0.72.0/22'
        ];

        // Get custom trusted proxies from settings
        $settings = get_option('cfblocklogins_settings', []);
        $custom_proxies = isset($settings['trusted_proxies']) ? $settings['trusted_proxies'] : [];

        return array_merge($cloudflare_ipv4, $custom_proxies);
    }

    /**
     * Check if IP is in trusted proxy ranges
     *
     * @param string $ip IP address to check
     * @param array  $trusted_ranges Array of CIDR ranges
     * @return bool True if IP is from trusted proxy
     */
    public static function is_trusted_proxy($ip, $trusted_ranges) {
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        foreach ($trusted_ranges as $range) {
            if (self::ip_in_range($ip, $range)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if private IPs should be allowed (for development environments)
     *
     * @return bool True if private IPs are allowed
     */
    private static function allow_private_ips() {
        $settings = get_option('cfblocklogins_settings', []);
        return isset($settings['allow_private_ips']) ? $settings['allow_private_ips'] : false;
    }
}