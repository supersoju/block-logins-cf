<?php
/**
 * Plugin Name: Block Logins with Cloudflare
 * Plugin URI: https://github.com/supersoju/block-logins-cf
 * Description: Blocks failed login attempts directly through Cloudflare.
 * Version: 1.0
 * Author: supersoju
 * Author URI: https://supersoju.com
 * License: GNU General Public License v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: block-logins-cf
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Tags: security, cloudflare, login, block, firewall
 * Tested up to: 6.8
 */

if (!defined('ABSPATH')) {
	exit; // Exit if accessed directly
}

// Migration function to handle prefix change from cf_ to cfblocklogins_
function cfblocklogins_migrate_from_old_prefix() {
    // Check if migration has already been done
    if (get_option('cfblocklogins_migration_done')) {
        return;
    }

    // List of old options to migrate
    $old_options = [
        'cf_api_key' => 'cfblocklogins_api_key',
        'cf_email' => 'cfblocklogins_email',
        'cf_zone_id' => 'cfblocklogins_zone_id',
        'cf_settings' => 'cfblocklogins_settings',
    ];

    // Migrate each option if it exists
    foreach ($old_options as $old_key => $new_key) {
        $old_value = get_option($old_key);
        if ($old_value !== false) {
            // Copy to new option name
            update_option($new_key, $old_value);
            // Delete old option
            delete_option($old_key);
        }
    }

    // Mark migration as complete
    update_option('cfblocklogins_migration_done', '1');
}
add_action('plugins_loaded', 'cfblocklogins_migrate_from_old_prefix', 1);

// Helper function for API response validation and logging
function cfblocklogins_validate_api_response($response, $context = '') {
    if (is_wp_error($response)) {
        cfblocklogins_log_error("API request failed: " . $response->get_error_message(), ['context' => $context]);
        return false;
    }

    $response_code = wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);

    if ($response_code !== 200) {
        cfblocklogins_log_error("API returned non-200 status: $response_code", [
            'context' => $context,
            'response_body' => $body
        ]);
        return false;
    }

    $data = json_decode($body, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        cfblocklogins_log_error("API returned invalid JSON", [
            'context' => $context,
            'json_error' => json_last_error_msg(),
            'response_body' => substr($body, 0, 200)
        ]);
        return false;
    }

    if (empty($data['success']) || $data['success'] === 'false' || $data['success'] === false) {
        $error_msg = isset($data['errors']) ? json_encode($data['errors']) : 'Unknown error';
        cfblocklogins_log_error("API request unsuccessful", [
            'context' => $context,
            'errors' => $error_msg
        ]);
        return false;
    }

    return $data;
}

// Error logging function
function cfblocklogins_log_error($message, $context = []) {
    // Skip logging during tests unless specifically enabled
    if (defined('CF_PLUGIN_TESTING') && CF_PLUGIN_TESTING) {
        return;
    }

    if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
        $log_message = 'Block Logins CF: ' . $message;
        if (!empty($context)) {
            $log_message .= ' | Context: ' . json_encode($context);
        }
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Used only when WP_DEBUG_LOG is enabled
        error_log($log_message);
    }
}

// Hook into login failure
add_action('wp_login_failed', 'cfblocklogins_track_failed_logins');

function cfblocklogins_track_failed_logins($username) {
    $ip = cfblocklogins_get_user_ip();
    $subnet = cfblocklogins_get_subnet($ip);

    $settings = get_option('cfblocklogins_settings', []);
    $whitelist = isset($settings['whitelist']) ? $settings['whitelist'] : [];
    if (in_array($ip, $whitelist) || ($subnet && in_array($subnet, $whitelist))) {
        return; // Don't track whitelisted IPs or subnets
    }

    // Use atomic operations to prevent race conditions
    $result = cfblocklogins_increment_failed_attempts_atomic($ip, $settings);
    if (!$result) {
        cfblocklogins_log_error("Failed to increment attempts for IP due to race condition", ['ip' => $ip]);
        return;
    }

    $failed_attempts = $result['attempts'];
    $max_attempts = intval($settings['max_attempts'] ?? 3);

    // Track subnet attempts atomically if enabled
    $subnet_attempts = 0;
    if ($subnet && !empty($settings['enable_subnet_blocking'])) {
        $subnet_result = cfblocklogins_increment_failed_attempts_atomic($subnet, $settings, 'subnet');
        if ($subnet_result) {
            $subnet_attempts = $subnet_result['attempts'];
        }
    }

    // Check if IP should be blocked
    if ($failed_attempts >= $max_attempts) {
        cfblocklogins_block_ip($ip);
        cfblocklogins_log_error("IP blocked after reaching attempt threshold", [
            'ip' => $ip,
            'attempts' => $failed_attempts,
            'threshold' => $max_attempts
        ]);
    }

    // Check if subnet should be blocked
    if ($subnet && !empty($settings['enable_subnet_blocking'])) {
        $subnet_threshold = intval($settings['subnet_threshold'] ?? 2);
        if ($subnet_attempts >= $subnet_threshold) {
            cfblocklogins_block_subnet($subnet);
            cfblocklogins_log_error("Subnet blocked after reaching attempt threshold", [
                'subnet' => $subnet,
                'attempts' => $subnet_attempts,
                'threshold' => $subnet_threshold
            ]);
        }
    }
}

// Atomically increment failed login attempts with race condition protection
function cfblocklogins_increment_failed_attempts_atomic($target, $settings, $type = 'ip') {
    $lock_key = "cfblocklogins_lock_{$type}_{$target}";
    $attempt_key = "cfblocklogins_failed_login" . ($type === 'subnet' ? '_subnet' : '') . "_{$target}";
    $block_duration = intval($settings['block_duration'] ?? 60);
    $lock_timeout = 5; // 5 second lock timeout

    // Try to acquire lock with timeout
    $lock_acquired = cfblocklogins_acquire_lock($lock_key, $lock_timeout);
    if (!$lock_acquired) {
        cfblocklogins_log_error("Failed to acquire lock for failed login tracking", [
            'target' => $target,
            'type' => $type,
            'lock_key' => $lock_key
        ]);
        return false;
    }

    try {
        // Get current attempts within the lock
        $current_attempts = get_transient($attempt_key) ?: 0;
        $new_attempts = $current_attempts + 1;

        // Set new attempt count
        set_transient($attempt_key, $new_attempts, $block_duration);

        // Release lock
        cfblocklogins_release_lock($lock_key);

        return [
            'attempts' => $new_attempts,
            'was_incremented' => true
        ];

    } catch (Exception $e) {
        // Ensure lock is released even if there's an error
        cfblocklogins_release_lock($lock_key);
        cfblocklogins_log_error("Error during atomic increment", [
            'target' => $target,
            'type' => $type,
            'error' => $e->getMessage()
        ]);
        return false;
    }
}

// Acquire a distributed lock using WordPress cache
function cfblocklogins_acquire_lock($lock_key, $timeout = 5) {
    $start_time = time();
    $lock_value = uniqid(php_uname('n'), true); // Unique lock identifier
    $lock_expiry = 30; // Lock expires after 30 seconds as safety

    while (time() - $start_time < $timeout) {
        // Try to acquire lock atomically
        if (wp_cache_add($lock_key, $lock_value, 'block-logins-cf-locks', $lock_expiry)) {
            // Successfully acquired lock
            return $lock_value;
        }

        // Check if existing lock has expired (safety mechanism)
        $existing_lock = wp_cache_get($lock_key, 'block-logins-cf-locks');
        if ($existing_lock === false) {
            // Lock doesn't exist, try again
            continue;
        }

        // Wait a bit before trying again
        usleep(100000); // 100ms
    }

    return false;
}

// Release a distributed lock
function cfblocklogins_release_lock($lock_key) {
    return wp_cache_delete($lock_key, 'block-logins-cf-locks');
}

// Enhanced version of login attempt checking that's race-condition safe
function cfblocklogins_check_if_blocked($ip) {
    $block_key = "cfblocklogins_block_login_{$ip}";

    // Check if IP is already blocked
    if (get_transient($block_key)) {
        return true;
    }

    // Check current failed attempts without modifying them
    $failed_attempts = get_transient("cfblocklogins_failed_login_{$ip}") ?: 0;
    $settings = get_option('cfblocklogins_settings', []);
    $max_attempts = intval($settings['max_attempts'] ?? 3);

    return $failed_attempts >= $max_attempts;
}

function cfblocklogins_block_ip($ip) {
    $settings = get_option('cfblocklogins_settings', []);
    $auto_unblock_hours = intval($settings['auto_unblock_hours'] ?? 24);
    $auto_unblock_seconds = $auto_unblock_hours * 3600;

    set_transient("cfblocklogins_block_login_$ip", '1', $auto_unblock_seconds);
    set_transient("cfblocklogins_block_login_time_$ip", time(), $auto_unblock_seconds);

    // After blocking an IP, clear the cached list of blocked IP transients
    wp_cache_delete('cfblocklogins_blocked_ip_transients', 'block-logins-cf');
    wp_cache_delete('cfblocklogins_blocked_ip_transients_cron', 'block-logins-cf');

    // Get decrypted API credentials
    $credentials = cfblocklogins_get_api_credentials();
    $email   = $credentials['email'] ?? '';
    $api_key = $credentials['api_key'] ?? '';
    $zone_id = $credentials['zone_id'] ?? '';

    if (!$email || !$api_key || !$zone_id) {
        cfblocklogins_log_error("Missing Cloudflare credentials for IP block", ['ip' => $ip]);
        return false;
    }

    $url = "https://api.cloudflare.com/client/v4/zones/$zone_id/firewall/access_rules/rules";
    $data = [
        'mode' => 'block',
        'configuration' => ['target' => 'ip', 'value' => $ip],
        'notes' => 'Blocked due to failed logins - Auto-generated by Block Logins CF plugin'
    ];

    $response = wp_remote_post($url, [
        'headers' => [
            'X-Auth-Email' => $email,
            'X-Auth-Key' => $api_key,
            'Content-Type' => 'application/json',
        ],
        'body' => json_encode($data),
        'method' => 'POST',
        'timeout' => 15,
    ]);

    $api_result = cfblocklogins_validate_api_response($response, "block_ip:$ip");
    if ($api_result === false) {
        cfblocklogins_log_error("Failed to block IP via Cloudflare API", ['ip' => $ip]);
        return false;
    }

    cfblocklogins_log_error("Successfully blocked IP via Cloudflare", ['ip' => $ip, 'rule_id' => $api_result['result']['id'] ?? 'unknown']);
    return true;
}

// Block a subnet via Cloudflare
function cfblocklogins_block_subnet($subnet) {
    $settings = get_option('cfblocklogins_settings', []);
    $auto_unblock_hours = intval($settings['auto_unblock_hours'] ?? 24);
    $auto_unblock_seconds = $auto_unblock_hours * 3600;

    set_transient("cfblocklogins_block_login_$subnet", '1', $auto_unblock_seconds);
    set_transient("cfblocklogins_block_login_time_$subnet", time(), $auto_unblock_seconds);

    // After blocking a subnet, clear the cached list of blocked IP transients
    wp_cache_delete('cfblocklogins_blocked_ip_transients', 'block-logins-cf');
    wp_cache_delete('cfblocklogins_blocked_ip_transients_cron', 'block-logins-cf');

    // Get decrypted API credentials
    $credentials = cfblocklogins_get_api_credentials();
    $email   = $credentials['email'] ?? '';
    $api_key = $credentials['api_key'] ?? '';
    $zone_id = $credentials['zone_id'] ?? '';

    if (!$email || !$api_key || !$zone_id) {
        cfblocklogins_log_error("Missing Cloudflare credentials for subnet block", ['subnet' => $subnet]);
        return false;
    }

    $url = "https://api.cloudflare.com/client/v4/zones/$zone_id/firewall/access_rules/rules";
    $data = [
        'mode' => 'block',
        'configuration' => ['target' => 'ip_range', 'value' => $subnet],
        'notes' => 'Blocked subnet due to failed logins - Auto-generated by Block Logins CF plugin'
    ];

    $response = wp_remote_post($url, [
        'headers' => [
            'X-Auth-Email' => $email,
            'X-Auth-Key' => $api_key,
            'Content-Type' => 'application/json',
        ],
        'body' => json_encode($data),
        'method' => 'POST',
        'timeout' => 15,
    ]);

    $api_result = cfblocklogins_validate_api_response($response, "block_subnet:$subnet");
    if ($api_result === false) {
        cfblocklogins_log_error("Failed to block subnet via Cloudflare API", ['subnet' => $subnet]);
        return false;
    }

    cfblocklogins_log_error("Successfully blocked subnet via Cloudflare", ['subnet' => $subnet, 'rule_id' => $api_result['result']['id'] ?? 'unknown']);
    return true;
}

// Add top-level menu and submenus
add_action('admin_menu', function() {
    // Top-level menu
    add_menu_page(
        'Block Logins CF', // Page title
        'Block Logins CF', // Menu title
        'manage_options',  // Capability
        'block-logins-cf', // Menu slug
        'cfblocklogins_settings_page', // Callback function
        'dashicons-shield-alt', // Icon
        25 // Position
    );

    // Settings page (redundant, but keeps menu highlight correct)
    add_submenu_page(
        'block-logins-cf', // Parent slug
        'Settings',
        'Settings',
        'manage_options',
        'block-logins-cf',
        'cfblocklogins_settings_page'
    );

    // Blocked IPs page
    add_submenu_page(
        'block-logins-cf', // Parent slug
        'Blocked IPs',
        'Blocked IPs',
        'manage_options',
        'block-logins-cf-blocked',
        'cfblocklogins_blocked_page'
    );
});

// Register settings with validation
add_action('admin_init', function() {
    register_setting(
        'cfblocklogins_settings_group',
        'cfblocklogins_settings',
        [
            'sanitize_callback' => 'cfblocklogins_settings_validate'
        ]
    );
});

// Validation callback
function cfblocklogins_settings_validate($input) {
    $current = get_option('cfblocklogins_settings', []);

    // Always sanitize all fields
    $input['email'] = sanitize_email($input['email'] ?? '');
    $input['api_key'] = sanitize_text_field($input['api_key'] ?? '');
    $input['zone_id'] = sanitize_text_field($input['zone_id'] ?? '');
    $input['max_attempts'] = intval($input['max_attempts'] ?? ($current['max_attempts'] ?? 3));
    $input['block_duration'] = intval($input['block_duration'] ?? ($current['block_duration'] ?? 60));
    $input['auto_unblock_hours'] = intval($input['auto_unblock_hours'] ?? ($current['auto_unblock_hours'] ?? 24));
    $input['subnet_threshold'] = intval($input['subnet_threshold'] ?? ($current['subnet_threshold'] ?? 2));
    $input['enable_subnet_blocking'] = !empty($input['enable_subnet_blocking']) ? 1 : 0;
    if ($input['enable_subnet_blocking']) {
        $input['subnet_threshold'] = intval($input['subnet_threshold'] ?? ($current['subnet_threshold'] ?? 2));
    } else {
        $input['subnet_threshold'] = '';
    }

    if (!isset($input['whitelist'])) {
        $input['whitelist'] = isset($current['whitelist']) ? $current['whitelist'] : [];
    }

    $decrypted_current = cfblocklogins_decrypt_api_credentials($current);
    $has_credentials = !empty($decrypted_current['email']) && !empty($decrypted_current['api_key']) && !empty($decrypted_current['zone_id']);
    $is_entering_credentials = !empty($input['email']) && !empty($input['api_key']) && !empty($input['zone_id']);

    // If credentials are missing or being entered, require and validate them
    if (!$has_credentials || $is_entering_credentials) {
        // All credential fields must be present
        if (empty($input['email']) || empty($input['api_key']) || empty($input['zone_id'])) {
            add_settings_error(
                'cfblocklogins_settings',
                'cfblocklogins_settings_missing',
                'Please enter all Cloudflare credential fields.',
                'error'
            );
            return $current;
        }
        // Validate API token
        $url = "https://api.cloudflare.com/client/v4/user/tokens/verify";
        $response = wp_remote_get($url, [
            'headers' => [
                'Authorization' => 'Bearer ' . $input['api_key'],
                'Content-Type' => 'application/json',
            ],
            'timeout' => 10,
        ]);

        $api_result = cfblocklogins_validate_api_response($response, 'token_verify');
        if ($api_result === false) {
            $body = wp_remote_retrieve_body($response);
            $debug = is_wp_error($response) ? $response->get_error_message() : substr($body, 0, 200);
            add_settings_error(
                'cfblocklogins_settings',
                'cfblocklogins_settings_invalid',
                'Cloudflare API Token is invalid. Error: ' . esc_html($debug),
                'error'
            );
            return $current;
        }
        // Save credentials (encrypted) and keep other settings from current
        $new_settings = array_merge($current, [
            'email' => $input['email'],
            'api_key' => $input['api_key'],
            'zone_id' => $input['zone_id'],
            'whitelist' => $input['whitelist'],
        ]);

        // Encrypt sensitive credentials before saving
        return cfblocklogins_encrypt_api_credentials($new_settings);
    }

    // If credentials exist and are not being changed, only update main settings
    return array_merge($current, [
        'max_attempts' => $input['max_attempts'],
        'block_duration' => $input['block_duration'],
        'auto_unblock_hours' => $input['auto_unblock_hours'],
        'enable_subnet_blocking' => $input['enable_subnet_blocking'],
        'subnet_threshold' => $input['enable_subnet_blocking'] ? $input['subnet_threshold'] : '',
        'enable_xmlrpc_blocking' => !empty($input['enable_xmlrpc_blocking']) ? 1 : 0,
        'xmlrpc_max_attempts' => intval($input['xmlrpc_max_attempts'] ?? ($current['xmlrpc_max_attempts'] ?? 3)),
        'xmlrpc_block_duration' => intval($input['xmlrpc_block_duration'] ?? ($current['xmlrpc_block_duration'] ?? 300)),
        'whitelist' => $input['whitelist'], // preserve whitelist
    ]);
}

// Enqueue admin scripts
function cfblocklogins_enqueue_admin_scripts($hook) {
    if ($hook !== 'toplevel_page_block-logins-cf') {
        return;
    }

    wp_enqueue_script('jquery');

    $inline_script = "
    document.addEventListener('DOMContentLoaded', function() {
        // Handle subnet blocking settings visibility
        var subnetCheckbox = document.querySelector('input[name=\"cfblocklogins_settings[enable_subnet_blocking]\"]');
        var subnetRow = document.getElementById('subnet-threshold-row');
        if (subnetCheckbox && subnetRow) {
            subnetCheckbox.addEventListener('change', function() {
                subnetRow.style.display = this.checked ? '' : 'none';
            });
        }

        // Handle XML-RPC settings visibility
        var xmlrpcCheckbox = document.querySelector('input[name=\"cfblocklogins_settings[enable_xmlrpc_blocking]\"]');
        var xmlrpcRow = document.getElementById('xmlrpc-settings-row');
        if (xmlrpcCheckbox && xmlrpcRow) {
            xmlrpcCheckbox.addEventListener('change', function() {
                xmlrpcRow.style.display = this.checked ? '' : 'none';
            });
        }
    });
    ";

    wp_add_inline_script('jquery', $inline_script);
}
add_action('admin_enqueue_scripts', 'cfblocklogins_enqueue_admin_scripts');

// Settings page HTML
function cfblocklogins_settings_page() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'block-logins-cf'));
    }

    // Handle clear credentials
    if (isset($_POST['cfblocklogins_clear_credentials']) && check_admin_referer('cfblocklogins_clear_credentials_action')) {
        $settings = get_option('cfblocklogins_settings', []);
        unset($settings['email'], $settings['api_key'], $settings['zone_id']);
        update_option('cfblocklogins_settings', $settings);
        echo '<div class="updated"><p>' . esc_html__('Cloudflare credentials cleared. Please re-enter them below.', 'block-logins-cf') . '</p></div>';
    }

    $options = get_option('cfblocklogins_settings', []);
    // Decrypt credentials for display and validation
    $decrypted_options = cfblocklogins_decrypt_api_credentials($options);
    $has_credentials = !empty($decrypted_options['email']) && !empty($decrypted_options['api_key']) && !empty($decrypted_options['zone_id']);

    // If credentials are missing, show only credential fields
    if (!$has_credentials) {
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('Block Logins with Cloudflare', 'block-logins-cf'); ?></h1>
            <?php settings_errors('cfblocklogins_settings'); ?>
            <form method="post" action="options.php">
                <?php settings_fields('cfblocklogins_settings_group'); ?>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row"><?php esc_html_e('Cloudflare Email', 'block-logins-cf'); ?></th>
                        <td><input type="email" name="cfblocklogins_settings[email]" value="<?php echo esc_attr($decrypted_options['email'] ?? ''); ?>" required /></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row"><?php esc_html_e('Cloudflare API Key', 'block-logins-cf'); ?></th>
                        <td><input type="text" name="cfblocklogins_settings[api_key]" value="<?php echo esc_attr($decrypted_options['api_key'] ?? ''); ?>" required /></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row"><?php esc_html_e('Cloudflare Zone ID', 'block-logins-cf'); ?></th>
                        <td><input type="text" name="cfblocklogins_settings[zone_id]" value="<?php echo esc_attr($decrypted_options['zone_id'] ?? ''); ?>" required /></td>
                    </tr>
                </table>
                <?php submit_button(esc_html__('Save Cloudflare Credentials', 'block-logins-cf')); ?>
            </form>
        </div>
        <?php
        return;
    }

    // If credentials exist, show main settings and credential status
    ?>
    <div class="wrap">
        <h1><?php esc_html_e('Block Logins with Cloudflare', 'block-logins-cf'); ?></h1>
        <?php settings_errors('cfblocklogins_settings'); ?>
        <form method="post" action="options.php">
            <?php settings_fields('cfblocklogins_settings_group'); ?>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row" colspan="2"><strong><?php esc_html_e('Block after...', 'block-logins-cf'); ?></strong></th>
                </tr>
                <tr valign="top">
                    <td colspan="2">
                        <input type="number" min="1" style="width:70px;" name="cfblocklogins_settings[max_attempts]" value="<?php echo esc_attr($options['max_attempts'] ?? 3); ?>" required />
                        <?php esc_html_e('failed attempts in', 'block-logins-cf'); ?>
                        <input type="number" min="1" style="width:90px;" name="cfblocklogins_settings[block_duration]" value="<?php echo esc_attr($options['block_duration'] ?? 60); ?>" required />
                        <?php esc_html_e('seconds', 'block-logins-cf'); ?>
                    </td>
                </tr>
                <tr valign="top">
                    <th scope="row"><?php esc_html_e('Enable Subnet Blocking', 'block-logins-cf'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="cfblocklogins_settings[enable_subnet_blocking]" value="1" <?php checked(!empty($options['enable_subnet_blocking'])); ?> />
                            <?php esc_html_e('Block entire subnet if multiple IPs in the subnet reach the failed attempts threshold.', 'block-logins-cf'); ?>
                        </label>
                    </td>
                </tr>
                <tr valign="top" id="subnet-threshold-row" <?php if (empty($options['enable_subnet_blocking'])) echo 'style="display:none;"'; ?>>
                    <th scope="row"><?php esc_html_e('Subnet Threshold', 'block-logins-cf'); ?></th>
                    <td>
                        <input type="number" min="1" name="cfblocklogins_settings[subnet_threshold]" value="<?php echo esc_attr($options['subnet_threshold'] ?? 2); ?>" />
                        <p class="description"><?php esc_html_e('Number of different IPs in a subnet that must reach the failed attempts threshold before blocking the entire subnet.', 'block-logins-cf'); ?></p>
                    </td>
                </tr>
                <tr valign="top">
                    <th scope="row"><?php esc_html_e('Auto Unblock Duration (hours)', 'block-logins-cf'); ?></th>
                    <td>
                        <input type="number" min="1" name="cfblocklogins_settings[auto_unblock_hours]" value="<?php echo esc_attr($options['auto_unblock_hours'] ?? 24); ?>" required />
                        <p class="description"><?php esc_html_e('Blocked IPs will be automatically unblocked after this many hours.', 'block-logins-cf'); ?></p>
                    </td>
                </tr>
                <tr valign="top">
                    <th scope="row" colspan="2"><strong><?php esc_html_e('XML-RPC Protection', 'block-logins-cf'); ?></strong></th>
                </tr>
                <tr valign="top">
                    <th scope="row"><?php esc_html_e('Enable XML-RPC Blocking', 'block-logins-cf'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="cfblocklogins_settings[enable_xmlrpc_blocking]" value="1" <?php checked(!empty($options['enable_xmlrpc_blocking'])); ?> />
                            <?php esc_html_e('Block IPs that make too many failed XML-RPC login attempts.', 'block-logins-cf'); ?>
                        </label>
                        <p class="description">
                            <?php esc_html_e('Note: Automattic services (WordPress.com, Jetpack, VaultPress) are automatically whitelisted.', 'block-logins-cf'); ?>
                        </p>
                    </td>
                </tr>
                <tr valign="top" id="xmlrpc-settings-row" <?php if (empty($options['enable_xmlrpc_blocking'])) echo 'style="display:none;"'; ?>>
                    <th scope="row"><?php esc_html_e('XML-RPC Block Settings', 'block-logins-cf'); ?></th>
                    <td>
                        <p>
                            <?php esc_html_e('Block after', 'block-logins-cf'); ?>
                            <input type="number" min="1" style="width:70px;" name="cfblocklogins_settings[xmlrpc_max_attempts]" value="<?php echo esc_attr($options['xmlrpc_max_attempts'] ?? 3); ?>" />
                            <?php esc_html_e('failed XML-RPC attempts for', 'block-logins-cf'); ?>
                            <input type="number" min="1" style="width:90px;" name="cfblocklogins_settings[xmlrpc_block_duration]" value="<?php echo esc_attr($options['xmlrpc_block_duration'] ?? 300); ?>" />
                            <?php esc_html_e('seconds', 'block-logins-cf'); ?>
                        </p>
                        <p class="description">
                            <?php esc_html_e('XML-RPC blocking uses separate thresholds from regular login blocking.', 'block-logins-cf'); ?>
                        </p>
                    </td>
                </tr>
            </table>
            <?php submit_button(esc_html__('Save Settings', 'block-logins-cf')); ?>
        </form>

        <hr>
        <h2><?php esc_html_e('Cloudflare API Credentials', 'block-logins-cf'); ?></h2>
        <?php
        // Validate credentials again for display
        $valid = false;
        $debug = '';
        if (!empty($options['api_key'])) {
            $url = "https://api.cloudflare.com/client/v4/user/tokens/verify";
            $response = wp_remote_get($url, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $options['api_key'],
                    'Content-Type' => 'application/json',
                ],
                'timeout' => 10,
            ]);

            $api_result = cfblocklogins_validate_api_response($response, 'token_verify_display');
            $valid = ($api_result !== false);
            if (!$valid) {
                $body = wp_remote_retrieve_body($response);
                $debug_msg = is_wp_error($response) ? $response->get_error_message() : substr($body, 0, 200);
                $debug = '<pre>' . esc_html($debug_msg) . '</pre>';
            }
        }
        if ($valid) {
            echo '<p style="color:green;">' . esc_html__('Cloudflare API credentials are valid.', 'block-logins-cf') . '</p>';
        } else {
            echo '<p style="color:red;">' . esc_html__('Cloudflare API credentials are invalid.', 'block-logins-cf') . '</p>';
            if ($debug) {
                echo wp_kses_post($debug);
            }
        }
        ?>
        <form method="post" style="margin-top:1em;">
            <?php wp_nonce_field('cfblocklogins_clear_credentials_action'); ?>
            <input type="hidden" name="cfblocklogins_clear_credentials" value="1">
            <input type="submit" class="button" value="<?php esc_attr_e('Clear Cloudflare Credentials', 'block-logins-cf'); ?>">
        </form>
    </div>
    <?php
}

// Whitelist logic
function cfblocklogins_get_whitelist() {
    $settings = get_option('cfblocklogins_settings', []);
    return isset($settings['whitelist']) && is_array($settings['whitelist']) ? $settings['whitelist'] : [];
}

function cfblocklogins_add_to_whitelist($ip) {
    $settings = get_option('cfblocklogins_settings', []);
    if (!isset($settings['whitelist']) || !is_array($settings['whitelist'])) {
        $settings['whitelist'] = [];
    }
    if (!in_array($ip, $settings['whitelist'])) {
        $settings['last_whitelist_update'] = time(); // Optional: track last update time
        $settings['whitelist'][] = $ip;
        $result = update_option('cfblocklogins_settings', $settings);
        wp_cache_delete('cfblocklogins_settings', 'options');
    }
}

function cfblocklogins_remove_from_whitelist($ip) {
    $settings = get_option('cfblocklogins_settings', []);
    if (isset($settings['whitelist']) && is_array($settings['whitelist'])) {
        $settings['whitelist'] = array_diff($settings['whitelist'], [$ip]);
        $result = update_option('cfblocklogins_settings', $settings);
        wp_cache_delete('cfblocklogins_settings', 'options');
    }
}

// Blocked IPs page
function cfblocklogins_blocked_page() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'block-logins-cf'));
    }

    // Handle unblock
    if (isset($_POST['cfblocklogins_unblock_ip']) && check_admin_referer('cfblocklogins_unblock_ip_action')) {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to perform this action.', 'block-logins-cf'));
        }
        $ip = sanitize_text_field(wp_unslash($_POST['cfblocklogins_unblock_ip']));
        delete_transient("cfblocklogins_block_login_$ip");
        delete_transient("cfblocklogins_block_login_time_$ip");
        wp_cache_delete('cfblocklogins_blocked_ip_transients', 'block-logins-cf');
        wp_cache_delete('cfblocklogins_blocked_ip_transients_cron', 'block-logins-cf');
        echo '<div class="updated"><p>Unblocked IP: ' . esc_html($ip) . '</p></div>';
    }
    // Handle whitelist add
    if (isset($_POST['cfblocklogins_whitelist_ip']) && check_admin_referer('cfblocklogins_whitelist_ip_action')) {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to perform this action.', 'block-logins-cf'));
        }
        $ip = sanitize_text_field(wp_unslash($_POST['cfblocklogins_whitelist_ip']));
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            cfblocklogins_add_to_whitelist($ip);
            echo '<div class="updated"><p>Whitelisted IP: ' . esc_html($ip) . '</p></div>';
        } else {
            echo '<div class="error"><p>Invalid IP address.</p></div>';
        }
    }
    // Handle whitelist remove
    if (isset($_POST['cfblocklogins_remove_whitelist_ip']) && check_admin_referer('cfblocklogins_remove_whitelist_ip_action')) {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to perform this action.', 'block-logins-cf'));
        }
        $ip = sanitize_text_field(wp_unslash($_POST['cfblocklogins_remove_whitelist_ip']));
        cfblocklogins_remove_from_whitelist($ip);
        echo '<div class="updated"><p>Removed from whitelist: ' . esc_html($ip) . '</p></div>';
    }

    // Handle immediate block
    if (isset($_POST['cfblocklogins_block_ip_manual']) && check_admin_referer('cfblocklogins_block_ip_manual_action')) {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to perform this action.', 'block-logins-cf'));
        }
        $ip = sanitize_text_field(wp_unslash($_POST['cfblocklogins_block_ip_manual']));
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            cfblocklogins_block_ip($ip);
            echo '<div class="updated"><p>Blocked IP: ' . esc_html($ip) . '</p></div>';
        } else {
            echo '<div class="error"><p>Invalid IP address.</p></div>';
        }
    }

    // Find blocked IPs (transients)
    global $wpdb;
    $blocked_ips = [];
    $cache_key = 'cfblocklogins_blocked_ip_transients';
    $transients = wp_cache_get($cache_key, 'block-logins-cf');

    if ($transients === false) {
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- No WP API to list transients by pattern, query is prepared and cached
        $transients = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
                '_transient_cf_block_login_%'
            )
        );
        // Cache for 1 minute
        wp_cache_set($cache_key, $transients, 'block-logins-cf', 60);
    }
    foreach ($transients as $transient) {
        $name = $transient->option_name;
        if (strpos($name, '_transient_cf_block_login_time_') === 0) {
            continue; // skip time transients
        }
        $ip = str_replace('_transient_cf_block_login_', '', $name);
        $blocked_ips[] = $ip;
    }

    $whitelist = cfblocklogins_get_whitelist();
    ?>
    <div class="wrap">
        <h1><?php esc_html_e('Blocked and Whitelisted IPs', 'block-logins-cf'); ?></h1>
        <h2><?php esc_html_e('Currently Blocked', 'block-logins-cf'); ?></h2>
        <table class="widefat">
            <thead>
                <tr>
                    <th><?php esc_html_e('IP Address', 'block-logins-cf'); ?></th>
                    <th><?php esc_html_e('Time Until Unblock', 'block-logins-cf'); ?></th>
                    <th><?php esc_html_e('Action', 'block-logins-cf'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($blocked_ips)): ?>
                    <tr><td colspan="3"><?php esc_html_e('No blocked IPs.', 'block-logins-cf'); ?></td></tr>
                <?php else: foreach ($blocked_ips as $ip): ?>
                    <tr>
                        <td><?php echo esc_html($ip); ?></td>
                        <td>
                            <?php
                            $block_time = get_transient("cfblocklogins_block_login_time_$ip");
                            if ($block_time) {
                                $settings = get_option('cfblocklogins_settings', []);
                                $auto_unblock_hours = intval($settings['auto_unblock_hours'] ?? 24);
                                $auto_unblock_seconds = $auto_unblock_hours * 3600;
                                $remaining = ($block_time + $auto_unblock_seconds) - time();
                                if ($remaining > 0) {
                                    $hours = floor($remaining / 3600);
                                    $minutes = floor(($remaining % 3600) / 60);
                                    $seconds = $remaining % 60;
                                    printf('%02dh %02dm %02ds', absint($hours), absint($minutes), absint($seconds));
                                } else {
                                    esc_html_e('Unblocking soon', 'block-logins-cf');
                                }
                            } else {
                                esc_html_e('Never', 'block-logins-cf');
                            }
                            ?>
                        </td>
                        <td>
                            <form method="post" style="display:inline;">
                                <?php wp_nonce_field('cfblocklogins_unblock_ip_action'); ?>
                                <input type="hidden" name="cfblocklogins_unblock_ip" value="<?php echo esc_attr($ip); ?>">
                                <input type="submit" class="button" value="<?php esc_attr_e('Unblock', 'block-logins-cf'); ?>">
                            </form>
                        </td>
                    </tr>
                <?php endforeach; endif; ?>
            </tbody>
        </table>
        
        <h3><?php esc_html_e('Manually Block an IP', 'block-logins-cf'); ?></h3>
        <form method="post">
            <?php wp_nonce_field('cfblocklogins_block_ip_manual_action'); ?>
            <input type="text" name="cfblocklogins_block_ip_manual" placeholder="<?php esc_attr_e('Enter IP address', 'block-logins-cf'); ?>" required>
            <input type="submit" class="button" value="<?php esc_attr_e('Block IP', 'block-logins-cf'); ?>">
        </form>
        <hr />

        <h2><?php esc_html_e('Whitelisted IPs', 'block-logins-cf'); ?></h2>
        <table class="widefat">
            <thead>
                <tr><th><?php esc_html_e('IP Address', 'block-logins-cf'); ?></th><th><?php esc_html_e('Action', 'block-logins-cf'); ?></th></tr>
            </thead>
            <tbody>
                <?php if (empty($whitelist)): ?>
                    <tr><td colspan="2"><?php esc_html_e('No whitelisted IPs.', 'block-logins-cf'); ?></td></tr>
                <?php else: foreach ($whitelist as $ip): ?>
                    <tr>
                        <td><?php echo esc_html($ip); ?></td>
                        <td>
                            <form method="post" style="display:inline;">
                                <?php wp_nonce_field('cfblocklogins_remove_whitelist_ip_action'); ?>
                                <input type="hidden" name="cfblocklogins_remove_whitelist_ip" value="<?php echo esc_attr($ip); ?>">
                                <input type="submit" class="button" value="<?php esc_attr_e('Remove', 'block-logins-cf'); ?>">
                            </form>
                        </td>
                    </tr>
                <?php endforeach; endif; ?>
            </tbody>
        </table>
        
        <h3><?php esc_html_e('Add Whitelisted IP', 'block-logins-cf'); ?></h3>
        <form method="post" style="margin-bottom:1em;">
            <?php wp_nonce_field('cfblocklogins_whitelist_ip_action'); ?>
            <input type="text" name="cfblocklogins_whitelist_ip" placeholder="<?php esc_attr_e('Enter IP address', 'block-logins-cf'); ?>" required>
            <input type="submit" class="button" value="<?php esc_attr_e('Add to Whitelist', 'block-logins-cf'); ?>">
        </form>

    </div>
    <?php
}

// Helper to get /24 subnet from an IPv4 address
function cfblocklogins_get_subnet($ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $parts = explode('.', $ip);
        return "{$parts[0]}.{$parts[1]}.{$parts[2]}.0/24";
    }
    // For IPv6 or invalid, return false or handle as needed
    return false;
}

// Get user IP with enhanced security validation
function cfblocklogins_get_user_ip() {
    // Get the direct connection IP as fallback
    $remote_addr = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';

    // Define trusted proxy sources (should be configurable in production)
    $trusted_proxies = cfblocklogins_get_trusted_proxies();

    // Check if we're behind a trusted proxy
    $is_trusted_proxy = cfblocklogins_is_trusted_proxy($remote_addr, $trusted_proxies);

    // If behind trusted proxy, validate and use proxy headers
    if ($is_trusted_proxy) {
        // Cloudflare CF-Connecting-IP header (highest priority for Cloudflare users)
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = cfblocklogins_validate_and_sanitize_ip(sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP'])));
            if ($ip) return $ip;
        }

        // X-Forwarded-For header (standard proxy header)
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $forwarded_ips = explode(',', sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR'])));
            // Get the leftmost (original client) IP, skipping any trusted proxies
            foreach ($forwarded_ips as $forwarded_ip) {
                $ip = cfblocklogins_validate_and_sanitize_ip(trim($forwarded_ip));
                if ($ip && !cfblocklogins_is_trusted_proxy($ip, $trusted_proxies)) {
                    return $ip;
                }
            }
        }

        // X-Real-IP header (some proxy configurations)
        if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            $ip = cfblocklogins_validate_and_sanitize_ip(sanitize_text_field(wp_unslash($_SERVER['HTTP_X_REAL_IP'])));
            if ($ip) return $ip;
        }
    }

    // If not behind trusted proxy or no valid proxy headers, use direct connection IP
    $ip = cfblocklogins_validate_and_sanitize_ip($remote_addr);
    return $ip ?: '0.0.0.0'; // Fallback to safe default
}

// Validate and sanitize IP address
function cfblocklogins_validate_and_sanitize_ip($ip) {
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
    $allow_private = cfblocklogins_allow_private_ips();
    if ($allow_private && filter_var($ip, FILTER_VALIDATE_IP)) {
        return $ip;
    }

    return false;
}

// Get list of trusted proxy IP ranges
function cfblocklogins_get_trusted_proxies() {
    // Default Cloudflare IP ranges (should be configurable)
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

// Check if IP is in trusted proxy ranges
function cfblocklogins_is_trusted_proxy($ip, $trusted_ranges) {
    if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }

    foreach ($trusted_ranges as $range) {
        if (cfblocklogins_ip_in_range($ip, $range)) {
            return true;
        }
    }

    return false;
}

// Check if IP is in CIDR range
function cfblocklogins_ip_in_range($ip, $range) {
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

// Check if private IPs should be allowed (for development environments)
function cfblocklogins_allow_private_ips() {
    $settings = get_option('cfblocklogins_settings', []);
    return isset($settings['allow_private_ips']) ? $settings['allow_private_ips'] : false;
}

// Encrypt sensitive data using WordPress security keys
function cfblocklogins_encrypt_data($data) {
    if (empty($data)) {
        return '';
    }

    // Use WordPress security constants as encryption key
    $key = cfblocklogins_get_encryption_key();
    if (!$key) {
        cfblocklogins_log_error("No encryption key available, storing data as plaintext");
        return $data; // Fallback to plaintext if no key available
    }

    try {
        // Use a simple but secure encryption method
        $iv = openssl_random_pseudo_bytes(16);
        $encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);

        if ($encrypted === false) {
            cfblocklogins_log_error("Encryption failed, storing data as plaintext");
            return $data; // Fallback to plaintext
        }

        // Prepend IV and base64 encode the result
        return base64_encode($iv . $encrypted);

    } catch (Exception $e) {
        cfblocklogins_log_error("Encryption error: " . $e->getMessage());
        return $data; // Fallback to plaintext
    }
}

// Decrypt sensitive data
function cfblocklogins_decrypt_data($encrypted_data) {
    if (empty($encrypted_data)) {
        return '';
    }

    $key = cfblocklogins_get_encryption_key();
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
            cfblocklogins_log_error("Decryption failed, assuming plaintext data");
            return $encrypted_data; // Fallback to original data
        }

        return $decrypted;

    } catch (Exception $e) {
        cfblocklogins_log_error("Decryption error: " . $e->getMessage());
        return $encrypted_data; // Fallback to original data
    }
}

// Generate encryption key from WordPress security constants
function cfblocklogins_get_encryption_key() {
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

// Check if encryption is available and working
function cfblocklogins_is_encryption_available() {
    return function_exists('openssl_encrypt') &&
           function_exists('openssl_decrypt') &&
           cfblocklogins_get_encryption_key() !== false;
}

// Encrypt API credentials when saving
function cfblocklogins_encrypt_api_credentials($settings) {
    if (!cfblocklogins_is_encryption_available()) {
        return $settings; // Return as-is if encryption not available
    }

    $sensitive_fields = ['api_key', 'email', 'zone_id'];

    foreach ($sensitive_fields as $field) {
        if (isset($settings[$field]) && !empty($settings[$field])) {
            $settings[$field] = cfblocklogins_encrypt_data($settings[$field]);
        }
    }

    // Mark that these credentials are encrypted
    $settings['_credentials_encrypted'] = true;

    return $settings;
}

// Decrypt API credentials when loading
function cfblocklogins_decrypt_api_credentials($settings) {
    if (empty($settings['_credentials_encrypted'])) {
        return $settings; // Not encrypted
    }

    if (!cfblocklogins_is_encryption_available()) {
        cfblocklogins_log_error("Cannot decrypt credentials - encryption not available");
        return $settings; // Return as-is, might fail but won't crash
    }

    $sensitive_fields = ['api_key', 'email', 'zone_id'];

    foreach ($sensitive_fields as $field) {
        if (isset($settings[$field]) && !empty($settings[$field])) {
            $settings[$field] = cfblocklogins_decrypt_data($settings[$field]);
        } else {
            $settings[$field] = ''; // Ensure field exists with empty value
        }
    }

    return $settings;
}

// Get decrypted API credentials
function cfblocklogins_get_api_credentials() {
    $settings = get_option('cfblocklogins_settings', []);
    return cfblocklogins_decrypt_api_credentials($settings);
}

// Schedule the cron event on plugin activation
register_activation_hook(__FILE__, function() {
    if (!wp_next_scheduled('cfblocklogins_cron_unblock')) {
        wp_schedule_event(time(), 'hourly', 'cfblocklogins_cron_unblock');
    }
});

// Clear the cron event on plugin deactivation
register_deactivation_hook(__FILE__, function() {
    wp_clear_scheduled_hook('cfblocklogins_cron_unblock');
});

// Cron callback to unblock expired IPs
add_action('cfblocklogins_cron_unblock', function() {
    global $wpdb;
    $settings = get_option('cfblocklogins_settings', []);
    $auto_unblock_hours = intval($settings['auto_unblock_hours'] ?? 24);
    $auto_unblock_seconds = $auto_unblock_hours * 3600;

    $cache_key = 'cfblocklogins_blocked_ip_transients_cron';
    $transients = wp_cache_get($cache_key, 'block-logins-cf');

    if ($transients === false) {
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- No WP API to list transients by pattern, query is prepared and cached
        $transients = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
                '_transient_cf_block_login_%'
            )
        );
        // Cache for 1 minute
        wp_cache_set($cache_key, $transients, 'block-logins-cf', 60);
    }
    foreach ($transients as $transient) {
        $name = $transient->option_name;
        if (strpos($name, '_transient_cf_block_login_time_') === 0) {
            continue; // skip time transients
        }
        $ip_or_subnet = str_replace('_transient_cf_block_login_', '', $name);

        // Check if this transient should be expired
        $block_time = get_transient("cfblocklogins_block_login_time_$ip_or_subnet");
        if ($block_time && (time() - $block_time) > $auto_unblock_seconds) {
            // Force delete expired transients (backup cleanup)
            delete_transient("cfblocklogins_block_login_$ip_or_subnet");
            delete_transient("cfblocklogins_block_login_time_$ip_or_subnet");

            cfblocklogins_log_error("Cron cleanup: Removed expired block", [
                'ip_or_subnet' => $ip_or_subnet,
                'block_age_seconds' => time() - $block_time
            ]);
        } elseif (!$block_time) {
            // Clean up orphaned block transients without time stamps
            delete_transient("cfblocklogins_block_login_$ip_or_subnet");
            cfblocklogins_log_error("Cron cleanup: Removed orphaned block transient", [
                'ip_or_subnet' => $ip_or_subnet
            ]);
        }
    }
});

// ============================================================================
// XML-RPC Protection Functions
// ============================================================================

// Get Automattic (WordPress.com, Jetpack, VaultPress) IP ranges
function cfblocklogins_get_automattic_ip_ranges() {
    return [
        // WordPress.com IP ranges
        '192.0.64.0/18',
        '66.155.40.0/24',
        '66.155.41.0/24',
        '209.15.21.0/24',
        '76.74.254.0/24',
        '76.74.255.0/24',
        '198.181.116.0/24',
        '198.181.117.0/24',
        '69.46.86.0/24',
        '69.46.87.0/24',

        // Jetpack IP ranges
        '195.234.108.0/22',
        '192.0.64.0/18',
        '198.181.116.0/22',
        '76.74.248.0/21',

        // VaultPress IP ranges
        '69.46.83.0/24',
        '69.46.82.0/24',
        '198.181.118.0/24',
        '198.181.119.0/24'
    ];
}

// Check if IP is from Automattic services
function cfblocklogins_is_automattic_ip($ip) {
    $automattic_ranges = cfblocklogins_get_automattic_ip_ranges();

    foreach ($automattic_ranges as $range) {
        if (cfblocklogins_ip_in_range($ip, $range)) {
            return true;
        }
    }

    return false;
}

// Log XML-RPC access
function cfblocklogins_log_xmlrpc_access($method = '', $args = []) {
    $ip = cfblocklogins_get_user_ip();
    $is_automattic = cfblocklogins_is_automattic_ip($ip);

    // Get current counts
    $today = gmdate('Y-m-d');
    $transient_key = "cfblocklogins_xmlrpc_access_$today";
    $access_data = get_transient($transient_key) ?: [
        'total_requests' => 0,
        'automattic_requests' => 0,
        'non_automattic_requests' => 0,
        'unique_ips' => [],
        'methods' => [],
        'first_seen' => time(),
        'last_seen' => time()
    ];

    // Update counters
    $access_data['total_requests']++;
    $access_data['last_seen'] = time();

    if ($is_automattic) {
        $access_data['automattic_requests']++;
    } else {
        $access_data['non_automattic_requests']++;
    }

    // Track unique IPs (limited to prevent memory issues)
    if (!in_array($ip, $access_data['unique_ips']) && count($access_data['unique_ips']) < 100) {
        $access_data['unique_ips'][] = $ip;
    }

    // Track methods (limited to prevent memory issues)
    if ($method && !isset($access_data['methods'][$method])) {
        if (count($access_data['methods']) < 50) {
            $access_data['methods'][$method] = 0;
        }
    }
    if ($method && isset($access_data['methods'][$method])) {
        $access_data['methods'][$method]++;
    }

    // Store for 25 hours (overlaps day boundary)
    set_transient($transient_key, $access_data, 25 * HOUR_IN_SECONDS);

    // Check if we should show admin notification
    cfblocklogins_check_xmlrpc_attack_threshold($access_data);

    // Log the access
    cfblocklogins_log_error("XML-RPC access logged", [
        'ip' => $ip,
        'method' => $method,
        'is_automattic' => $is_automattic,
        'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown'
    ]);
}

// Check if XML-RPC traffic suggests an attack
function cfblocklogins_check_xmlrpc_attack_threshold($access_data) {
    $settings = get_option('cfblocklogins_settings', []);

    // Skip if XML-RPC blocking is already enabled
    if (!empty($settings['enable_xmlrpc_blocking'])) {
        return;
    }

    // Skip if notification was already shown today
    $today = gmdate('Y-m-d');
    $notification_shown = get_transient("cfblocklogins_xmlrpc_notification_shown_$today");
    if ($notification_shown) {
        return;
    }

    // Define thresholds for suspicious activity
    $non_automattic_threshold = 50;  // 50+ non-Automattic requests
    $unique_ip_threshold = 10;       // 10+ unique IPs
    $time_threshold = 3600;          // Within 1 hour

    // Check if thresholds are exceeded
    $time_since_first = time() - $access_data['first_seen'];
    $exceeds_request_threshold = $access_data['non_automattic_requests'] >= $non_automattic_threshold;
    $exceeds_ip_threshold = count($access_data['unique_ips']) >= $unique_ip_threshold;
    $within_time_window = $time_since_first <= $time_threshold;

    if ($exceeds_request_threshold && $exceeds_ip_threshold && $within_time_window) {
        // Mark notification as shown for today
        set_transient("cfblocklogins_xmlrpc_notification_shown_$today", true, 25 * HOUR_IN_SECONDS);

        // Log the detected attack
        cfblocklogins_log_error("XML-RPC attack detected - showing admin notification", [
            'non_automattic_requests' => $access_data['non_automattic_requests'],
            'unique_ips' => count($access_data['unique_ips']),
            'time_window_seconds' => $time_since_first
        ]);
    }
}

// Hook into XML-RPC calls to log access
add_action('xmlrpc_call', function($method) {
    cfblocklogins_log_xmlrpc_access($method);
});

// Display admin notification if XML-RPC attack is detected
add_action('admin_notices', function() {
    $current_screen = get_current_screen();
    if (!$current_screen || $current_screen->id !== 'toplevel_page_block-logins-cf') {
        return; // Only show on our plugin page
    }

    $today = gmdate('Y-m-d');
    $notification_shown = get_transient("cfblocklogins_xmlrpc_notification_shown_$today");
    $transient_key = "cfblocklogins_xmlrpc_access_$today";
    $access_data = get_transient($transient_key);

    if (!$notification_shown || !$access_data) {
        return;
    }

    $settings = get_option('cfblocklogins_settings', []);
    if (!empty($settings['enable_xmlrpc_blocking'])) {
        return; // Don't show if already enabled
    }

    // Check if thresholds are still exceeded
    $exceeds_thresholds = $access_data['non_automattic_requests'] >= 50 &&
                         count($access_data['unique_ips']) >= 10;

    if ($exceeds_thresholds) {
        ?>
        <div class="notice notice-warning is-dismissible">
            <h3><?php esc_html_e('Potential XML-RPC Attack Detected', 'block-logins-cf'); ?></h3>
            <p>
                <?php
                printf(
                    // translators: %1$d is the number of XML-RPC requests, %2$d is the number of unique IP addresses
                    esc_html__('We detected %1$d XML-RPC requests from %2$d unique IP addresses in the last hour. This pattern suggests a potential brute force attack via XML-RPC.', 'block-logins-cf'),
                    absint($access_data['non_automattic_requests']),
                    absint(count($access_data['unique_ips']))
                );
                ?>
            </p>
            <p>
                <strong><?php esc_html_e('Would you like to enable XML-RPC blocking protection?', 'block-logins-cf'); ?></strong>
            </p>
            <p>
                <a href="<?php echo esc_url(wp_nonce_url(admin_url('admin.php?page=block-logins-cf&enable_xmlrpc=1'), 'cfblocklogins_xmlrpc_action')); ?>" class="button button-primary">
                    <?php esc_html_e('Enable XML-RPC Protection', 'block-logins-cf'); ?>
                </a>
                <a href="<?php echo esc_url(wp_nonce_url(admin_url('admin.php?page=block-logins-cf&dismiss_xmlrpc=1'), 'cfblocklogins_xmlrpc_action')); ?>" class="button button-secondary">
                    <?php esc_html_e('Dismiss for Today', 'block-logins-cf'); ?>
                </a>
            </p>
            <p class="description">
                <?php esc_html_e('Note: Automattic services (WordPress.com, Jetpack, VaultPress) are automatically whitelisted and will not be blocked.', 'block-logins-cf'); ?>
            </p>
        </div>
        <?php
    }
});

// Handle XML-RPC enable/dismiss actions
add_action('admin_init', function() {
    if (isset($_GET['enable_xmlrpc']) && $_GET['enable_xmlrpc'] == '1') {
        if (!isset($_GET['_wpnonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'])), 'cfblocklogins_xmlrpc_action')) {
            wp_die(esc_html__('Security check failed.', 'block-logins-cf'));
        }
        if (current_user_can('manage_options')) {
            $settings = get_option('cfblocklogins_settings', []);
            $settings['enable_xmlrpc_blocking'] = 1;
            $settings['xmlrpc_max_attempts'] = 3;
            $settings['xmlrpc_block_duration'] = 300; // 5 minutes
            update_option('cfblocklogins_settings', $settings);

            // Clear the notification
            $today = gmdate('Y-m-d');
            delete_transient("cfblocklogins_xmlrpc_notification_shown_$today");

            wp_redirect(admin_url('admin.php?page=block-logins-cf&xmlrpc_enabled=1'));
            exit;
        }
    }

    if (isset($_GET['dismiss_xmlrpc']) && $_GET['dismiss_xmlrpc'] == '1') {
        if (!isset($_GET['_wpnonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'])), 'cfblocklogins_xmlrpc_action')) {
            wp_die(esc_html__('Security check failed.', 'block-logins-cf'));
        }
        if (current_user_can('manage_options')) {
            // Clear the notification for today
            $today = gmdate('Y-m-d');
            delete_transient("cfblocklogins_xmlrpc_notification_shown_$today");

            wp_redirect(admin_url('admin.php?page=block-logins-cf&xmlrpc_dismissed=1'));
            exit;
        }
    }
});

// Track failed XML-RPC login attempts
function cfblocklogins_track_xmlrpc_failed_logins($method, $args) {
    $settings = get_option('cfblocklogins_settings', []);

    // Skip if XML-RPC blocking is not enabled
    if (empty($settings['enable_xmlrpc_blocking'])) {
        return;
    }

    $ip = cfblocklogins_get_user_ip();

    // Skip if IP is from Automattic services
    if (cfblocklogins_is_automattic_ip($ip)) {
        return;
    }

    // Check if IP is whitelisted
    $whitelist = cfblocklogins_get_whitelist();
    if (in_array($ip, $whitelist)) {
        return;
    }

    // Check if IP is already blocked
    if (cfblocklogins_check_if_blocked($ip)) {
        return; // Already blocked
    }

    $max_attempts = intval($settings['xmlrpc_max_attempts'] ?? 3);
    $block_duration = intval($settings['xmlrpc_block_duration'] ?? 300); // 5 minutes default

    // Use the existing atomic increment function with XML-RPC specific settings
    $increment_result = cfblocklogins_increment_failed_attempts_atomic($ip, [
        'max_attempts' => $max_attempts,
        'block_duration' => $block_duration
    ], 'xmlrpc');

    if ($increment_result && isset($increment_result['attempts'])) {
        $attempts = $increment_result['attempts'];

        // Check if this attempt should trigger blocking
        if ($attempts >= $max_attempts) {
            // Block the IP using existing function
            cfblocklogins_block_ip($ip);

            cfblocklogins_log_error("IP blocked for XML-RPC abuse", [
                'ip' => $ip,
                'method' => $method,
                'attempts' => $attempts,
                'block_type' => 'xmlrpc'
            ]);
        }
    }
}

// Hook into XML-RPC authentication failures
add_filter('xmlrpc_login_error', function($error, $user) {
    // Get the current method from the global XML-RPC server
    global $wp_xmlrpc_server;
    $method = '';

    if (isset($wp_xmlrpc_server) && isset($wp_xmlrpc_server->message)) {
        $method = $wp_xmlrpc_server->message->methodName ?? '';
    }

    cfblocklogins_track_xmlrpc_failed_logins($method, []);

    return $error;
}, 10, 2);

// Block XML-RPC requests from blocked IPs
add_action('xmlrpc_call', function($method) {
    $settings = get_option('cfblocklogins_settings', []);

    // Skip if XML-RPC blocking is not enabled
    if (empty($settings['enable_xmlrpc_blocking'])) {
        return;
    }

    $ip = cfblocklogins_get_user_ip();

    // Allow Automattic services
    if (cfblocklogins_is_automattic_ip($ip)) {
        return;
    }

    // Check if IP is whitelisted
    $whitelist = cfblocklogins_get_whitelist();
    if (in_array($ip, $whitelist)) {
        return;
    }

    // Check if IP is blocked
    if (cfblocklogins_check_if_blocked($ip)) {
        cfblocklogins_log_error("Blocked XML-RPC request", [
            'ip' => $ip,
            'method' => $method,
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown'
        ]);

        // Return XML-RPC error
        $error = new IXR_Error(403, esc_html__('Access denied: IP address is temporarily blocked due to security policy.', 'block-logins-cf'));
        header('Content-Type: text/xml; charset=UTF-8');
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- IXR_Error::getXml() returns safe XML
        echo $error->getXml();
        exit;
    }
}, 1); // Priority 1 to run before logging
