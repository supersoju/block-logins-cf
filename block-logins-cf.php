<?php
/**
 * Plugin Name: Block Logins with Cloudflare
 * Plugin URI: https://github.com/supersoju/block-logins-cf
 * Description: Blocks failed login attempts directly through Cloudflare.
 * Version: 1.0
 * Author: supersoju
 * Author URI: https://supersoju.com
 * Tested up to: 6.8
 * License: GNU General Public License v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: block-logins-with-cloudflare
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Tags: security, cloudflare, login, block, firewall
 */

if (!defined('ABSPATH')) {
	exit; // Exit if accessed directly
}

// Hook into login failure
add_action('wp_login_failed', 'cf_track_failed_logins');

function cf_track_failed_logins($username) {
    $ip = cf_get_user_ip();
    $subnet = cf_get_subnet($ip);

    $settings = get_option('cf_block_logins_settings', []);
    $whitelist = isset($settings['whitelist']) ? $settings['whitelist'] : [];
    if (in_array($ip, $whitelist) || ($subnet && in_array($subnet, $whitelist))) {
        return; // Don't track whitelisted IPs or subnets
    }

    $failed_attempts = get_transient("cf_failed_login_$ip") ?: 0;
    $failed_attempts++;
    set_transient("cf_failed_login_$ip", $failed_attempts, intval($settings['block_duration'] ?? 60));

    // Track subnet attempts
    if ($subnet) {
        $subnet_attempts = get_transient("cf_failed_login_subnet_$subnet") ?: 0;
        $subnet_attempts++;
        set_transient("cf_failed_login_subnet_$subnet", $subnet_attempts, intval($settings['block_duration'] ?? 60));
    }

    $max_attempts = intval($settings['max_attempts'] ?? 3);

    if ($failed_attempts >= $max_attempts) {
        cf_block_ip($ip);
    }

    // Block subnet if threshold reached (e.g., 2 different IPs in subnet reach threshold)
    if ($subnet) {
        $subnet_attempts = get_transient("cf_failed_login_subnet_$subnet") ?: 0;
        $subnet_threshold = intval($settings['subnet_threshold'] ?? 2); // You can add this to your settings page
        if ($subnet_attempts >= $subnet_threshold) {
            cf_block_subnet($subnet);
        }
    }
}

function cf_block_ip($ip) {
    set_transient("cf_block_login_$ip", '1', 0);
    set_transient("cf_block_login_time_$ip", time(), 0);

    // After unblocking or blocking an IP, clear the cached list of blocked IP transients
    wp_cache_delete('cf_blocked_ip_transients', 'block-logins-cf');
    wp_cache_delete('cf_blocked_ip_transients_cron', 'block-logins-cf'); 

    $settings = get_option('cf_block_logins_settings', []);
    $email   = $settings['email'] ?? '';
    $api_key = $settings['api_key'] ?? '';
    $zone_id = $settings['zone_id'] ?? '';

    if (!$email || !$api_key || !$zone_id) {
        return;
    }

    $url = "https://api.cloudflare.com/client/v4/zones/$zone_id/firewall/access_rules/rules";
    $data = [
        'mode' => 'block',
        'configuration' => ['target' => 'ip', 'value' => $ip],
        'notes' => 'Blocked due to failed logins'
    ];

    $response = wp_remote_post($url, [
        'headers' => [
            'X-Auth-Email' => $email,
            'X-Auth-Key' => $api_key,
            'Content-Type' => 'application/json',
        ],
        'body' => json_encode($data),
        'method' => 'POST',
    ]);
}

// Block a subnet via Cloudflare
function cf_block_subnet($subnet) {
    set_transient("cf_block_login_$subnet", '1', 0);
    set_transient("cf_block_login_time_$subnet", time(), 0);

    // After unblocking or blocking an IP, clear the cached list of blocked IP transients
    wp_cache_delete('cf_blocked_ip_transients', 'block-logins-cf');
    wp_cache_delete('cf_blocked_ip_transients_cron', 'block-logins-cf');

    $settings = get_option('cf_block_logins_settings', []);
    $email   = $settings['email'] ?? '';
    $api_key = $settings['api_key'] ?? '';
    $zone_id = $settings['zone_id'] ?? '';

    if (!$email || !$api_key || !$zone_id) {
        return;
    }

    $url = "https://api.cloudflare.com/client/v4/zones/$zone_id/firewall/access_rules/rules";
    $data = [
        'mode' => 'block',
        'configuration' => ['target' => 'ip', 'value' => $subnet],
        'notes' => 'Blocked subnet due to failed logins'
    ];

    $response = wp_remote_post($url, [
        'headers' => [
            'X-Auth-Email' => $email,
            'X-Auth-Key' => $api_key,
            'Content-Type' => 'application/json',
        ],
        'body' => json_encode($data),
        'method' => 'POST',
    ]);
}

// Add top-level menu and submenus
add_action('admin_menu', function() {
    // Top-level menu
    add_menu_page(
        'Block Logins CF', // Page title
        'Block Logins CF', // Menu title
        'manage_options',  // Capability
        'block-logins-cf', // Menu slug
        'cf_block_logins_settings_page', // Callback function
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
        'cf_block_logins_settings_page'
    );

    // Blocked IPs page
    add_submenu_page(
        'block-logins-cf', // Parent slug
        'Blocked IPs',
        'Blocked IPs',
        'manage_options',
        'block-logins-cf-blocked',
        'cf_block_logins_blocked_page'
    );
});

// Register settings with validation
add_action('admin_init', function() {
    register_setting(
        'cf_block_logins_settings_group',
        'cf_block_logins_settings',
        [
            'sanitize_callback' => 'cf_block_logins_settings_validate'
        ]
    );
});

// Validation callback
function cf_block_logins_settings_validate($input) {
    $current = get_option('cf_block_logins_settings', []);

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

    $has_credentials = !empty($current['email']) && !empty($current['api_key']) && !empty($current['zone_id']);
    $is_entering_credentials = !empty($input['email']) && !empty($input['api_key']) && !empty($input['zone_id']);

    // If credentials are missing or being entered, require and validate them
    if (!$has_credentials || $is_entering_credentials) {
        // All credential fields must be present
        if (empty($input['email']) || empty($input['api_key']) || empty($input['zone_id'])) {
            add_settings_error(
                'cf_block_logins_settings',
                'cf_block_logins_settings_missing',
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
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (
            is_wp_error($response) ||
            empty($data['success']) ||
            !$data['success']
        ) {
            $debug = '<pre>' . esc_html($body) . '</pre>';
            add_settings_error(
                'cf_block_logins_settings',
                'cf_block_logins_settings_invalid',
                'Cloudflare API Token is invalid. Debug info: ' . $debug,
                'error'
            );
            return $current;
        }
        // Save credentials and keep other settings from current
        return array_merge($current, [
            'email' => $input['email'],
            'api_key' => $input['api_key'],
            'zone_id' => $input['zone_id'],
            'whitelist' => $input['whitelist'],
        ]);
    }

    // If credentials exist and are not being changed, only update main settings
    return array_merge($current, [
        'max_attempts' => $input['max_attempts'],
        'block_duration' => $input['block_duration'],
        'auto_unblock_hours' => $input['auto_unblock_hours'],
        'enable_subnet_blocking' => $input['enable_subnet_blocking'],
        'subnet_threshold' => $input['enable_subnet_blocking'] ? $input['subnet_threshold'] : '',
        'whitelist' => $input['whitelist'], // preserve whitelist
    ]);
}

// Settings page HTML
function cf_block_logins_settings_page() {
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have sufficient permissions to access this page.', 'block-logins-cf'));
    }

    // Handle clear credentials
    if (isset($_POST['cf_clear_credentials']) && check_admin_referer('cf_clear_credentials_action')) {
        $settings = get_option('cf_block_logins_settings', []);
        unset($settings['email'], $settings['api_key'], $settings['zone_id']);
        update_option('cf_block_logins_settings', $settings);
        echo '<div class="updated"><p>' . __('Cloudflare credentials cleared. Please re-enter them below.', 'block-logins-cf') . '</p></div>';
    }

    $options = get_option('cf_block_logins_settings', []);
    $has_credentials = !empty($options['email']) && !empty($options['api_key']) && !empty($options['zone_id']);

    // If credentials are missing, show only credential fields
    if (!$has_credentials) {
        ?>
        <div class="wrap">
            <h1><?php _e('Block Logins with Cloudflare', 'block-logins-cf'); ?></h1>
            <?php settings_errors('cf_block_logins_settings'); ?>
            <form method="post" action="options.php">
                <?php settings_fields('cf_block_logins_settings_group'); ?>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row"><?php _e('Cloudflare Email', 'block-logins-cf'); ?></th>
                        <td><input type="email" name="cf_block_logins_settings[email]" value="<?php echo esc_attr($options['email'] ?? ''); ?>" required /></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row"><?php _e('Cloudflare API Key', 'block-logins-cf'); ?></th>
                        <td><input type="text" name="cf_block_logins_settings[api_key]" value="<?php echo esc_attr($options['api_key'] ?? ''); ?>" required /></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row"><?php _e('Cloudflare Zone ID', 'block-logins-cf'); ?></th>
                        <td><input type="text" name="cf_block_logins_settings[zone_id]" value="<?php echo esc_attr($options['zone_id'] ?? ''); ?>" required /></td>
                    </tr>
                </table>
                <?php submit_button(__('Save Cloudflare Credentials', 'block-logins-cf')); ?>
            </form>
        </div>
        <?php
        return;
    }

    // If credentials exist, show main settings and credential status
    ?>
    <div class="wrap">
        <h1><?php _e('Block Logins with Cloudflare', 'block-logins-cf'); ?></h1>
        <?php settings_errors('cf_block_logins_settings'); ?>
        <form method="post" action="options.php">
            <?php settings_fields('cf_block_logins_settings_group'); ?>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row" colspan="2"><strong><?php _e('Block after...', 'block-logins-cf'); ?></strong></th>
                </tr>
                <tr valign="top">
                    <td colspan="2">
                        <input type="number" min="1" style="width:70px;" name="cf_block_logins_settings[max_attempts]" value="<?php echo esc_attr($options['max_attempts'] ?? 3); ?>" required />
                        <?php _e('failed attempts in', 'block-logins-cf'); ?>
                        <input type="number" min="1" style="width:90px;" name="cf_block_logins_settings[block_duration]" value="<?php echo esc_attr($options['block_duration'] ?? 60); ?>" required />
                        <?php _e('seconds', 'block-logins-cf'); ?>
                    </td>
                </tr>
                <tr valign="top">
                    <th scope="row"><?php _e('Enable Subnet Blocking', 'block-logins-cf'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="cf_block_logins_settings[enable_subnet_blocking]" value="1" <?php checked(!empty($options['enable_subnet_blocking'])); ?> />
                            <?php _e('Block entire subnet if multiple IPs in the subnet reach the failed attempts threshold.', 'block-logins-cf'); ?>
                        </label>
                    </td>
                </tr>
                <tr valign="top" id="subnet-threshold-row" <?php if (empty($options['enable_subnet_blocking'])) echo 'style="display:none;"'; ?>>
                    <th scope="row"><?php _e('Subnet Threshold', 'block-logins-cf'); ?></th>
                    <td>
                        <input type="number" min="1" name="cf_block_logins_settings[subnet_threshold]" value="<?php echo esc_attr($options['subnet_threshold'] ?? 2); ?>" />
                        <p class="description"><?php _e('Number of different IPs in a subnet that must reach the failed attempts threshold before blocking the entire subnet.', 'block-logins-cf'); ?></p>
                    </td>
                </tr>
                <tr valign="top">
                    <th scope="row"><?php _e('Auto Unblock Duration (hours)', 'block-logins-cf'); ?></th>
                    <td>
                        <input type="number" min="1" name="cf_block_logins_settings[auto_unblock_hours]" value="<?php echo esc_attr($options['auto_unblock_hours'] ?? 24); ?>" required />
                        <p class="description"><?php _e('Blocked IPs will be automatically unblocked after this many hours.', 'block-logins-cf'); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(__('Save Settings', 'block-logins-cf')); ?>
        </form>

        <hr>
        <h2><?php _e('Cloudflare API Credentials', 'block-logins-cf'); ?></h2>
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
            $body = wp_remote_retrieve_body($response);
            $data = json_decode($body, true);
            $valid = !is_wp_error($response) && !empty($data['success']) && $data['success'];
            if (!$valid) {
                $debug = '<pre>' . esc_html($body) . '</pre>';
            }
        }
        if ($valid) {
            echo '<p style="color:green;">' . __('Cloudflare API credentials are valid.', 'block-logins-cf') . '</p>';
        } else {
            echo '<p style="color:red;">' . __('Cloudflare API credentials are invalid.', 'block-logins-cf') . '</p>';
            if ($debug) {
                echo $debug;
            }
        }
        ?>
        <form method="post" style="margin-top:1em;">
            <?php wp_nonce_field('cf_clear_credentials_action'); ?>
            <input type="hidden" name="cf_clear_credentials" value="1">
            <input type="submit" class="button" value="<?php esc_attr_e('Clear Cloudflare Credentials', 'block-logins-cf'); ?>">
        </form>
    </div>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        var checkbox = document.querySelector('input[name="cf_block_logins_settings[enable_subnet_blocking]"]');
        var row = document.getElementById('subnet-threshold-row');
        if (checkbox) {
            checkbox.addEventListener('change', function() {
                row.style.display = this.checked ? '' : 'none';
            });
        }
    });
    </script>
    <?php
}

// Whitelist logic
function cf_get_whitelist() {
    $settings = get_option('cf_block_logins_settings', []);
    return isset($settings['whitelist']) && is_array($settings['whitelist']) ? $settings['whitelist'] : [];
}

function cf_add_to_whitelist($ip) {
    $settings = get_option('cf_block_logins_settings', []);
    if (!isset($settings['whitelist']) || !is_array($settings['whitelist'])) {
        $settings['whitelist'] = [];
    }
    if (!in_array($ip, $settings['whitelist'])) {
        $settings['last_whitelist_update'] = time(); // Optional: track last update time
        $settings['whitelist'][] = $ip;
        $result = update_option('cf_block_logins_settings', $settings);
        wp_cache_delete('cf_block_logins_settings', 'options');
    }
}

function cf_remove_from_whitelist($ip) {
    $settings = get_option('cf_block_logins_settings', []);
    if (isset($settings['whitelist']) && is_array($settings['whitelist'])) {
        $settings['whitelist'] = array_diff($settings['whitelist'], [$ip]);
        $result = update_option('cf_block_logins_settings', $settings);
        wp_cache_delete('cf_block_logins_settings', 'options');
    }
}

// Blocked IPs page
function cf_block_logins_blocked_page() {
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have sufficient permissions to access this page.', 'block-logins-cf'));
    }

    // Handle unblock
    if (isset($_POST['cf_unblock_ip']) && check_admin_referer('cf_unblock_ip_action')) {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to perform this action.', 'block-logins-cf'));
        }
        $ip = sanitize_text_field(wp_unslash($_POST['cf_unblock_ip']));
        delete_transient("cf_block_login_$ip");
        delete_transient("cf_block_login_time_$ip");
        wp_cache_delete('cf_blocked_ip_transients', 'block-logins-cf');
        wp_cache_delete('cf_blocked_ip_transients_cron', 'block-logins-cf');
        echo '<div class="updated"><p>Unblocked IP: ' . esc_html($ip) . '</p></div>';
    }
    // Handle whitelist add
    if (isset($_POST['cf_whitelist_ip']) && check_admin_referer('cf_whitelist_ip_action')) {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to perform this action.', 'block-logins-cf'));
        }
        $ip = sanitize_text_field(wp_unslash($_POST['cf_whitelist_ip']));
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            cf_add_to_whitelist($ip);
            echo '<div class="updated"><p>Whitelisted IP: ' . esc_html($ip) . '</p></div>';
        } else {
            echo '<div class="error"><p>Invalid IP address.</p></div>';
        }
    }
    // Handle whitelist remove
    if (isset($_POST['cf_remove_whitelist_ip']) && check_admin_referer('cf_remove_whitelist_ip_action')) {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to perform this action.', 'block-logins-cf'));
        }
        $ip = sanitize_text_field(wp_unslash($_POST['cf_remove_whitelist_ip']));
        cf_remove_from_whitelist($ip);
        echo '<div class="updated"><p>Removed from whitelist: ' . esc_html($ip) . '</p></div>';
    }

    // Handle immediate block
    if (isset($_POST['cf_block_ip_manual']) && check_admin_referer('cf_block_ip_manual_action')) {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to perform this action.', 'block-logins-cf'));
        }
        $ip = sanitize_text_field(wp_unslash($_POST['cf_block_ip_manual']));
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            cf_block_ip($ip);
            echo '<div class="updated"><p>Blocked IP: ' . esc_html($ip) . '</p></div>';
        } else {
            echo '<div class="error"><p>Invalid IP address.</p></div>';
        }
    }

    // Find blocked IPs (transients)
    global $wpdb;
    $blocked_ips = [];
    $cache_key = 'cf_blocked_ip_transients';
    $transients = wp_cache_get($cache_key, 'block-logins-cf');

    if ($transients === false) {
        // This direct query is necessary to list all blocked IP transients.
        $transients = $wpdb->get_results(
            "SELECT option_name FROM $wpdb->options WHERE option_name LIKE '_transient_cf_block_login_%'"
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

    $whitelist = cf_get_whitelist();
    ?>
    <div class="wrap">
        <h1><?php _e('Blocked and Whitelisted IPs', 'block-logins-cf'); ?></h1>
        <h2><?php _e('Currently Blocked', 'block-logins-cf'); ?></h2>
        <table class="widefat">
            <thead>
                <tr>
                    <th><?php _e('IP Address', 'block-logins-cf'); ?></th>
                    <th><?php _e('Time Until Unblock', 'block-logins-cf'); ?></th>
                    <th><?php _e('Action', 'block-logins-cf'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($blocked_ips)): ?>
                    <tr><td colspan="3"><?php _e('No blocked IPs.', 'block-logins-cf'); ?></td></tr>
                <?php else: foreach ($blocked_ips as $ip): ?>
                    <tr>
                        <td><?php echo esc_html($ip); ?></td>
                        <td>
                            <?php
                            $block_time = get_transient("cf_block_login_time_$ip");
                            if ($block_time) {
                                $settings = get_option('cf_block_logins_settings', []);
                                $auto_unblock_hours = intval($settings['auto_unblock_hours'] ?? 24);
                                $auto_unblock_seconds = $auto_unblock_hours * 3600;
                                $remaining = ($block_time + $auto_unblock_seconds) - time();
                                if ($remaining > 0) {
                                    $hours = floor($remaining / 3600);
                                    $minutes = floor(($remaining % 3600) / 60);
                                    $seconds = $remaining % 60;
                                    printf('%02dh %02dm %02ds', $hours, $minutes, $seconds);
                                } else {
                                    _e('Unblocking soon', 'block-logins-cf');
                                }
                            } else {
                                _e('Never', 'block-logins-cf');
                            }
                            ?>
                        </td>
                        <td>
                            <form method="post" style="display:inline;">
                                <?php wp_nonce_field('cf_unblock_ip_action'); ?>
                                <input type="hidden" name="cf_unblock_ip" value="<?php echo esc_attr($ip); ?>">
                                <input type="submit" class="button" value="<?php esc_attr_e('Unblock', 'block-logins-cf'); ?>">
                            </form>
                        </td>
                    </tr>
                <?php endforeach; endif; ?>
            </tbody>
        </table>
        
        <h3><?php _e('Manually Block an IP', 'block-logins-cf'); ?></h3>
        <form method="post">
            <?php wp_nonce_field('cf_block_ip_manual_action'); ?>
            <input type="text" name="cf_block_ip_manual" placeholder="<?php esc_attr_e('Enter IP address', 'block-logins-cf'); ?>" required>
            <input type="submit" class="button" value="<?php esc_attr_e('Block IP', 'block-logins-cf'); ?>">
        </form>
        <hr />

        <h2><?php _e('Whitelisted IPs', 'block-logins-cf'); ?></h2>
        <table class="widefat">
            <thead>
                <tr><th><?php _e('IP Address', 'block-logins-cf'); ?></th><th><?php _e('Action', 'block-logins-cf'); ?></th></tr>
            </thead>
            <tbody>
                <?php if (empty($whitelist)): ?>
                    <tr><td colspan="2"><?php _e('No whitelisted IPs.', 'block-logins-cf'); ?></td></tr>
                <?php else: foreach ($whitelist as $ip): ?>
                    <tr>
                        <td><?php echo esc_html($ip); ?></td>
                        <td>
                            <form method="post" style="display:inline;">
                                <?php wp_nonce_field('cf_remove_whitelist_ip_action'); ?>
                                <input type="hidden" name="cf_remove_whitelist_ip" value="<?php echo esc_attr($ip); ?>">
                                <input type="submit" class="button" value="<?php esc_attr_e('Remove', 'block-logins-cf'); ?>">
                            </form>
                        </td>
                    </tr>
                <?php endforeach; endif; ?>
            </tbody>
        </table>
        
        <h3><?php _e('Add Whitelisted IP', 'block-logins-cf'); ?></h3>
        <form method="post" style="margin-bottom:1em;">
            <?php wp_nonce_field('cf_whitelist_ip_action'); ?>
            <input type="text" name="cf_whitelist_ip" placeholder="<?php esc_attr_e('Enter IP address', 'block-logins-cf'); ?>" required>
            <input type="submit" class="button" value="<?php esc_attr_e('Add to Whitelist', 'block-logins-cf'); ?>">
        </form>

    </div>
    <?php
}

// Helper to get /24 subnet from an IPv4 address
function cf_get_subnet($ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $parts = explode('.', $ip);
        return "{$parts[0]}.{$parts[1]}.{$parts[2]}.0/24";
    }
    // For IPv6 or invalid, return false or handle as needed
    return false;
}

// Get user IP, considering Cloudflare and other proxies
function cf_get_user_ip() {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        // In case of multiple IPs, take the first one
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($ips[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? '';
}

// Schedule the cron event on plugin activation
register_activation_hook(__FILE__, function() {
    if (!wp_next_scheduled('cf_block_logins_cron_unblock')) {
        wp_schedule_event(time(), 'hourly', 'cf_block_logins_cron_unblock');
    }
});

// Clear the cron event on plugin deactivation
register_deactivation_hook(__FILE__, function() {
    wp_clear_scheduled_hook('cf_block_logins_cron_unblock');
});

// Cron callback to unblock expired IPs
add_action('cf_block_logins_cron_unblock', function() {
    global $wpdb;
    $settings = get_option('cf_block_logins_settings', []);
    $auto_unblock_hours = intval($settings['auto_unblock_hours'] ?? 24);
    $auto_unblock_seconds = $auto_unblock_hours * 3600;

    $cache_key = 'cf_blocked_ip_transients_cron';
    $transients = wp_cache_get($cache_key, 'block-logins-cf');

    if ($transients === false) {
        // This direct query is necessary to list all blocked IP transients.
        $transients = $wpdb->get_results(
            "SELECT option_name FROM $wpdb->options WHERE option_name LIKE '_transient_cf_block_login_%'"
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
        $block_time = get_transient("cf_block_login_time_$ip");
        if ($block_time && (time() - $block_time) > $auto_unblock_seconds) {
            delete_transient("cf_block_login_$ip");
            delete_transient("cf_block_login_time_$ip");
        }
    }
});
