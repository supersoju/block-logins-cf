<?php
/**
 * Logger utility class
 *
 * @package BlockLoginsCF\Utils
 */

namespace BlockLoginsCF\Utils;

/**
 * Centralized logging functionality
 */
class Logger {

    /**
     * Log an error message with optional context
     *
     * @param string $message Error message
     * @param array  $context Additional context information
     */
    public static function error($message, $context = []) {
        // Skip logging during tests unless specifically enabled
        if (defined('CF_PLUGIN_TESTING') && CF_PLUGIN_TESTING) {
            return;
        }

        if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
            $log_message = 'Block Logins CF: ' . $message;
            if (!empty($context)) {
                $log_message .= ' | Context: ' . wp_json_encode($context);
            }
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Used only when WP_DEBUG_LOG is enabled
            error_log($log_message);
        }
    }

    /**
     * Log an info message with optional context
     *
     * @param string $message Info message
     * @param array  $context Additional context information
     */
    public static function info($message, $context = []) {
        // Skip logging during tests unless specifically enabled
        if (defined('CF_PLUGIN_TESTING') && CF_PLUGIN_TESTING) {
            return;
        }

        if (defined('WP_DEBUG') && WP_DEBUG) {
            $log_message = 'Block Logins CF [INFO]: ' . $message;
            if (!empty($context)) {
                $log_message .= ' | Context: ' . wp_json_encode($context);
            }
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Used only when WP_DEBUG is enabled
            error_log($log_message);
        }
    }

    /**
     * Log a debug message with optional context
     *
     * @param string $message Debug message
     * @param array  $context Additional context information
     */
    public static function debug($message, $context = []) {
        // Skip logging during tests unless specifically enabled
        if (defined('CF_PLUGIN_TESTING') && CF_PLUGIN_TESTING) {
            return;
        }

        if (defined('WP_DEBUG') && WP_DEBUG && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
            $log_message = 'Block Logins CF [DEBUG]: ' . $message;
            if (!empty($context)) {
                $log_message .= ' | Context: ' . wp_json_encode($context);
            }
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Used only when WP_DEBUG and WP_DEBUG_LOG are enabled
            error_log($log_message);
        }
    }

    /**
     * Check if logging is enabled in the current environment
     *
     * @return bool True if logging is enabled
     */
    public static function is_logging_enabled() {
        // Don't log during tests unless specifically enabled
        if (defined('CF_PLUGIN_TESTING') && CF_PLUGIN_TESTING) {
            return false;
        }

        return defined('WP_DEBUG_LOG') && WP_DEBUG_LOG;
    }
}