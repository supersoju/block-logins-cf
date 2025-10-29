<?php
/**
 * Autoloader for Block Logins CF Plugin Classes
 *
 * @package BlockLoginsCF
 */

namespace BlockLoginsCF;

/**
 * Simple PSR-4 compatible autoloader for the plugin
 */
class Autoloader {

    /**
     * Base directory for the namespace prefix
     *
     * @var string
     */
    private $base_dir;

    /**
     * Namespace prefix
     *
     * @var string
     */
    private $namespace_prefix;

    /**
     * Constructor
     *
     * @param string $namespace_prefix The namespace prefix
     * @param string $base_dir Base directory for class files
     */
    public function __construct($namespace_prefix, $base_dir) {
        $this->namespace_prefix = $namespace_prefix;
        $this->base_dir = rtrim($base_dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    }

    /**
     * Register the autoloader
     */
    public function register() {
        spl_autoload_register([$this, 'load_class']);
    }

    /**
     * Load a class file
     *
     * @param string $class The fully-qualified class name
     * @return mixed The mapped file name on success, or boolean false on failure
     */
    public function load_class($class) {
        // Check if the class uses our namespace prefix
        $prefix_len = strlen($this->namespace_prefix);
        if (strncmp($this->namespace_prefix, $class, $prefix_len) !== 0) {
            return false;
        }

        // Get the relative class name
        $relative_class = substr($class, $prefix_len);

        // Convert namespace separators to directory separators
        // Convert class name format from CamelCase to kebab-case with class- prefix
        $relative_class = str_replace('\\', DIRECTORY_SEPARATOR, $relative_class);

        // Split into parts to handle class naming
        $parts = explode(DIRECTORY_SEPARATOR, $relative_class);

        // Convert the last part (class name) to WordPress naming convention
        if (!empty($parts)) {
            $class_name = array_pop($parts);
            $class_name = $this->camel_to_kebab($class_name);
            $class_name = 'class-' . $class_name . '.php';
            $parts[] = $class_name;
        }

        $file = $this->base_dir . implode(DIRECTORY_SEPARATOR, $parts);

        // If the file exists, require it
        if (file_exists($file)) {
            require $file;
            return $file;
        }

        return false;
    }

    /**
     * Convert CamelCase to kebab-case
     *
     * @param string $input CamelCase string
     * @return string kebab-case string
     */
    private function camel_to_kebab($input) {
        return strtolower(preg_replace('/([a-z])([A-Z])/', '$1-$2', $input));
    }
}