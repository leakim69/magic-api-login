<?php
/**
 * Plugin Name: Magic API Login
 * Description: Passwordless authentication via reusable magic links with API support - Improved UI Edition
 * Version: 2.8.0
 * Author: Creative Chili
 */

if (!defined('ABSPATH')) exit;

class SimpleMagicLogin {
    private const SCHEMA_VERSION = 3;

    private $table;
    private $option_key = 'sml_settings';
    private $schema_version_option = 'sml_schema_version';
    private $schema_checked = false;

    public function __construct() {
        global $wpdb;
        $this->table = $wpdb->prefix . 'magic_login_tokens';
        
        add_action('plugins_loaded', [$this, 'init']);
        register_activation_hook(__FILE__, [$this, 'activate']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
    }

    public function init() {
        add_action('admin_menu', [$this, 'add_settings_page']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('rest_api_init', [$this, 'register_rest_routes']);
        // Hook early to avoid loading unnecessary WordPress components
        add_action('init', [SimpleMagicLogin::class, 'verify_and_login'], 1);
        add_action('sml_purge_tokens', [$this, 'purge_expired_tokens']);
        
        // Deferred login hooks handler (runs after redirect to avoid blocking)
        add_action('sml_deferred_login_hooks', [$this, 'handle_deferred_login_hooks'], 10, 5);
        
        // Shortcode for email login form
        add_shortcode('magic_login_form', [$this, 'render_login_form_shortcode']);
        
        // User profile actions
        add_action('show_user_profile', [$this, 'user_profile_revoke_section']);
        add_action('edit_user_profile', [$this, 'user_profile_revoke_section']);
        add_action('personal_options_update', [$this, 'handle_user_revoke']);
        add_action('edit_user_profile_update', [$this, 'handle_user_revoke']);
        
        // Ensure schema is up to date
        $this->ensure_schema();
    }
    
    /**
     * Handle deferred login hooks to avoid blocking redirect
     * This runs after the user has been redirected, so slow plugins don't delay login
     * Note: wp_login hook is skipped by default for magic logins to avoid delays from other plugins
     * If you need wp_login to fire, you can hook into sml_user_logged_in instead
     */
    public function handle_deferred_login_hooks($user_login, $user_id, $current_ip, $current_ua, $original_ip) {
        // Skip wp_login hook by default - it's often slow due to security/analytics plugins
        // Plugins that need login events should hook into sml_user_logged_in instead
        // Uncomment the line below if you specifically need wp_login to fire:
        // do_action('wp_login', $user_login, get_userdata($user_id));
        
        // Fire custom hook (faster, less likely to have slow listeners)
        do_action('sml_user_logged_in', $user_id, $current_ip, $current_ua);
        
        // Optional: Alert if IP changed
        if (!empty($original_ip) && $original_ip !== $current_ip) {
            do_action('sml_ip_changed', $user_id, $original_ip, $current_ip);
        }
    }

    public function register_rest_routes() {
        register_rest_route('magic-login/v1', '/generate-link', [
            'methods' => 'POST',
            'callback' => [$this, 'api_generate_link'],
            'permission_callback' => [$this, 'api_permission_check'],
            'args' => [
                'user_id' => [
                    'required' => false,
                    'type' => 'integer',
                    'description' => 'WordPress user ID'
                ],
                'email' => [
                    'required' => false,
                    'type' => 'string',
                    'description' => 'User email address'
                ],
                'redirect_url' => [
                    'required' => false,
                    'type' => 'string',
                    'description' => 'URL to redirect to after login'
                ]
            ]
        ]);

        register_rest_route('magic-login/v1', '/verify-token', [
            'methods' => 'POST',
            'callback' => [$this, 'api_verify_token'],
            'permission_callback' => '__return_true',
            'args' => [
                'token' => [
                    'required' => true,
                    'type' => 'string',
                    'description' => 'Magic login token'
                ]
            ]
        ]);
        
        register_rest_route('magic-login/v1', '/revoke-user-tokens', [
            'methods' => 'POST',
            'callback' => [$this, 'api_revoke_user_tokens'],
            'permission_callback' => [$this, 'api_permission_check'],
            'args' => [
                'user_id' => [
                    'required' => true,
                    'type' => 'integer',
                    'description' => 'WordPress user ID'
                ]
            ]
        ]);

        register_rest_route('magic-login/v1', '/request-new-link', [
            'methods' => 'POST',
            'callback' => [$this, 'api_request_new_link'],
            'permission_callback' => '__return_true',
            'args' => [
                'email' => [
                    'required' => true,
                    'type' => 'string',
                    'description' => 'User email address',
                    'validate_callback' => function($param) {
                        return is_email($param);
                    },
                    'sanitize_callback' => 'sanitize_email'
                ],
                'redirect_url' => [
                    'required' => false,
                    'type' => 'string',
                    'description' => 'URL to redirect to after login',
                    'sanitize_callback' => 'esc_url_raw'
                ]
            ]
        ]);
    }

    public function api_permission_check() {
        $settings = get_option($this->option_key, []);
        $api_key = isset($settings['api_key']) ? trim($settings['api_key']) : '';
        
        if (empty($api_key)) {
            error_log('Magic Login API: No API key configured');
            return new WP_Error('api_disabled', 'API not enabled - please generate an API key in settings', ['status' => 403]);
        }

        // Support multiple header sources for proxy compatibility
        $auth_header = $_SERVER['HTTP_AUTHORIZATION']
            ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION']
            ?? ($_SERVER['HTTP_X_API_KEY'] ?? '');
        
        // Fallback: some stacks (PHP-FPM, reverse proxies) only populate getallheaders()
        if (empty($auth_header) && function_exists('getallheaders')) {
            $headers = array_change_key_case(getallheaders(), CASE_LOWER);
            if (isset($headers['authorization']) && !$auth_header) {
                $auth_header = $headers['authorization'];
            }
            if (isset($headers['x-api-key']) && !$auth_header) {
                $auth_header = $headers['x-api-key'];
            }
        }
        
        // Normalize and trim
        $auth_header = trim($auth_header);
        
        // Reject empty or whitespace-only headers
        if (empty($auth_header) || ctype_space($auth_header)) {
            error_log('Magic Login API: Missing Authorization header (tried $_SERVER and getallheaders)');
            return new WP_Error('missing_auth', 'Missing Authorization header. Try using X-API-Key header if your proxy strips Authorization.', ['status' => 401]);
        }

        // Support both "Bearer TOKEN" and raw key format
        $token = $auth_header;
        if (preg_match('/^Bearer\s+(.+)$/i', $auth_header, $m)) {
            $token = trim($m[1]);
        }
        
        // Additional cleanup - remove any hidden characters
        $token = preg_replace('/[\x00-\x1F\x7F]/u', '', $token);
        $api_key = preg_replace('/[\x00-\x1F\x7F]/u', '', $api_key);
        
        // Timing-safe comparison - ensure both are same length first
        if (strlen($token) !== strlen($api_key)) {
            error_log('Magic Login API: Key length mismatch - expected ' . strlen($api_key) . ' got ' . strlen($token));
            return new WP_Error('invalid_auth', 'Invalid API key', ['status' => 401]);
        }
        
        if (!hash_equals($api_key, $token)) {
            error_log('Magic Login API: Invalid API key attempt');
            return new WP_Error('invalid_auth', 'Invalid API key', ['status' => 401]);
        }

        return true;
    }

    private function hash_token($token) {
        if (!defined('AUTH_SALT') || empty(AUTH_SALT)) {
            // Fallback if AUTH_SALT not defined (should never happen in proper WP install)
            return hash('sha256', $token . 'sml_fallback_salt_' . NONCE_SALT);
        }
        return hash_hmac('sha256', $token, AUTH_SALT);
    }

    private function ensure_schema() {
        if ($this->schema_checked) {
            return;
        }
        $this->schema_checked = true;

        $current_version = (int) get_option($this->schema_version_option, 0);
        if ($current_version >= self::SCHEMA_VERSION) {
            return;
        }

        global $wpdb;
        $table = $this->table;

        // Check if table exists
        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
            $table
        ));
        
        if (!$exists) {
            // Table doesn't exist, create it
            $this->activate();
            return;
        }

        // Migrate old columns to new schema
        $columns = $wpdb->get_col("SHOW COLUMNS FROM {$table}", 0);
        $altered = false;

        // Handle old 'token' column from v1.x - drop it if it exists
        if (in_array('token', $columns, true)) {
            $wpdb->query("ALTER TABLE {$table} DROP COLUMN token");
            error_log('[SML] Schema migration: Dropped old token column');
            $altered = true;
        }

        if (!in_array('token_hash', $columns, true)) {
            $wpdb->query("ALTER TABLE {$table} ADD COLUMN token_hash CHAR(64) NULL UNIQUE");
            $altered = true;
            error_log('[SML] Schema migration: Added token_hash column');
        }
        
        if (!in_array('user_agent', $columns, true)) {
            $wpdb->query("ALTER TABLE {$table} ADD COLUMN user_agent VARCHAR(255) NULL");
            $altered = true;
            error_log('[SML] Schema migration: Added user_agent column');
        }
        
        if (!in_array('created_at', $columns, true)) {
            $wpdb->query("ALTER TABLE {$table} ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP");
            $altered = true;
            error_log('[SML] Schema migration: Added created_at column');
        }

        // v3: usage limits support
        if (!in_array('use_count', $columns, true)) {
            $wpdb->query("ALTER TABLE {$table} ADD COLUMN use_count INT NOT NULL DEFAULT 0");
            $altered = true;
            error_log('[SML] Schema migration: Added use_count column');
        }
        if (!in_array('max_uses', $columns, true)) {
            $wpdb->query("ALTER TABLE {$table} ADD COLUMN max_uses INT NOT NULL DEFAULT 0");
            $altered = true;
            error_log('[SML] Schema migration: Added max_uses column');
        }

        // Add helpful indexes if missing (suppress errors if they already exist)
        if ($altered) {
            $wpdb->query("ALTER TABLE {$table} ADD INDEX user_idx (user_id)");
            $wpdb->query("ALTER TABLE {$table} ADD INDEX expires_idx (expires_at)");
            $wpdb->query("ALTER TABLE {$table} ADD INDEX token_hash_idx (token_hash)");
            error_log('[SML] Schema migration: Added indexes');
        }

        update_option($this->schema_version_option, self::SCHEMA_VERSION, false);
    }

    private function check_rate_limit($user_id) {
        $key = 'sml_throttle_' . (int)$user_id;
        $limit = 5; // 5 requests
        $window = 60; // per 60 seconds
        
        $data = get_transient($key);
        if ($data === false) {
            $data = ['count' => 0, 'time' => time()];
        }
        
        // Reset if window expired
        if (time() - $data['time'] > $window) {
            $data = ['count' => 0, 'time' => time()];
        }
        
        $data['count']++;
        set_transient($key, $data, $window);
        
        return $data['count'] <= $limit;
    }

    public function api_generate_link(WP_REST_Request $request) {
        // Ensure schema is current before inserting
        $this->ensure_schema();
        
        $user_id = $request->get_param('user_id');
        $email = $request->get_param('email');
        $redirect_url = $request->get_param('redirect_url');

        // Require at least one identifier
        if (empty($user_id) && empty($email)) {
            return new WP_Error('missing_param', 'Either user_id or email is required', ['status' => 400]);
        }

        // Get user
        if (!empty($user_id)) {
            $user = get_user_by('ID', $user_id);
        } else {
            $user = get_user_by('email', $email);
        }

        if (!$user) {
            return new WP_Error('user_not_found', 'User not found', ['status' => 404]);
        }

        // Rate limiting
        if (!$this->check_rate_limit($user->ID)) {
            return new WP_Error('rate_limit', 'Too many requests. Please try again later.', ['status' => 429]);
        }

        // Generate token (plaintext, only returned once)
        global $wpdb;
        $token = bin2hex(random_bytes(32));
        $token_hash = $this->hash_token($token);
        
        $settings = get_option($this->option_key, []);
        // Back-compat: convert legacy expiry_days to new value/unit if needed
        $expiry_value = isset($settings['expiry_value']) ? (int)$settings['expiry_value'] : (isset($settings['expiry_days']) ? (int)$settings['expiry_days'] : 60);
        $expiry_unit = isset($settings['expiry_unit']) ? $settings['expiry_unit'] : 'hours';
        $expiry_value = max(1, $expiry_value);
        switch (strtolower($expiry_unit)) {
            case 'minutes':
                $expiry_seconds = $expiry_value * 60;
                break;
            case 'hours':
                $expiry_seconds = $expiry_value * 3600;
                break;
            default:
                $expiry_seconds = $expiry_value * 24 * 3600; // days
        }
        $max_uses_setting = isset($settings['max_uses']) ? max(0, (int)$settings['max_uses']) : 0;
        
        // Capture IP and User Agent
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 255) : '';
        
        // Store redirect URL if provided
        $redirect_data = !empty($redirect_url) ? esc_url_raw($redirect_url) : '';
        
        // Insert with hashed token
        $insert = $wpdb->insert($this->table, [
            'user_id' => $user->ID,
            'token_hash' => $token_hash,
            'ip_address' => $ip_address,
            'user_agent' => $user_agent,
            'expires_at' => gmdate('Y-m-d H:i:s', time() + $expiry_seconds),
            'use_count' => 0,
            'max_uses' => $max_uses_setting
        ]);

        if (!$insert) {
            global $wpdb;
            $db_error = $wpdb->last_error ?: 'unknown error';
            error_log('[SML] DB insert failed: ' . $db_error);
            return new WP_Error('db_error', 'Failed to create token', [
                'status' => 500,
                'details' => $db_error
            ]);
        }

        // Log the generation
        // For backward compatibility the action still passes days
        $days_equivalent = max(1, (int) ceil($expiry_seconds / (24 * 3600)));
        do_action('sml_token_generated', $user->ID, $days_equivalent, $ip_address);

        $login_url_params = [
            'sml_action' => 'login',
            'sml_token' => $token,
            'sml_user' => $user->ID
        ];
        
        // Add redirect URL to query string if provided
		if (!empty($redirect_url)) {
			$login_url_params['sml_redirect'] = $redirect_url;
		} else {
			// Fallback to configured Return URL
			$return_url_setting = isset($settings['return_url']) && $settings['return_url'] !== '' ? $settings['return_url'] : home_url('/');
			$login_url_params['sml_redirect'] = $return_url_setting;
		}
        
        $login_url = add_query_arg($login_url_params, home_url('/'));

        return new WP_REST_Response([
            'success' => true,
            'user_id' => $user->ID,
            'email' => $user->user_email,
            'token' => $token, // Plaintext returned once
            'login_url' => $login_url,
            'expires_in_seconds' => $expiry_seconds,
            'max_uses' => $max_uses_setting,
            'expires_at' => gmdate('c', time() + $expiry_seconds),
            'redirect_url' => $redirect_data ?: null
        ], 200);
    }

    public function api_verify_token(WP_REST_Request $request) {
        $token = sanitize_text_field($request->get_param('token'));
        $token_hash = $this->hash_token($token);
        
        global $wpdb;
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT user_id, expires_at, created_at FROM {$this->table} WHERE token_hash = %s LIMIT 1",
            $token_hash
        ));

        // Generic response to avoid leaking token validity
        if (!$row || strtotime($row->expires_at) <= time()) {
            return new WP_REST_Response(['valid' => false], 200);
        }

        $user = get_user_by('ID', $row->user_id);
        if (!$user) {
            return new WP_REST_Response(['valid' => false], 200);
        }

        return new WP_REST_Response([
            'valid' => true,
            'user_id' => (int) $row->user_id,
            'expires_at' => $row->expires_at,
            'issued_at' => $row->created_at
        ], 200);
    }

    public function api_revoke_user_tokens(WP_REST_Request $request) {
        $user_id = (int)$request->get_param('user_id');
        
        if (!$user_id) {
            return new WP_Error('invalid_user', 'Invalid user ID', ['status' => 400]);
        }
        
        global $wpdb;
        $deleted = $wpdb->delete($this->table, ['user_id' => $user_id], ['%d']);
        
        do_action('sml_tokens_revoked', $user_id, $deleted);
        
        return new WP_REST_Response([
            'success' => true,
            'revoked_count' => $deleted
        ], 200);
    }

    public function api_request_new_link(WP_REST_Request $request) {
        // Verify nonce for CSRF protection
        $nonce = $request->get_header('X-WP-Nonce');
        if (!$nonce || !wp_verify_nonce($nonce, 'wp_rest')) {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Security check failed. Please refresh the page and try again.'
            ], 403);
        }
        
        // Ensure schema is current before inserting
        $this->ensure_schema();
        
        $email = sanitize_email($request->get_param('email'));
        
        if (empty($email) || !is_email($email)) {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Please provide a valid email address.'
            ], 400);
        }

        // Get user by email
        $user = get_user_by('email', $email);
        
        // For security, always return success message even if user doesn't exist
        // This prevents email enumeration attacks
        if (!$user) {
            // Still return success to prevent user enumeration
            return new WP_REST_Response([
                'success' => true,
                'message' => 'If an account exists with this email, a new login link has been sent.'
            ], 200);
        }

        // Rate limiting - use a generic key to prevent enumeration
        $rate_limit_key = 'sml_request_link_' . md5($email);
        $limit = 3; // 3 requests
        $window = 300; // per 5 minutes
        
        $data = get_transient($rate_limit_key);
        if ($data === false) {
            $data = ['count' => 0, 'time' => time()];
        }
        
        // Reset if window expired
        if (time() - $data['time'] > $window) {
            $data = ['count' => 0, 'time' => time()];
        }
        
        $data['count']++;
        set_transient($rate_limit_key, $data, $window);
        
        if ($data['count'] > $limit) {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Too many requests. Please try again later.'
            ], 429);
        }

        // Apply user-specific rate limiting
        if (!$this->check_rate_limit($user->ID)) {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Too many requests. Please try again later.'
            ], 429);
        }

        // Generate token
        global $wpdb;
        $token = bin2hex(random_bytes(32));
        $token_hash = $this->hash_token($token);
        
        $settings = get_option($this->option_key, []);
        $expiry_value = isset($settings['expiry_value']) ? (int)$settings['expiry_value'] : (isset($settings['expiry_days']) ? (int)$settings['expiry_days'] : 60);
        $expiry_unit = isset($settings['expiry_unit']) ? $settings['expiry_unit'] : 'hours';
        $expiry_value = max(1, $expiry_value);
        switch (strtolower($expiry_unit)) {
            case 'minutes':
                $expiry_seconds = $expiry_value * 60;
                break;
            case 'hours':
                $expiry_seconds = $expiry_value * 3600;
                break;
            default:
                $expiry_seconds = $expiry_value * 24 * 3600; // days
        }
        $max_uses_setting = isset($settings['max_uses']) ? max(0, (int)$settings['max_uses']) : 0;
        
        // Capture IP and User Agent
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 255) : '';
        
        // Get redirect URL - use provided redirect_url or fall back to settings
        $redirect_url = $request->get_param('redirect_url');
        if (empty($redirect_url)) {
            $redirect_url = isset($settings['return_url']) && $settings['return_url'] !== '' ? $settings['return_url'] : home_url('/');
        }
        $redirect_url = esc_url_raw($redirect_url);
        
        // Insert with hashed token
        $insert = $wpdb->insert($this->table, [
            'user_id' => $user->ID,
            'token_hash' => $token_hash,
            'ip_address' => $ip_address,
            'user_agent' => $user_agent,
            'expires_at' => gmdate('Y-m-d H:i:s', time() + $expiry_seconds),
            'use_count' => 0,
            'max_uses' => $max_uses_setting
        ]);

        if (!$insert) {
            error_log('[SML] Failed to create token for email request: ' . $wpdb->last_error);
            return new WP_REST_Response([
                'success' => false,
                'message' => 'An error occurred. Please try again later.'
            ], 500);
        }

        // Log the generation
        $days_equivalent = max(1, (int) ceil($expiry_seconds / (24 * 3600)));
        do_action('sml_token_generated', $user->ID, $days_equivalent, $ip_address);

        // Build login URL
        $login_url_params = [
            'sml_action' => 'login',
            'sml_token' => $token,
            'sml_user' => $user->ID,
            'sml_redirect' => $redirect_url
        ];
        
        $login_url = add_query_arg($login_url_params, home_url('/'));

        // Send email
        $site_name = get_bloginfo('name');
        $site_url = home_url('/');
        $subject = sprintf(__('Your New Login Link for %s', 'magic-api-login'), $site_name);
        
        $expiry_display = '';
        if ($expiry_unit === 'minutes') {
            $expiry_display = $expiry_value . ' ' . ($expiry_value === 1 ? 'minute' : 'minutes');
        } elseif ($expiry_unit === 'hours') {
            $expiry_display = $expiry_value . ' ' . ($expiry_value === 1 ? 'hour' : 'hours');
        } else {
            $expiry_display = $expiry_value . ' ' . ($expiry_value === 1 ? 'day' : 'days');
        }
        
        $max_uses_display = $max_uses_setting > 0 ? sprintf(__('This link can be used up to %d time(s).', 'magic-api-login'), $max_uses_setting) : __('This link can be used multiple times.', 'magic-api-login');
        
        $message = sprintf(
            __("Hello,\n\nYou requested a new login link for %s.\n\nClick the link below to log in:\n\n%s\n\nThis link will expire in %s. %s\n\nIf you didn't request this link, you can safely ignore this email.\n\nBest regards,\n%s", 'magic-api-login'),
            $site_name,
            $login_url,
            $expiry_display,
            $max_uses_display,
            $site_name
        );
        
        $headers = ['Content-Type: text/plain; charset=UTF-8'];
        $sent = wp_mail($user->user_email, $subject, $message, $headers);
        
        if (!$sent) {
            error_log('[SML] Failed to send email for new link request to: ' . $user->user_email);
        }

        do_action('sml_new_link_requested', $user->ID, $email, $sent);

        return new WP_REST_Response([
            'success' => true,
            'message' => 'A new login link has been sent to your email address.'
        ], 200);
    }

    public function activate() {
        global $wpdb;
        $charset = $wpdb->get_charset_collate();
        
        // Updated schema with token_hash, user_agent, and better indexes
        $sql = "CREATE TABLE IF NOT EXISTS {$this->table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id BIGINT(20) UNSIGNED NOT NULL,
            token_hash CHAR(64) NOT NULL UNIQUE,
            ip_address VARCHAR(45),
            user_agent VARCHAR(255),
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            use_count INT NOT NULL DEFAULT 0,
            max_uses INT NOT NULL DEFAULT 0,
            PRIMARY KEY (id),
            KEY user_idx (user_id),
            KEY expires_idx (expires_at),
            KEY token_hash_idx (token_hash)
        ) $charset;";
        
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
        
        // Schedule daily cleanup
        if (!wp_next_scheduled('sml_purge_tokens')) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'sml_purge_tokens');
        }

        update_option($this->schema_version_option, self::SCHEMA_VERSION, false);
    }

    public function deactivate() {
        wp_clear_scheduled_hook('sml_purge_tokens');
    }

    public function purge_expired_tokens() {
        global $wpdb;
        $deleted = $wpdb->query("DELETE FROM {$this->table} WHERE expires_at <= NOW()");
        do_action('sml_tokens_purged', $deleted);
    }

    public static function safe_redirect($raw_redirect) {
        if (empty($raw_redirect)) {
            return admin_url();
        }
        
        // Only allow same-host redirects
        $site_host = wp_parse_url(home_url('/'), PHP_URL_HOST);
        
        add_filter('allowed_redirect_hosts', function($hosts) use ($site_host) {
            if (!in_array($site_host, $hosts)) {
                $hosts[] = $site_host;
            }
            return array_unique($hosts);
        });
        
        $validated = wp_validate_redirect(esc_url_raw($raw_redirect), admin_url());
        return $validated;
    }

	/**
	 * Output a modern, branded error page for login link issues.
	 */
	private static function render_login_error_page($title, $message, $show_request_form = false) {
		header('Content-Type: text/html; charset=utf-8');
		$home = esc_url(home_url('/'));
		$title_esc = esc_html($title);
		$message_esc = esc_html($message);
		$site_name = esc_html(get_bloginfo('name'));
		$rest_url = esc_url(rest_url('magic-login/v1/request-new-link'));
		$nonce = wp_create_nonce('wp_rest');
		
		$form_html = '';
		if ($show_request_form) {
			$form_html = '<div class="request-form" style="margin-top:24px;padding-top:24px;border-top:1px solid #e2e8f0"><h2 style="font-size:18px;margin:0 0 12px">Request a New Login Link</h2><p style="margin:0 0 16px;color:var(--muted);font-size:14px">Enter your email address and we\'ll send you a new login link.</p><form id="request-link-form" style="display:flex;flex-direction:column;gap:12px"><input type="email" id="request-email" placeholder="your@email.com" required style="width:100%;padding:12px 16px;border:1px solid #cbd5e1;border-radius:12px;font-size:15px;background:#fff" /><button type="submit" id="request-submit" style="background:var(--primary);color:#fff;border:none;padding:12px 24px;border-radius:12px;font-size:15px;font-weight:600;cursor:pointer;transition:background 0.2s">Send New Link</button></form><div id="request-message" style="margin-top:12px;padding:12px;border-radius:8px;display:none"></div></div>';
		}
		
		echo "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{$title_esc} – {$site_name}</title><style>
			:root{--bg:#f8fafc;--card:#ffffff;--text:#0f172a;--muted:#475569;--primary:#4f46e5;--ring:rgba(99,102,241,.15)}
			*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
			.container{min-height:100vh;display:grid;place-items:center;padding:32px}
			.card{background:var(--card);max-width:720px;width:100%;border:1px solid #e2e8f0;border-radius:16px;padding:32px;box-shadow:0 20px 45px rgba(15,23,42,.08)}
			.icon{width:56px;height:56px;border-radius:14px;display:grid;place-items:center;background:rgba(239,68,68,.08);color:#ef4444;margin-bottom:16px}
			h1{font-size:22px;margin:0 0 8px}
			p{margin:0 0 18px;color:var(--muted)}
			.actions{margin-top:12px}
			.btn{display:inline-block;background:var(--text);color:#fff;text-decoration:none;padding:10px 16px;border-radius:12px}
			.btn:hover{background:#1e293b}
			#request-link-form input:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px var(--ring)}
			#request-submit:hover{background:#4338ca}
			#request-submit:disabled{opacity:0.6;cursor:not-allowed}
			.request-form h2{color:var(--text)}
		</style></head><body><div class=\"container\"><div class=\"card\"><div class=\"icon\" aria-hidden=\"true\">⚠️</div><h1>{$title_esc}</h1><p>{$message_esc}</p><div class=\"actions\"><a class=\"btn\" href=\"{$home}\">Back to homepage</a></div>{$form_html}</div></div><script>
		(function() {
			var form = document.getElementById('request-link-form');
			if (!form) return;
			var emailInput = document.getElementById('request-email');
			var submitBtn = document.getElementById('request-submit');
			var messageDiv = document.getElementById('request-message');
			
			form.addEventListener('submit', function(e) {
				e.preventDefault();
				var email = emailInput.value.trim();
				if (!email) return;
				
				submitBtn.disabled = true;
				submitBtn.textContent = 'Sending...';
				messageDiv.style.display = 'none';
				
				fetch('{$rest_url}', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'X-WP-Nonce': '{$nonce}'
					},
					body: JSON.stringify({email: email})
				})
				.then(function(response) { return response.json(); })
				.then(function(data) {
					submitBtn.disabled = false;
					submitBtn.textContent = 'Send New Link';
					messageDiv.style.display = 'block';
					
					if (data.success) {
						messageDiv.style.background = '#d1fae5';
						messageDiv.style.color = '#065f46';
						messageDiv.style.border = '1px solid #86efac';
						messageDiv.textContent = '✓ A new login link has been sent to your email address. Please check your inbox.';
						emailInput.value = '';
					} else {
						messageDiv.style.background = '#fee2e2';
						messageDiv.style.color = '#991b1b';
						messageDiv.style.border = '1px solid #fca5a5';
						messageDiv.textContent = data.message || 'An error occurred. Please try again later.';
					}
				})
				.catch(function(error) {
					submitBtn.disabled = false;
					submitBtn.textContent = 'Send New Link';
					messageDiv.style.display = 'block';
					messageDiv.style.background = '#fee2e2';
					messageDiv.style.color = '#991b1b';
					messageDiv.style.border = '1px solid #fca5a5';
					messageDiv.textContent = 'An error occurred. Please try again later.';
				});
			});
		})();
		</script></body></html>";
	}

    public static function verify_and_login() {
        if (empty($_GET['sml_action']) || $_GET['sml_action'] !== 'login') return;
        if (empty($_GET['sml_token']) || empty($_GET['sml_user'])) return;

        // If processing POST, do the actual login
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['sml_process'])) {
            self::process_login();
            return;
        }

        // Otherwise, show loading page that will process login
        self::render_loading_page();
        exit;
    }

    /**
     * Render a loading page that processes login in background
     */
    private static function render_loading_page() {
        $token = sanitize_text_field($_GET['sml_token']);
        $user_id = (int)$_GET['sml_user'];
        $redirect = isset($_GET['sml_redirect']) ? esc_url_raw($_GET['sml_redirect']) : '';
        $site_name = esc_html(get_bloginfo('name'));
        $current_url = esc_url(add_query_arg([
            'sml_action' => 'login',
            'sml_token' => $token,
            'sml_user' => $user_id,
            'sml_redirect' => $redirect
        ], home_url('/')));
        
        header('Content-Type: text/html; charset=utf-8');
        echo "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Logging you in – {$site_name}</title><style>
			:root{--bg:#f8fafc;--card:#ffffff;--text:#0f172a;--muted:#475569;--primary:#4f46e5}
			*{box-sizing:border-box;margin:0;padding:0}
			body{background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;min-height:100vh;display:grid;place-items:center;padding:32px}
			.card{background:var(--card);max-width:480px;width:100%;border:1px solid #e2e8f0;border-radius:16px;padding:48px 32px;box-shadow:0 20px 45px rgba(15,23,42,.08);text-align:center}
			.spinner{width:48px;height:48px;border:4px solid #e2e8f0;border-top-color:var(--primary);border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto 24px}
			@keyframes spin{to{transform:rotate(360deg)}}
			h1{font-size:20px;margin:0 0 8px;color:var(--text)}
			p{color:var(--muted);font-size:15px;margin:0}
		</style></head><body><div class=\"card\"><div class=\"spinner\" aria-hidden=\"true\"></div><h1>Logging you in...</h1><p>Please wait while we sign you in.</p></div>
		<form id=\"login-form\" method=\"post\" action=\"{$current_url}\" style=\"display:none\">
			<input type=\"hidden\" name=\"sml_process\" value=\"1\">
			<input type=\"hidden\" name=\"sml_token\" value=\"" . esc_attr($token) . "\">
			<input type=\"hidden\" name=\"sml_user\" value=\"" . esc_attr($user_id) . "\">
			" . ($redirect ? '<input type="hidden" name="sml_redirect" value="' . esc_attr($redirect) . '">' : '') . "
		</form>
		<script>
		// Immediately submit form to process login
		(function() {
			var form = document.getElementById('login-form');
			if (form) {
				// Small delay to ensure page is rendered
				setTimeout(function() {
					form.submit();
				}, 50);
			}
		})();
		</script></body></html>";
    }

    /**
     * Process the actual login
     */
    private static function process_login() {
        // Get token from POST or GET
        $token = isset($_POST['sml_token']) ? sanitize_text_field($_POST['sml_token']) : sanitize_text_field($_GET['sml_token']);
        $user_id = isset($_POST['sml_user']) ? (int)$_POST['sml_user'] : (int)$_GET['sml_user'];
        
        if (empty($token) || empty($user_id)) {
            self::render_login_error_page('Invalid link', 'This login link is invalid. Please request a new one.');
            exit;
        }

        global $wpdb;
        $table = $wpdb->prefix . 'magic_login_tokens';
        
        // Hash the token for comparison
        if (!defined('AUTH_SALT') || empty(AUTH_SALT)) {
            $token_hash = hash('sha256', $token . 'sml_fallback_salt_' . NONCE_SALT);
        } else {
            $token_hash = hash_hmac('sha256', $token, AUTH_SALT);
        }
        
        // Optimized single query - check expiry in SQL (faster than PHP)
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT id, user_id, ip_address, expires_at, use_count, max_uses FROM {$table} 
             WHERE token_hash = %s AND user_id = %d AND expires_at > NOW() LIMIT 1",
            $token_hash, $user_id
        ), ARRAY_A);
        
        if (!$row) {
            self::render_login_error_page('Link expired', 'This magic login link has expired. Please request a new one.');
            exit;
        }

        // Enforce usage limits
        if ($row['max_uses'] > 0 && (int)$row['use_count'] >= (int)$row['max_uses']) {
            self::render_login_error_page('Link limit reached', 'This login link has reached its maximum allowed uses. Please request a new one.', true);
            exit;
        }

        // Get user - use direct query to avoid loading user meta unnecessarily
        $user = $wpdb->get_row($wpdb->prepare(
            "SELECT ID, user_login FROM {$wpdb->users} WHERE ID = %d LIMIT 1",
            $user_id
        ));
        
        if (!$user) {
            wp_die('User not found');
        }
        
        // Capture current IP and UA for security logging
        $current_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $current_ua = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 255) : '';
        
        // Increment use count atomically in database
        $wpdb->query($wpdb->prepare(
            "UPDATE {$table} SET use_count = use_count + 1 WHERE id = %d",
            $row['id']
        ));
        
        // Get redirect URL BEFORE login (faster, avoids loading user meta)
        $raw_redirect = isset($_POST['sml_redirect']) ? $_POST['sml_redirect'] : (isset($_GET['sml_redirect']) ? $_GET['sml_redirect'] : '');
        if ($raw_redirect === '') {
            // Cache settings lookup to avoid repeated get_option calls
            static $cached_settings = null;
            if ($cached_settings === null) {
                $cached_settings = get_option('sml_settings', []);
            }
            $raw_redirect = isset($cached_settings['return_url']) && $cached_settings['return_url'] !== '' ? $cached_settings['return_url'] : home_url('/');
        }
        $redirect_url = self::fast_redirect($raw_redirect);
        
        // Log in user with "Remember Me" enabled for persistent sessions
        wp_set_auth_cookie($user_id, true);
        wp_set_current_user($user_id);
        
        // Defer slow hooks to avoid blocking redirect
        // Use spawn_cron to trigger immediately if possible, otherwise schedule
        $hook_args = [$user->user_login, $user_id, $current_ip, $current_ua, $row['ip_address']];
        wp_schedule_single_event(time(), 'sml_deferred_login_hooks', $hook_args);
        
        // Try to spawn cron immediately (non-blocking)
        if (function_exists('spawn_cron')) {
            spawn_cron();
        }
        
        // Use wp_redirect for speed (we've already validated the URL)
        wp_redirect($redirect_url, 302);
        exit;
    }
    
    /**
     * Fast redirect validation without dynamic filter overhead
     * Pre-validates URL to avoid wp_safe_redirect filter processing
     */
    private static function fast_redirect($raw_redirect) {
        if (empty($raw_redirect)) {
            return admin_url();
        }
        
        $parsed = wp_parse_url($raw_redirect);
        $site_host = wp_parse_url(home_url('/'), PHP_URL_HOST);
        
        // Only allow same-host redirects (security check)
        if (isset($parsed['host']) && $parsed['host'] !== $site_host) {
            return admin_url();
        }
        
        // Validate and sanitize URL
        $validated = esc_url_raw($raw_redirect);
        return $validated ?: admin_url();
    }

    /**
     * Render shortcode for magic login email form
     * Usage: [magic_login_form]
     * 
     * @param array $atts Shortcode attributes
     * @return string HTML form
     */
    public function render_login_form_shortcode($atts = []) {
        $atts = shortcode_atts([
            'title' => 'Request Login Link',
            'description' => 'Enter your email address and we\'ll send you a magic login link.',
            'button_text' => 'Send Login Link',
            'placeholder' => 'your@email.com',
            'redirect_url' => ''
        ], $atts, 'magic_login_form');
        
        $rest_url = esc_url(rest_url('magic-login/v1/request-new-link'));
        $nonce = wp_create_nonce('wp_rest');
        $redirect = !empty($atts['redirect_url']) ? esc_attr($atts['redirect_url']) : '';
        
        ob_start();
        ?>
        <div class="sml-login-form-container" style="max-width:480px;margin:0 auto;padding:24px;background:#ffffff;border:1px solid #e2e8f0;border-radius:16px;box-shadow:0 4px 6px rgba(0,0,0,0.1)">
            <?php if (!empty($atts['title'])): ?>
                <h3 style="margin:0 0 12px;font-size:20px;color:#0f172a"><?php echo esc_html($atts['title']); ?></h3>
            <?php endif; ?>
            <?php if (!empty($atts['description'])): ?>
                <p style="margin:0 0 20px;color:#475569;font-size:14px"><?php echo esc_html($atts['description']); ?></p>
            <?php endif; ?>
            <form class="sml-login-form" style="display:flex;flex-direction:column;gap:12px">
                <input 
                    type="email" 
                    name="email" 
                    class="sml-email-input" 
                    placeholder="<?php echo esc_attr($atts['placeholder']); ?>" 
                    required 
                    style="width:100%;padding:12px 16px;border:1px solid #cbd5e1;border-radius:12px;font-size:15px;background:#fff;box-sizing:border-box"
                />
                <?php if ($redirect): ?>
                    <input type="hidden" name="redirect_url" value="<?php echo esc_attr($redirect); ?>" />
                <?php endif; ?>
                <button 
                    type="submit" 
                    class="sml-submit-btn" 
                    style="background:#4f46e5;color:#fff;border:none;padding:12px 24px;border-radius:12px;font-size:15px;font-weight:600;cursor:pointer;transition:background 0.2s"
                >
                    <?php echo esc_html($atts['button_text']); ?>
                </button>
            </form>
            <div class="sml-form-message" style="margin-top:12px;padding:12px;border-radius:8px;display:none"></div>
        </div>
        <style>
            .sml-login-form-container .sml-email-input:focus {
                outline:none;
                border-color:#4f46e5;
                box-shadow:0 0 0 3px rgba(79,70,229,0.15);
            }
            .sml-login-form-container .sml-submit-btn:hover {
                background:#4338ca;
            }
            .sml-login-form-container .sml-submit-btn:disabled {
                opacity:0.6;
                cursor:not-allowed;
            }
        </style>
        <script>
        (function() {
            var form = document.querySelector('.sml-login-form');
            if (!form) return;
            
            var emailInput = form.querySelector('.sml-email-input');
            var submitBtn = form.querySelector('.sml-submit-btn');
            var messageDiv = form.parentElement.querySelector('.sml-form-message');
            var originalBtnText = submitBtn.textContent;
            
            form.addEventListener('submit', function(e) {
                e.preventDefault();
                var email = emailInput.value.trim();
                if (!email) return;
                
                submitBtn.disabled = true;
                submitBtn.textContent = 'Sending...';
                messageDiv.style.display = 'none';
                
                var formData = {
                    email: email
                };
                
                <?php if ($redirect): ?>
                formData.redirect_url = '<?php echo esc_js($redirect); ?>';
                <?php endif; ?>
                
                fetch('<?php echo esc_url($rest_url); ?>', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-WP-Nonce': '<?php echo esc_js($nonce); ?>'
                    },
                    body: JSON.stringify(formData)
                })
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalBtnText;
                    messageDiv.style.display = 'block';
                    
                    if (data.success) {
                        messageDiv.style.background = '#d1fae5';
                        messageDiv.style.color = '#065f46';
                        messageDiv.style.border = '1px solid #86efac';
                        messageDiv.textContent = '✓ A login link has been sent to your email address. Please check your inbox.';
                        emailInput.value = '';
                    } else {
                        messageDiv.style.background = '#fee2e2';
                        messageDiv.style.color = '#991b1b';
                        messageDiv.style.border = '1px solid #fca5a5';
                        messageDiv.textContent = data.message || 'An error occurred. Please try again later.';
                    }
                })
                .catch(function(error) {
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalBtnText;
                    messageDiv.style.display = 'block';
                    messageDiv.style.background = '#fee2e2';
                    messageDiv.style.color = '#991b1b';
                    messageDiv.style.border = '1px solid #fca5a5';
                    messageDiv.textContent = 'An error occurred. Please try again later.';
                });
            });
        })();
        </script>
        <?php
        return ob_get_clean();
    }

    public function add_settings_page() {
        add_submenu_page(
            'options-general.php',
            'Magic API Login Settings',
            'Magic API Login',
            'manage_options',
            'sml-settings',
            [$this, 'render_settings_page']
        );
    }

    public function register_settings() {
        register_setting('sml_settings', $this->option_key, [
            'type' => 'array',
            'sanitize_callback' => [$this, 'sanitize_settings']
        ]);
    }

    public function sanitize_settings($input) {
        $output = [];
        
        // Preserve or accept API key
        $existing = get_option($this->option_key, []);
		if (isset($input['api_key']) && is_string($input['api_key'])) {
			$candidate = trim($input['api_key']);
			// Accept newly generated 64-char hex keys
			if ($candidate !== '' && preg_match('/^[a-f0-9]{64}$/i', $candidate)) {
				$output['api_key'] = strtolower($candidate);
			} elseif (isset($existing['api_key']) && !empty($existing['api_key'])) {
				// On invalid candidate, fall back to existing key if present
				$output['api_key'] = $existing['api_key'];
			}
		} elseif (isset($existing['api_key']) && !empty($existing['api_key'])) {
			// When no key provided in input (e.g., saving other settings), keep existing
			$output['api_key'] = $existing['api_key'];
		}
		
        // Return URL (default to home URL, preserve if missing)
		$default_return = home_url('/');
		if (isset($input['return_url'])) {
			$raw = trim((string)$input['return_url']);
			$sanitized = $raw !== '' ? esc_url_raw($raw) : '';
			$output['return_url'] = $sanitized !== '' ? $sanitized : $default_return;
		} elseif (isset($existing['return_url']) && $existing['return_url'] !== '') {
			$output['return_url'] = $existing['return_url'];
		} else {
			$output['return_url'] = $default_return;
		}
        
        // Expiry settings: value + unit (minutes | hours | days)
        $allowed_units = ['minutes', 'hours', 'days'];
        if (isset($input['expiry_value'])) {
            $output['expiry_value'] = max(1, (int)$input['expiry_value']);
        } elseif (isset($existing['expiry_value'])) {
            $output['expiry_value'] = max(1, (int)$existing['expiry_value']);
        } elseif (isset($existing['expiry_days'])) {
            // Back-compat for older installs
            $output['expiry_value'] = max(1, (int)$existing['expiry_days']);
        } else {
            $output['expiry_value'] = 1; // default 1 hour
        }
        
        if (isset($input['expiry_unit'])) {
            $unit = strtolower((string)$input['expiry_unit']);
            $output['expiry_unit'] = in_array($unit, $allowed_units, true) ? $unit : 'hours';
        } elseif (isset($existing['expiry_unit']) && in_array(strtolower((string)$existing['expiry_unit']), $allowed_units, true)) {
            $output['expiry_unit'] = strtolower((string)$existing['expiry_unit']);
        } else {
            $output['expiry_unit'] = 'hours';
        }
        
        // Maximum uses: 0 for unlimited
        if (isset($input['max_uses'])) {
            $output['max_uses'] = max(0, (int)$input['max_uses']);
        } elseif (isset($existing['max_uses'])) {
            $output['max_uses'] = max(0, (int)$existing['max_uses']);
        } else {
            $output['max_uses'] = 0;
        }
		
		return $output;
    }

    public function user_profile_revoke_section($user) {
        global $wpdb;
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->table} WHERE user_id = %d AND expires_at > NOW()",
            $user->ID
        ));
        
        ?>
        <h2>Magic Login Links</h2>
        <table class="form-table">
            <tr>
                <th><label>Active Links</label></th>
                <td>
                    <p>You currently have <strong><?php echo (int)$count; ?></strong> active magic login link(s).</p>
                    <?php if ($count > 0): ?>
                        <p class="description">If you believe your magic links have been compromised, you can revoke all of them.</p>
                    <?php endif; ?>
                </td>
            </tr>
        </table>
        <?php if ($count > 0): ?>
            <table class="form-table">
                <tr>
                    <th></th>
                    <td>
                        <button type="submit" name="sml_revoke_all" class="button button-secondary" 
                                onclick="return confirm('Are you sure you want to revoke all your magic login links? This cannot be undone.');">
                            Revoke All My Magic Links
                        </button>
                    </td>
                </tr>
            </table>
        <?php endif;
    }

    public function handle_user_revoke($user_id) {
        if (!isset($_POST['sml_revoke_all'])) {
            return;
        }
        
        // Security check
        if (!current_user_can('edit_user', $user_id)) {
            return;
        }
        
        global $wpdb;
        $deleted = $wpdb->delete($this->table, ['user_id' => $user_id], ['%d']);
        
        if ($deleted !== false) {
            add_action('admin_notices', function() use ($deleted) {
                echo '<div class="updated"><p>Successfully revoked ' . (int)$deleted . ' magic login link(s).</p></div>';
            });
            do_action('sml_user_tokens_revoked', $user_id, $deleted);
        }
    }

    public function render_settings_page() {
        // Handle API key generation FIRST before getting settings
        if (isset($_POST['sml_generate_api_key'])) {
            if (!current_user_can('manage_options')) {
                wp_die('Insufficient permissions');
            }
            if (!isset($_POST['sml_generate_api_key_nonce']) || !wp_verify_nonce($_POST['sml_generate_api_key_nonce'], 'sml_generate_api_key')) {
                wp_die('Nonce verification failed');
            }
            $new_key = bin2hex(random_bytes(32));
            $current_settings = get_option($this->option_key, []);
            $current_settings['api_key'] = $new_key;
            update_option($this->option_key, $current_settings, false);
            echo '<div class="updated"><p>✓ New API key generated successfully</p></div>';
        }
        
        // Now get fresh settings after potential update
        $settings = get_option($this->option_key, []);
        // Back-compat: compute display values
        $expiry_value = isset($settings['expiry_value']) ? (int)$settings['expiry_value'] : (isset($settings['expiry_days']) ? (int)$settings['expiry_days'] : 1);
        $expiry_unit = isset($settings['expiry_unit']) ? $settings['expiry_unit'] : 'hours';
        $max_uses = isset($settings['max_uses']) ? (int)$settings['max_uses'] : 0;
		$api_key = isset($settings['api_key']) ? $settings['api_key'] : '';
		$return_url = isset($settings['return_url']) ? $settings['return_url'] : home_url('/');
        
        $api_endpoint = rest_url('magic-login/v1/generate-link');
        ?>
        <div class="wrap">
            <h1>Magic API Login Settings</h1>

            <style>
                .sml-settings-page {
                    max-width: 1100px;
                    margin-top: 24px;
                }

                .sml-grid {
                    display: grid;
                    gap: 24px;
                    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                }

                .sml-card {
                    background: #ffffff;
                    border-radius: 16px;
                    padding: 24px;
                    border: 1px solid #e2e8f0;
                    box-shadow: 0 20px 45px rgba(15, 23, 42, 0.08);
                }

                .sml-card--full {
                    grid-column: 1 / -1;
                }

                .sml-card--highlight {
                    background: linear-gradient(135deg, #1e293b, #0f172a);
                    color: #fff;
                    border: none;
                    box-shadow: 0 25px 50px rgba(15, 23, 42, 0.35);
                }

                .sml-card--highlight p {
                    color: rgba(255, 255, 255, 0.85);
                    margin: 0;
                }

                .sml-badge {
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                    padding: 6px 14px;
                    border-radius: 999px;
                    background: rgba(255, 255, 255, 0.12);
                    color: #fff;
                    font-size: 12px;
                    letter-spacing: 0.08em;
                    text-transform: uppercase;
                }

                .sml-card-subtitle {
                    margin-top: 6px;
                    margin-bottom: 24px;
                    color: #64748b;
                }

                .sml-stack {
                    display: flex;
                    flex-direction: column;
                    gap: 18px;
                }

                .sml-field label {
                    display: block;
                    font-weight: 600;
                    margin-bottom: 6px;
                    color: #1f2937;
                }

                .sml-field input[type="text"],
                .sml-field input[type="number"] {
                    width: 100%;
                    padding: 10px 14px;
                    border-radius: 12px;
                    border: 1px solid #cbd5f5;
                    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
                    background: #f8fafc;
                    color: #0f172a;
                }

                .sml-field input[type="number"] {
                    font-family: inherit;
                }

                .sml-field input:focus {
                    border-color: #4f46e5;
                    box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15);
                    outline: none;
                    background: #fff;
                }

                .sml-input-group {
                    display: flex;
                    gap: 10px;
                }

                .sml-input-group input {
                    flex: 1;
                }

                .sml-copy {
                    border-radius: 12px;
                    padding: 0 16px;
                    line-height: 34px;
                    background: #0f172a;
                    color: #fff;
                    border: none;
                }

                .sml-copy:hover {
                    background: #1e293b;
                    color: #fff;
                }

                .sml-primary,
                .sml-secondary {
                    border-radius: 12px !important;
                    padding: 0 24px !important;
                    line-height: 42px !important;
                }

                .sml-meta {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 12px;
                    align-items: center;
                    color: #475569;
                    font-size: 13px;
                    margin-bottom: 18px;
                }

                .sml-pill {
                    background: #e0e7ff;
                    border-radius: 999px;
                    padding: 6px 12px;
                    font-weight: 600;
                    color: #4338ca;
                }

                .sml-empty-state {
                    background: #f8fafc;
                    border-radius: 12px;
                    padding: 16px;
                    color: #475569;
                    font-weight: 500;
                }

                .sml-inline-form {
                    margin-top: 18px;
                    display: flex;
                    flex-direction: column;
                    gap: 10px;
                }

                .sml-inline-form .description {
                    margin: 0;
                    color: #64748b;
                }

                .sml-card pre {
                    background: #0f172a;
                    color: #e2e8f0;
                    border-radius: 14px;
                    padding: 16px;
                    font-size: 12px;
                    line-height: 1.5;
                    box-shadow: inset 0 0 0 1px rgba(148, 163, 184, 0.12);
                    overflow-x: auto;
                }

                .sml-card code {
                    background: rgba(15, 23, 42, 0.08);
                    padding: 2px 6px;
                    border-radius: 6px;
                }

                .sml-card ul,
                .sml-list {
                    color: #475569;
                }

                .sml-list {
                    margin: 0;
                    padding-left: 18px;
                }

                .sml-card h3 {
                    margin-top: 28px;
                    color: #0f172a;
                }

                .sml-card h4 {
                    margin-top: 20px;
                    color: #1f2937;
                }

                @media (max-width: 600px) {
                    .sml-input-group {
                        flex-direction: column;
                    }

                    .sml-card {
                        padding: 20px;
                    }

                    .sml-primary,
                    .sml-secondary {
                        width: 100%;
                        text-align: center;
                    }
                }
            </style>

            <div class="sml-settings-page">
                <div class="sml-grid">
                    <section class="sml-card sml-card--highlight sml-card--full">
                        <span class="sml-badge">Security Hardened v2.0</span>
                        <p>Tokens are hashed at rest, rate-limited, and automatically purged while links remain reusable throughout the expiry window.</p>
                    </section>

                    <section class="sml-card">
                        <h2>Link Settings</h2>
                        <p class="sml-card-subtitle">Control how long passwordless links stay valid for your users.</p>
                        <form method="post" action="options.php" class="sml-stack">
                            <?php settings_fields('sml_settings'); ?>
                            <div class="sml-field">
                                <label for="sml_expiry_value">Link Expiry</label>
                                <div class="sml-input-group">
                                    <input type="number" id="sml_expiry_value" name="<?php echo $this->option_key; ?>[expiry_value]" value="<?php echo esc_attr($expiry_value); ?>" min="1">
                                    <select id="sml_expiry_unit" name="<?php echo $this->option_key; ?>[expiry_unit]">
                                        <?php $units = ['minutes' => 'Minutes', 'hours' => 'Hour(s)', 'days' => 'Day(s)'];
                                        foreach ($units as $value => $label): ?>
                                            <option value="<?php echo esc_attr($value); ?>" <?php selected($expiry_unit, $value); ?>><?php echo esc_html($label); ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <p class="description">How long a generated link remains valid. Default: 1 Hour.</p>
                            </div>
                            <div class="sml-field">
                                <label for="sml_max_uses">Max Uses</label>
                                <input type="number" id="sml_max_uses" name="<?php echo $this->option_key; ?>[max_uses]" value="<?php echo esc_attr($max_uses); ?>" min="0">
                                <p class="description">How many times a generated link can be used. Use 0 for unlimited.</p>
                            </div>
							<div class="sml-field">
								<label for="sml_return_url">Return URL</label>
								<input type="text" id="sml_return_url" name="<?php echo $this->option_key; ?>[return_url]" value="<?php echo esc_attr($return_url); ?>">
								<p class="description">Where to send the user after successful login. Default: <?php echo esc_html(home_url('/')); ?></p>
							</div>
                            <?php submit_button('Save Changes', 'primary', 'submit', false, ['class' => 'sml-primary']); ?>
                        </form>
                    </section>

                    <section class="sml-card">
                        <h2>API Access</h2>
                        <p class="sml-card-subtitle">Generate magic login links from automations or external services.</p>
                        <div class="sml-meta">
                            <span class="sml-pill">Rate limit · 5 requests/minute per user</span>
                        </div>
                        <?php if ($api_key): ?>
                            <div class="sml-field">
                                <label for="sml-api-key">API Key</label>
                                <div class="sml-input-group">
                                    <input type="text" readonly value="<?php echo esc_attr($api_key); ?>" id="sml-api-key">
                                    <button type="button" class="button sml-copy" onclick="navigator.clipboard.writeText(document.getElementById('sml-api-key').value); this.textContent='Copied'; setTimeout(() => this.textContent='Copy', 1800);">Copy</button>
                                </div>
                                <p class="description">Keep the 64-character key private—anyone with it can generate login links.</p>
                            </div>
                        <?php else: ?>
                            <div class="sml-empty-state">
                                <strong>No API key yet.</strong> Generate one below to enable external requests.
                            </div>
                        <?php endif; ?>
                        <div class="sml-field">
                            <label for="sml-api-endpoint">API Endpoint</label>
                            <input type="text" readonly value="<?php echo esc_attr($api_endpoint); ?>" id="sml-api-endpoint">
                        </div>
						<form method="post" class="sml-inline-form" onsubmit="return confirm('Generate a new API key? The old key will stop working immediately.');">
							<?php wp_nonce_field('sml_generate_api_key', 'sml_generate_api_key_nonce'); ?>
							<button type="submit" name="sml_generate_api_key" class="button button-secondary sml-secondary">
								Generate New API Key
							</button>
							<p class="description">Regenerating immediately revokes the previous key.</p>
						</form>
                    </section>

                    <section class="sml-card sml-card--full">
                        <h2>Shortcode</h2>
                        <p class="sml-card-subtitle">Display a login form on any page or post using the shortcode.</p>
                        
                        <h3>Basic Usage</h3>
                        <p>Add the shortcode to any page or post:</p>
                        <pre>[magic_login_form]</pre>
                        
                        <h3>Customization Options</h3>
                        <p>You can customize the form with these attributes:</p>
                        <pre>[magic_login_form title="Get Your Login Link" description="Enter your email to receive a magic login link." button_text="Send Link" placeholder="email@example.com" redirect_url="/dashboard"]</pre>
                        
                        <h4>Available Attributes</h4>
                        <ul class="sml-list">
                            <li><strong>title</strong> - Form title (default: "Request Login Link")</li>
                            <li><strong>description</strong> - Description text below the title</li>
                            <li><strong>button_text</strong> - Submit button text (default: "Send Login Link")</li>
                            <li><strong>placeholder</strong> - Email input placeholder (default: "your@email.com")</li>
                            <li><strong>redirect_url</strong> - Where to redirect after login (optional, uses Return URL setting if not provided)</li>
                        </ul>
                        
                        <h3>Example</h3>
                        <pre>[magic_login_form title="Login to Your Account" redirect_url="/my-account"]</pre>
                        
                        <p class="description" style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #e2e8f0;">
                            <strong>Note:</strong> The form uses the same security features as the API, including rate limiting and CSRF protection. Users will receive an email with their magic login link.
                        </p>
                    </section>

                    <section class="sml-card sml-card--full">
                        <h2>Troubleshooting</h2>
                        <p class="sml-card-subtitle">Quick checks when you encounter 401 responses or “Invalid API Key” errors.</p>
                        <ol class="sml-list">
                            <li><strong>Confirm the length:</strong> The key should contain exactly 64 characters.</li>
                            <li><strong>Copy cleanly:</strong> Use the copy button to avoid hidden whitespace or trailing breaks.</li>
                            <li><strong>Send the right header:</strong> Prefer <code>Authorization: Bearer YOUR_KEY</code>.</li>
                            <li><strong>Fallback header:</strong> If proxies strip Authorization, send <code>X-API-Key: YOUR_KEY</code>.</li>
                            <li><strong>Inspect logs:</strong> Look for “Magic Login API” entries in <code>debug.log</code>.</li>
                            <li><strong>Rotate if unsure:</strong> Generate a new key and update your integrations.</li>
                        </ol>

                        <h3>Test with cURL</h3>
                        <div class="sml-stack">
                            <div>
                                <h4>Authorization header</h4>
								<pre>curl -X POST "<?php echo esc_attr($api_endpoint); ?>" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com"}'</pre>
                            </div>
                            <div>
                                <h4>X-API-Key header</h4>
								<pre>curl -X POST "<?php echo esc_attr($api_endpoint); ?>" \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com"}'</pre>
                            </div>
                        </div>

                        <h4>Nginx / proxy tip</h4>
                        <pre># FastCGI / PHP-FPM
fastcgi_param HTTP_AUTHORIZATION $http_authorization;

# Reverse proxy
proxy_set_header Authorization $http_authorization;</pre>
                    </section>

                    <section class="sml-card sml-card--full">
                        <h2>Security Features (v2.0)</h2>
                        <ul>
                            <li>✅ <strong>Hashed tokens:</strong> Stored using <code>AUTH_SALT</code> for defense in depth.</li>
                            <li>✅ <strong>Rate limiting:</strong> 5 requests per minute per user to stop brute-force attempts.</li>
                            <li>✅ <strong>IP &amp; user-agent logging:</strong> Track when and where tokens are generated or redeemed.</li>
                            <li>✅ <strong>Auto-purge:</strong> Expired tokens are cleaned up every day.</li>
                            <li>✅ <strong>Same-host redirects:</strong> Blocks open redirect exploits.</li>
                            <li>✅ <strong>Session cookies:</strong> Defaults to short-lived session authentication.</li>
                            <li>✅ <strong>User revocation:</strong> Users can revoke links from their WordPress profile.</li>
                        </ul>
                    </section>

                    <section class="sml-card sml-card--full">
                        <h2>API Documentation</h2>

                        <h3>Generate Magic Login Link</h3>
                        <p><strong>Endpoint:</strong> <code>POST <?php echo esc_attr($api_endpoint); ?></code></p>
                        <p><strong>Authentication:</strong> <code>Authorization: Bearer YOUR_API_KEY</code> or <code>X-API-Key: YOUR_API_KEY</code></p>

                        <h4>Request</h4>
                        <pre>{
  "user_id": 1,
  "email": "user@example.com",
  "redirect_url": "https://yoursite.com/some-page"
}</pre>

                        <h4>Response</h4>
                        <pre>{
  "success": true,
  "user_id": 1,
  "email": "user@example.com",
  "token": "abc123...",
  "login_url": "https://yoursite.com/?sml_action=login&sml_token=abc123&sml_user=1&sml_redirect=...",
  "expires_in_seconds": 2592000,
  "max_uses": 0,
  "expires_at": "2025-11-11T10:30:00+00:00",
  "redirect_url": "https://yoursite.com/some-page"
}</pre>

                        <h3>N8N Example</h3>
                        <p>Configure an HTTP Request node:</p>
                        <pre>Method: POST
URL: <?php echo esc_attr($api_endpoint); ?>

Headers:
  Authorization: Bearer <?php echo $api_key ? 'YOUR_API_KEY' : '(generate key above)'; ?>
  Content-Type: application/json

Body:
{
  "email": "{{ $json.userEmail }}",
  "redirect_url": "https://yoursite.com/dashboard"
}</pre>

                        <p><strong>Response in N8N:</strong></p>
                        <ul>
                            <li><code>{{ $json.login_url }}</code> – Full login URL.</li>
                            <li><code>{{ $json.token }}</code> – Token value.</li>
                            <li><code>{{ $json.expires_at }}</code> – Expiry timestamp.</li>
                        </ul>
                    </section>
                </div>
            </div>
        </div>
        <?php
    }
}

// Initialize
$magic_login = new SimpleMagicLogin();
