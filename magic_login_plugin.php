<?php
/**
 * Plugin Name: Magic API Login
 * Description: Passwordless authentication via reusable magic links with API support - Hardened Security Edition
 * Version: 2.2.0
 * Author: Creative Chili
 */

if (!defined('ABSPATH')) exit;

class SimpleMagicLogin {
    private const SCHEMA_VERSION = 2;

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
        add_action('wp_loaded', [SimpleMagicLogin::class, 'verify_and_login'], 10);
        add_action('sml_purge_tokens', [$this, 'purge_expired_tokens']);
        
        // User profile actions
        add_action('show_user_profile', [$this, 'user_profile_revoke_section']);
        add_action('edit_user_profile', [$this, 'user_profile_revoke_section']);
        add_action('personal_options_update', [$this, 'handle_user_revoke']);
        add_action('edit_user_profile_update', [$this, 'handle_user_revoke']);
        
        // Ensure schema is up to date
        $this->ensure_schema();
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
        $expiry_days = isset($settings['expiry_days']) ? (int)$settings['expiry_days'] : 30;
        $expiry_seconds = $expiry_days * 24 * 3600;
        
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
            'expires_at' => gmdate('Y-m-d H:i:s', time() + $expiry_seconds)
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
        do_action('sml_token_generated', $user->ID, $expiry_days, $ip_address);

        $login_url_params = [
            'sml_action' => 'login',
            'sml_token' => $token,
            'sml_user' => $user->ID
        ];
        
        // Add redirect URL to query string if provided
        if (!empty($redirect_url)) {
            $login_url_params['sml_redirect'] = $redirect_url;
        }
        
        $login_url = add_query_arg($login_url_params, home_url('/'));

        return new WP_REST_Response([
            'success' => true,
            'user_id' => $user->ID,
            'email' => $user->user_email,
            'token' => $token, // Plaintext returned once
            'login_url' => $login_url,
            'expires_in_days' => $expiry_days,
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

    public static function verify_and_login() {
        if (empty($_GET['sml_action']) || $_GET['sml_action'] !== 'login') return;
        if (empty($_GET['sml_token']) || empty($_GET['sml_user'])) return;

        global $wpdb;
        $table = $wpdb->prefix . 'magic_login_tokens';
        $token = sanitize_text_field($_GET['sml_token']);
        $user_id = (int)$_GET['sml_user'];
        
        // Hash the token for comparison
        if (!defined('AUTH_SALT') || empty(AUTH_SALT)) {
            $token_hash = hash('sha256', $token . 'sml_fallback_salt_' . NONCE_SALT);
        } else {
            $token_hash = hash_hmac('sha256', $token, AUTH_SALT);
        }
        
        // Query with hashed token, reusable (no "used" check)
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT id, user_id, ip_address, user_agent, expires_at FROM {$table} 
             WHERE token_hash = %s AND user_id = %d LIMIT 1",
            $token_hash, $user_id
        ));
        
        if (!$row || strtotime($row->expires_at) <= time()) {
            wp_die('Invalid or expired login link');
        }

        // Get user
        $user = get_user_by('ID', $user_id);
        if (!$user) {
            wp_die('User not found');
        }
        
        // Capture current IP and UA for security logging
        $current_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $current_ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        // Optional: Alert if IP changed (just log for now, don't block)
        if (!empty($row->ip_address) && $row->ip_address !== $current_ip) {
            do_action('sml_ip_changed', $user_id, $row->ip_address, $current_ip);
        }
        
        // Log in user (session cookie by default, not "remember me")
        wp_set_auth_cookie($user_id, false);
        wp_set_current_user($user_id);
        do_action('wp_login', $user->user_login, $user);
        do_action('sml_user_logged_in', $user_id, $current_ip, $current_ua);
        
        // Safe redirect - no urldecode, same-host only
        $raw_redirect = isset($_GET['sml_redirect']) ? $_GET['sml_redirect'] : '';
        $redirect_url = SimpleMagicLogin::safe_redirect($raw_redirect);
        
        wp_safe_redirect($redirect_url);
        exit;
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
        
        // Validate expiry days (1-365)
        if (isset($input['expiry_days'])) {
            $output['expiry_days'] = max(1, min(365, (int)$input['expiry_days']));
        } else {
            $output['expiry_days'] = 30;
        }
        
        // CRITICAL: Always preserve the API key - it can only be changed via the Generate button
        // Get the current settings to preserve the API key
        $existing = get_option($this->option_key, []);
        if (isset($existing['api_key']) && !empty($existing['api_key'])) {
            $output['api_key'] = $existing['api_key'];
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
        $expiry = isset($settings['expiry_days']) ? $settings['expiry_days'] : 30;
        $api_key = isset($settings['api_key']) ? $settings['api_key'] : '';
        
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
                                <label for="sml_expiry">Link Expiry (days)</label>
                                <input type="number" id="sml_expiry" name="<?php echo $this->option_key; ?>[expiry_days]" value="<?php echo esc_attr($expiry); ?>" min="1" max="365">
                                <p class="description">Default is 30 days. Choose anywhere between 1 and 365 days.</p>
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
                        <form method="post" class="sml-inline-form">
                            <?php wp_nonce_field('sml_generate_api_key', 'sml_generate_api_key_nonce'); ?>
                            <button type="submit" name="sml_generate_api_key" class="button button-secondary sml-secondary" onclick="return confirm('Generate a new API key? The old key will stop working immediately.');">
                                Generate New API Key
                            </button>
                            <p class="description">Regenerating immediately revokes the previous key.</p>
                        </form>
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
                                <pre>curl -i -X POST "<?php echo esc_attr($api_endpoint); ?>" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com"}'</pre>
                            </div>
                            <div>
                                <h4>X-API-Key header</h4>
                                <pre>curl -i -X POST "<?php echo esc_attr($api_endpoint); ?>" \
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
  "expires_in_days": 30,
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
