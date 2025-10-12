<?php
/**
 * Plugin Name: Magic API Login
 * Description: Passwordless authentication via reusable magic links with API support - Hardened Security Edition
 * Version: 2.0.1
 * Author: Creative Chili
 */

if (!defined('ABSPATH')) exit;

class SimpleMagicLogin {
    private $table;
    private $option_key = 'sml_settings';

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
        
        // Normalize and trim
        $auth_header = trim($auth_header);
        
        // Reject empty or whitespace-only headers
        if (empty($auth_header) || ctype_space($auth_header)) {
            error_log('Magic Login API: Missing Authorization header');
            return new WP_Error('missing_auth', 'Missing Authorization header', ['status' => 401]);
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
            return new WP_Error('db_error', 'Failed to create token', ['status' => 500]);
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
            'user_id' => $row->user_id,
            'user_login' => $user->user_login,
            'user_email' => $user->user_email,
            'expires_at' => $row->expires_at
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
        if (isset($_POST['sml_generate_api_key']) && wp_verify_nonce($_POST['_wpnonce'], 'sml_generate_api_key')) {
            $new_key = bin2hex(random_bytes(32));
            $current_settings = get_option($this->option_key, []);
            $current_settings['api_key'] = $new_key;
            update_option($this->option_key, $current_settings);
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
            
            <div class="notice notice-info">
                <p><strong>Security Hardened v2.0:</strong> Tokens are now hashed at rest, rate-limited, and auto-purged. Links remain reusable within expiry period.</p>
            </div>
            
            <form method="post" action="options.php">
                <?php settings_fields('sml_settings'); ?>
                <table class="form-table">
                    <tr>
                        <th><label for="sml_expiry">Link Expiry (days)</label></th>
                        <td>
                            <input type="number" id="sml_expiry" name="<?php echo $this->option_key; ?>[expiry_days]" value="<?php echo esc_attr($expiry); ?>" min="1" max="365">
                            <p class="description">How many days a generated link remains valid (default: 30 days, max: 365 days)</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>

            <hr>
            <h2>API Settings</h2>
            <p>Use the API to generate magic login links from external applications like N8N.</p>
            <p><strong>Rate Limit:</strong> 5 requests per minute per user</p>
            
            <table class="form-table">
                <tr>
                    <th><label>API Key</label></th>
                    <td>
                        <?php if ($api_key): ?>
                            <input type="text" readonly value="<?php echo esc_attr($api_key); ?>" id="sml-api-key" style="width: 100%; padding: 8px; font-family: monospace; background: #f5f5f5; font-size: 12px;">
                            <button type="button" class="button button-small" onclick="navigator.clipboard.writeText(document.getElementById('sml-api-key').value); this.textContent='✓ Copied!'; setTimeout(() => this.textContent='Copy to Clipboard', 2000);" style="margin-top: 5px;">Copy to Clipboard</button>
                            <p class="description">
                                <strong>Key Length:</strong> <?php echo strlen($api_key); ?> characters (should be 64)<br>
                                Keep this key secure. It provides full access to generate login links.<br>
                                <strong>Important:</strong> Copy the entire key including all characters. No spaces before or after.
                            </p>
                        <?php else: ?>
                            <p style="color: #666;">No API key generated yet. Click "Generate New API Key" below to create one.</p>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <th><label>API Endpoint</label></th>
                    <td>
                        <input type="text" readonly value="<?php echo esc_attr($api_endpoint); ?>" style="width: 100%; padding: 8px; font-family: monospace; background: #f5f5f5;">
                    </td>
                </tr>
            </table>

            <form method="post">
                <?php wp_nonce_field('sml_generate_api_key'); ?>
                <button type="submit" name="sml_generate_api_key" class="button button-secondary" 
                        onclick="return confirm('Generate a new API key? The old key will stop working immediately.');">
                    Generate New API Key
                </button>
            </form>
            
            <hr>
            <h2>Troubleshooting</h2>
            <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 15px 0;">
                <h3 style="margin-top: 0;">Getting "Invalid API Key" error in N8N?</h3>
                <ol style="margin-left: 20px;">
                    <li><strong>Verify key length:</strong> Should be exactly 64 characters (shown above)</li>
                    <li><strong>Copy properly:</strong> Use the "Copy to Clipboard" button to avoid extra spaces</li>
                    <li><strong>Check N8N header:</strong> Must be <code>Authorization: Bearer YOUR_KEY</code></li>
                    <li><strong>Generate new key:</strong> If issues persist, generate a fresh key</li>
                    <li><strong>Check logs:</strong> WordPress debug.log will show "Magic Login API:" messages</li>
                    <li><strong>After generating:</strong> Wait 1-2 seconds before using the key</li>
                </ol>
                <p><strong>Testing:</strong> You can test the API with cURL:</p>
                <pre style="background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; font-size: 11px;">curl -X POST "<?php echo esc_attr($api_endpoint); ?>" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com"}'</pre>
            </div>
            
            <hr>
            <h2>Security Features (v2.0)</h2>
            <ul style="list-style: disc; margin-left: 20px;">
                <li>✅ <strong>Hashed Tokens:</strong> Tokens are hashed with AUTH_SALT at rest for security</li>
                <li>✅ <strong>Rate Limiting:</strong> 5 requests per minute per user prevents abuse</li>
                <li>✅ <strong>IP & User Agent Logging:</strong> Track where tokens are generated and used</li>
                <li>✅ <strong>Auto-Purge:</strong> Expired tokens automatically deleted daily</li>
                <li>✅ <strong>Same-Host Redirects:</strong> Prevents open redirect vulnerabilities</li>
                <li>✅ <strong>Session Cookies:</strong> Default to session cookies (not "remember me")</li>
                <li>✅ <strong>User Revocation:</strong> Users can revoke all their links from their profile</li>
            </ul>
            
            <hr>
            <h2>API Documentation</h2>
            
            <h3>Generate Magic Login Link</h3>
            <p><strong>Endpoint:</strong> <code>POST <?php echo esc_attr($api_endpoint); ?></code></p>
            <p><strong>Authentication:</strong> <code>Authorization: Bearer YOUR_API_KEY</code></p>
            
            <h4>Request Parameters:</h4>
            <pre style="background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto;">
{
  "user_id": 1,                    // Optional: WordPress user ID
  "email": "user@example.com",     // Optional: User email (use either user_id or email)
  "redirect_url": "https://yoursite.com/some-page"  // Optional: URL to redirect after login
}</pre>

            <h4>Response:</h4>
            <pre style="background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto;">
{
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
            <p>Use an HTTP Request node with these settings:</p>
            <pre style="background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto;">
Method: POST
URL: <?php echo esc_attr($api_endpoint); ?>
Headers:
  - Authorization: Bearer <?php echo $api_key ? 'YOUR_API_KEY' : '(generate key above)'; ?>
  - Content-Type: application/json
Body:
  {
    "email": "{{ $json.userEmail }}",
    "redirect_url": "https://yoursite.com/dashboard"
  }</pre>

            <p><strong>Response in N8N:</strong></p>
            <ul>
                <li><code>{{ $json.login_url }}</code> - Full login URL (includes redirect)</li>
                <li><code>{{ $json.token }}</code> - Just the token</li>
                <li><code>{{ $json.expires_at }}</code> - When the link expires</li>
            </ul>
        </div>
        <?php
    }
}

// Initialize
$magic_login = new SimpleMagicLogin();
