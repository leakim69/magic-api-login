<?php
/**
 * Plugin Name: Magic API Login
 * Description: Passwordless authentication via magic links with API support
 * Version: 1.5.0
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
    }

    public function init() {
        add_action('admin_menu', [$this, 'add_settings_page']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('rest_api_init', [$this, 'register_rest_routes']);
        add_action('wp_loaded', [SimpleMagicLogin::class, 'verify_and_login'], 10);
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
    }

    public function api_permission_check() {
        $settings = get_option($this->option_key, []);
        $api_key = isset($settings['api_key']) ? $settings['api_key'] : '';
        
        if (empty($api_key)) {
            return new WP_Error('api_disabled', 'API not enabled', ['status' => 403]);
        }

        // Support multiple header sources for proxy compatibility
        $auth_header = $_SERVER['HTTP_AUTHORIZATION']
            ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION']
            ?? ($_SERVER['HTTP_X_API_KEY'] ?? '');
        
        if (empty($auth_header)) {
            return new WP_Error('missing_auth', 'Missing Authorization header', ['status' => 401]);
        }

        // Support both "Bearer TOKEN" and raw key format
        $token = $auth_header;
        if (preg_match('/^Bearer\s+(.+)$/i', $auth_header, $m)) {
            $token = $m[1];
        }
        
        if (!hash_equals($api_key, $token)) {
            return new WP_Error('invalid_auth', 'Invalid API key', ['status' => 401]);
        }

        return true;
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

        // Generate token
        global $wpdb;
        $token = bin2hex(random_bytes(32));
        $settings = get_option($this->option_key, []);
        $expiry_hours = isset($settings['expiry_hours']) ? (int)$settings['expiry_hours'] : 24;
        
        // Store redirect URL if provided
        $redirect_data = !empty($redirect_url) ? esc_url_raw($redirect_url) : '';
        
        $insert = $wpdb->insert($this->table, [
            'user_id' => $user->ID,
            'token' => $token,
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'API',
            'expires_at' => gmdate('Y-m-d H:i:s', time() + ($expiry_hours * 3600))
        ]);

        if (!$insert) {
            return new WP_Error('db_error', 'Failed to create token', ['status' => 500]);
        }

        $login_url_params = [
            'sml_action' => 'login',
            'sml_token' => $token,
            'sml_user' => $user->ID
        ];
        
        // Add redirect URL to query string if provided (add_query_arg handles encoding)
        if (!empty($redirect_url)) {
            $login_url_params['sml_redirect'] = $redirect_url;
        }
        
        $login_url = add_query_arg($login_url_params, home_url('/'));

        return new WP_REST_Response([
            'success' => true,
            'user_id' => $user->ID,
            'email' => $user->user_email,
            'token' => $token,
            'login_url' => $login_url,
            'expires_in_hours' => $expiry_hours,
            'expires_at' => gmdate('c', time() + ($expiry_hours * 3600)),
            'redirect_url' => $redirect_data ?: null
        ], 200);
    }

    public function api_verify_token(WP_REST_Request $request) {
        $token = sanitize_text_field($request->get_param('token'));
        
        global $wpdb;
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$this->table} WHERE token = %s AND used = 0 AND expires_at > NOW()",
            $token
        ));

        if (!$row) {
            return new WP_Error('invalid_token', 'Invalid or expired token', ['status' => 401]);
        }

        $user = get_user_by('ID', $row->user_id);

        return new WP_REST_Response([
            'valid' => true,
            'user_id' => $row->user_id,
            'user_login' => $user->user_login,
            'user_email' => $user->user_email,
            'expires_at' => $row->expires_at
        ], 200);
    }

    public function activate() {
        global $wpdb;
        $charset = $wpdb->get_charset_collate();
        
        $sql = "CREATE TABLE IF NOT EXISTS {$this->table} (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            user_id bigint(20) NOT NULL,
            token varchar(64) NOT NULL UNIQUE,
            ip_address varchar(45),
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            expires_at datetime NOT NULL,
            used tinyint(1) DEFAULT 0,
            PRIMARY KEY (id),
            KEY token_idx (token)
        ) $charset;";
        
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    public static function verify_and_login() {
        if (empty($_GET['sml_action']) || $_GET['sml_action'] !== 'login') return;
        if (empty($_GET['sml_token']) || empty($_GET['sml_user'])) return;

        global $wpdb;
        $table = $wpdb->prefix . 'magic_login_tokens';
        $token = sanitize_text_field($_GET['sml_token']);
        $user_id = (int)$_GET['sml_user'];
        
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$table} WHERE token = %s AND user_id = %d AND used = 0 AND expires_at > NOW()",
            $token, $user_id
        ));
        
        if (!$row) {
            wp_die('Invalid or expired login link');
        }

        // Mark as used
        $wpdb->update($table, ['used' => 1], ['id' => $row->id]);
        
        // Get user
        $user = get_user_by('ID', $user_id);
        if (!$user) {
            wp_die('User not found');
        }
        
        // Log in user
        wp_set_auth_cookie($user_id, true);
        wp_set_current_user($user_id);
        do_action('wp_login', $user->user_login, $user);
        
        // Safe redirect with validation
        $raw_redirect = isset($_GET['sml_redirect']) ? urldecode($_GET['sml_redirect']) : '';
        $raw_redirect = esc_url_raw($raw_redirect);
        $redirect_url = wp_validate_redirect($raw_redirect, admin_url());
        
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
        register_setting('sml_settings', $this->option_key);
    }

    public function render_settings_page() {
        $settings = get_option($this->option_key, []);
        $expiry = isset($settings['expiry_hours']) ? $settings['expiry_hours'] : 24;
        $api_key = isset($settings['api_key']) ? $settings['api_key'] : '';
        
        // Generate new API key if requested
        if (isset($_POST['sml_generate_api_key']) && wp_verify_nonce($_POST['_wpnonce'], 'sml_settings')) {
            $new_key = bin2hex(random_bytes(32));
            $settings['api_key'] = $new_key;
            update_option($this->option_key, $settings);
            $api_key = $new_key;
            echo '<div class="updated"><p>✓ New API key generated</p></div>';
        }
        
        $api_endpoint = rest_url('magic-login/v1/generate-link');
        ?>
        <div class="wrap">
            <h1>Magic API Login Settings</h1>
            <form method="post" action="options.php">
                <?php settings_fields('sml_settings'); ?>
                <table class="form-table">
                    <tr>
                        <th><label for="sml_expiry">Link Expiry (hours)</label></th>
                        <td>
                            <input type="number" id="sml_expiry" name="<?php echo $this->option_key; ?>[expiry_hours]" value="<?php echo esc_attr($expiry); ?>" min="1" max="720">
                            <p class="description">How long login links remain valid</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>

            <hr>
            <h2>API Settings</h2>
            <p>Use the API to generate magic login links from external applications like N8N.</p>
            
            <table class="form-table">
                <tr>
                    <th><label>API Key</label></th>
                    <td>
                        <?php if ($api_key): ?>
                            <input type="text" readonly value="<?php echo esc_attr($api_key); ?>" style="width: 100%; padding: 8px; font-family: monospace; background: #f5f5f5;">
                            <p class="description">Copy this key and use it in your API requests</p>
                        <?php else: ?>
                            <p style="color: #666;">No API key generated yet</p>
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
                <?php wp_nonce_field('sml_settings'); ?>
                <button type="submit" name="sml_generate_api_key" class="button button-secondary">Generate New API Key</button>
            </form>
            
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
  "expires_in_hours": 24,
  "expires_at": "2025-10-12T10:30:00+00:00",
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
