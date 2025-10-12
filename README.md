# Magic API Login

A WordPress/WooCommerce plugin that provides passwordless authentication via magic links with comprehensive API support and hardened security.

## Features

- 🔐 **Passwordless Authentication**: Generate secure magic login links for users
- 🚀 **RESTful API**: Full API support for integration with external applications (N8N, Zapier, Make, etc.)
- ⏱️ **Configurable Expiry**: Set custom expiration times for login links (default: 30 days)
- 🔄 **Custom Redirects**: Redirect users to specific pages after login
- 🔑 **Secure API Keys**: Generate and manage API keys for external integrations
- ♻️ **Reusable Tokens**: Tokens can be used unlimited times until they expire
- 🔒 **Hashed Tokens**: Tokens are hashed with HMAC-SHA256 at rest for maximum security
- 🚦 **Rate Limiting**: 5 requests per minute per user to prevent abuse
- 🛡️ **IP & User Agent Tracking**: Comprehensive logging for security auditing
- 🗑️ **Auto-Purge**: Daily cleanup of expired tokens
- 🚫 **Same-Host Redirects**: Prevents open redirect vulnerabilities
- 👤 **User Revocation**: Users can revoke all their magic links from their profile

## Installation

1. Upload the `magic_login_plugin.php` file to your WordPress plugins directory (`/wp-content/plugins/magic-api-login/`)
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Navigate to **Settings > Magic API Login** to configure

## Configuration

### Settings Page

Access the settings at **Settings > Magic API Login** in your WordPress admin panel:

- **Link Expiry**: Set how long magic login links remain valid (default: 24 hours)
- **API Key**: Generate a secure API key for external integrations

## API Usage

### Generate Magic Login Link

**Endpoint:** `POST /wp-json/magic-login/v1/generate-link`

**Authentication:** Include your API key in the request header:
```
Authorization: Bearer YOUR_API_KEY
```

**Request Body:**
```json
{
  "user_id": 1,                           // Optional: WordPress user ID
  "email": "user@example.com",            // Optional: User email (use either user_id or email)
  "redirect_url": "https://yoursite.com/dashboard"  // Optional: URL to redirect after login
}
```

**Response:**
```json
{
  "success": true,
  "user_id": 1,
  "email": "user@example.com",
  "token": "abc123...",
  "login_url": "https://yoursite.com/?sml_action=login&sml_token=abc123&sml_user=1&sml_redirect=...",
  "expires_in_days": 30,
  "expires_at": "2025-11-11T10:30:00+00:00",
  "redirect_url": "https://yoursite.com/dashboard"
}
```

### Verify Token

**Endpoint:** `POST /wp-json/magic-login/v1/verify-token`

**Authentication:** No authentication required (public endpoint)

**Request Body:**
```json
{
  "token": "abc123..."
}
```

**Response:**
```json
{
  "valid": true,
  "user_id": 1,
  "user_login": "username",
  "user_email": "user@example.com",
  "expires_at": "2025-10-12 10:30:00"
}
```

## Integration Examples

### N8N Workflow

Use an HTTP Request node with the following configuration:

**Method:** POST  
**URL:** `https://yoursite.com/wp-json/magic-login/v1/generate-link`

**Headers:**
```
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json
```

**Body:**
```json
{
  "email": "{{ $json.userEmail }}",
  "redirect_url": "https://yoursite.com/dashboard"
}
```

**Access Response Data:**
- `{{ $json.login_url }}` - Full login URL
- `{{ $json.token }}` - Token only
- `{{ $json.expires_at }}` - Expiration timestamp

### cURL Example

```bash
curl -X POST https://yoursite.com/wp-json/magic-login/v1/generate-link \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "redirect_url": "https://yoursite.com/my-account"
  }'
```

## Security Features (v2.0 Hardened)

### Token Security
- **HMAC-SHA256 Hashing**: Tokens are hashed with `hash_hmac('sha256', $token, AUTH_SALT)` before storage
- **Plaintext Never Stored**: Raw tokens only exist in transit and in responses
- **Timing-Safe Comparisons**: Uses `hash_equals()` for constant-time validation
- **Cryptographically Secure**: Uses `random_bytes()` for token generation

### Access Control
- **Rate Limiting**: 5 requests per minute per user prevents brute force and abuse
- **API Key Authentication**: Secure Bearer token authentication with timing-safe checks
- **Whitespace Rejection**: Auth headers are validated to reject empty/whitespace-only values
- **Same-Host Redirects**: Only allows redirects to the same domain (prevents open redirects)

### Monitoring & Auditing
- **IP Address Logging**: Captures requester IP on token generation and use
- **User Agent Tracking**: Stores User Agent strings (255 chars) for forensics
- **Action Hooks**: Extensible with `sml_token_generated`, `sml_user_logged_in`, `sml_tokens_revoked` hooks
- **IP Change Detection**: Fires `sml_ip_changed` action when login IP differs from generation IP

### Data Hygiene
- **Auto-Purge Cron**: Daily scheduled task removes expired tokens automatically
- **User Revocation**: Users can revoke all their active tokens from profile page
- **API Revocation**: REST endpoint for programmatic token revocation
- **Manual Cleanup**: Deactivation removes scheduled cron jobs

### Database Hardening
- **Indexed Queries**: Optimized indexes on `user_id`, `expires_at`, and `token_hash`
- **Proper Field Types**: Uses `BIGINT UNSIGNED` for IDs, `CHAR(64)` for hashes
- **NOT NULL Constraints**: Required fields properly constrained

### Session Management
- **Session Cookies by Default**: No "remember me" unless explicitly needed
- **Standard WordPress Auth**: Uses `wp_set_auth_cookie()` with WordPress best practices
- **Validated Settings**: All admin settings sanitized with min/max bounds (1-365 days)

## Database

The plugin creates a `{prefix}_magic_login_tokens` table with the following structure:

- `id`: BIGINT UNSIGNED - Auto-incrementing primary key
- `user_id`: BIGINT(20) UNSIGNED - WordPress user ID (indexed)
- `token_hash`: CHAR(64) - HMAC-SHA256 hash of token (unique, indexed)
- `ip_address`: VARCHAR(45) - IP address where token was generated
- `user_agent`: VARCHAR(255) - User agent string (for forensics)
- `created_at`: DATETIME - Token creation timestamp (auto-filled)
- `expires_at`: DATETIME - Token expiration timestamp (indexed)

**Indexes:**
- PRIMARY KEY on `id`
- UNIQUE KEY on `token_hash`
- KEY on `user_id` (for revocation queries)
- KEY on `expires_at` (for purge queries)

## Requirements

- WordPress 5.0 or higher
- PHP 7.0 or higher
- MySQL 5.6 or higher

## Use Cases

- **Email Marketing**: Send personalized login links in email campaigns
- **Customer Support**: Generate instant login links for customer assistance
- **Automation**: Integrate with workflow automation tools (N8N, Zapier, Make)
- **Multi-Site Management**: Generate login links from external systems
- **Password Reset Alternatives**: Provide passwordless login options

## Version History

### 2.0.0 - Security Hardened Edition 🔒
**Major Security Overhaul**
- 🔐 **Token Hashing**: Tokens now hashed with HMAC-SHA256 using AUTH_SALT before storage
- 🚦 **Rate Limiting**: 5 requests per minute per user to prevent abuse
- 🛡️ **User Agent Tracking**: Capture and store User Agent for forensic analysis
- 🗑️ **Auto-Purge Cron**: Daily scheduled task removes expired tokens
- 🚫 **Same-Host Redirects**: Tightened redirect validation to prevent open redirect attacks
- 🔒 **Settings Sanitization**: All settings now properly validated with min/max bounds
- 🍪 **Session Cookies**: Changed from persistent to session cookies by default
- 👤 **User Revocation**: Users can revoke all their magic links from profile page
- 📊 **Enhanced Logging**: IP change detection and comprehensive action hooks
- ⚡ **Database Optimization**: Added indexes on user_id, expires_at, and token_hash
- 🔧 **Hardened Auth**: Reject whitespace-only headers, timing-safe comparisons
- 🎯 **API Revocation Endpoint**: New REST endpoint for programmatic token revocation

**Breaking Changes:**
- Database schema updated: `token` field renamed to `token_hash`
- Added `user_agent` field to database
- Changed field types for better performance and security
- Existing installations will need to regenerate all tokens after upgrade

### 1.7.0
- **Settings now use days instead of hours** for better UX
- Admin setting changed from "Link Expiry (hours)" to "Link Expiry (days)"
- API response changed from `expires_in_hours` to `expires_in_days`
- Default remains 30 days, configurable up to 365 days

### 1.6.0
- **Changed tokens to be reusable** until expiration instead of single-use
- Default expiration changed to 30 days instead of 24 hours
- Tokens can now be used unlimited times within the expiry period

### 1.5.0
- Initial public release
- Magic link generation and verification
- RESTful API with Bearer token authentication
- Custom redirect support
- Configurable link expiration

## Author

**Creative Chili**

## License

This plugin is provided as-is. Feel free to modify and use it for your projects.

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/leakim69/magic-api-login).

