# Magic API Login

A WordPress/WooCommerce plugin that provides passwordless authentication via magic links with comprehensive API support.

## Features

- 🔐 **Passwordless Authentication**: Generate secure magic login links for users
- 🚀 **RESTful API**: Full API support for integration with external applications (N8N, Zapier, Make, etc.)
- ⏱️ **Configurable Expiry**: Set custom expiration times for login links (default: 30 days)
- 🔄 **Custom Redirects**: Redirect users to specific pages after login
- 🔑 **Secure API Keys**: Generate and manage API keys for external integrations
- ♻️ **Reusable Tokens**: Tokens can be used unlimited times until they expire
- 🛡️ **IP Tracking**: Track IP addresses for security auditing

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

## Security Features

- **Secure Token Generation**: Uses `random_bytes()` for cryptographically secure tokens
- **Reusable Tokens**: Tokens can be used multiple times until expiration (perfect for sharing or bookmarking)
- **Expiration Tracking**: Tokens expire after the configured time period (default: 30 days)
- **API Key Authentication**: Secure API access with Bearer token authentication
- **IP Address Logging**: Track IP addresses for security auditing
- **WordPress Security Integration**: Uses WordPress nonces and sanitization functions

## Database

The plugin creates a `{prefix}_magic_login_tokens` table with the following structure:

- `id`: Auto-incrementing primary key
- `user_id`: WordPress user ID
- `token`: Unique 64-character token
- `ip_address`: IP address of the requester
- `created_at`: Token creation timestamp
- `expires_at`: Token expiration timestamp
- `used`: Boolean flag indicating if token has been used

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

### 1.7.0
- **Settings now use days instead of hours** for better UX
- Admin setting changed from "Link Expiry (hours)" to "Link Expiry (days)"
- API response changed from `expires_in_hours` to `expires_in_days`
- Default remains 30 days, configurable up to 365 days
- Internal calculations still precise (days converted to seconds)

### 1.6.0
- **Changed tokens to be reusable** until expiration instead of single-use
- Default expiration changed to 30 days instead of 24 hours
- Tokens can now be used unlimited times within the expiry period
- Perfect for sharing login links or bookmarking user dashboards

### 1.5.0
- Initial public release
- Magic link generation and verification
- RESTful API with Bearer token authentication
- Custom redirect support
- Configurable link expiration
- IP address tracking

## Author

**Creative Chili**

## License

This plugin is provided as-is. Feel free to modify and use it for your projects.

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/leakim69/magic-api-login).

