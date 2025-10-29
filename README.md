# Block Logins with Cloudflare

Block brute-force login attempts on your WordPress site by integrating with Cloudflare’s firewall API. Automatically block IPs after repeated failed login attempts, manage blocks and whitelists from the admin, and keep your site secure.

## Features

- Block IPs via Cloudflare after configurable failed login attempts
- Automatic unblocking after a configurable duration
- Whitelist IPs to never block or track them
- View and manually unblock blocked IPs from the admin
- Secure settings page with Cloudflare API token validation
- Uses a single serialized option for all settings
- Hourly cron job for automatic maintenance

## Requirements

- WordPress 5.0+
- PHP 7.2+
- Cloudflare account with API Token (with Firewall permissions)
- Your site must be proxied through Cloudflare

## Installation

1. Upload the plugin to your `/wp-content/plugins/` directory.
2. Activate the plugin through the WordPress admin.
3. Go to **Block Logins CF** in the admin sidebar to configure settings.

## Configuration

- **Cloudflare API Token:** Create a token with at least `Zone.Zone` and `Zone.Firewall` permissions.
- **Zone ID:** Find this in your Cloudflare dashboard under your domain's overview.
- **Max Failed Attempts:** Number of failed logins before blocking an IP.
- **Block Duration:** Time window (in seconds) for counting failed attempts.
- **Auto Unblock Duration:** How long (in hours) to keep an IP blocked before automatic unblocking.
- **Whitelist:** Add IPs that should never be blocked or tracked.

## External Services

This plugin relies on the **Cloudflare API** to function. It communicates with Cloudflare's external servers to block IP addresses at the firewall level.

### What is the Cloudflare API and what is it used for?

The Cloudflare API is a RESTful service provided by Cloudflare, Inc. that allows programmatic management of Cloudflare firewall rules. This plugin uses it to automatically block and unblock IP addresses based on failed login attempts.

### What data is sent and when?

The plugin sends the following data to Cloudflare's API servers:

1. **During settings validation** (when you save Cloudflare credentials):
   - Your Cloudflare API token (for verification)
   - Endpoint: `https://api.cloudflare.com/client/v4/user/tokens/verify`

2. **When blocking an IP** (after failed login threshold is reached):
   - The IP address to be blocked
   - Your Cloudflare email address and API key/token
   - Your Cloudflare Zone ID
   - A note describing the reason for the block
   - Endpoint: `https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules`

No personally identifiable information about your WordPress users is transmitted. Only IP addresses of failed login attempts are sent to Cloudflare.

### Service Provider Information

- **Service:** Cloudflare API
- **Provider:** Cloudflare, Inc.
- **Terms of Service:** https://www.cloudflare.com/terms/
- **Privacy Policy:** https://www.cloudflare.com/privacypolicy/
- **API Documentation:** https://developers.cloudflare.com/api/

### Required for Functionality

This plugin requires a Cloudflare account and will not function without valid Cloudflare API credentials. The external API calls are essential to the plugin's core functionality.

## Security

- Only administrators (`manage_options`) can access settings and unblock/whitelist IPs.
- All form actions are protected by WordPress nonces.

## FAQ

**Q: Does this block at the Cloudflare level or just WordPress?**  
A: This plugin uses the Cloudflare API to block IPs at the edge, before they reach your server.

**Q: Can I use an API key instead of a token?**  
A: API tokens are recommended for security and are required for the verification feature.

## License

GNU General Public License v2 or later

---

**Contributions welcome!**  
Open an issue or PR on [GitHub](https://github.com/yourusername/block-logins-cf).