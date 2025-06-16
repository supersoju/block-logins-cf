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
- **Zone ID:** Find this in your Cloudflare dashboard under your domain’s overview.
- **Max Failed Attempts:** Number of failed logins before blocking an IP.
- **Block Duration:** Time window (in seconds) for counting failed attempts.
- **Auto Unblock Duration:** How long (in hours) to keep an IP blocked before automatic unblocking.
- **Whitelist:** Add IPs that should never be blocked or tracked.

## Security

- Only administrators (`manage_options`) can access settings and unblock/whitelist IPs.
- All form actions are protected by WordPress nonces.

## FAQ

**Q: Does this block at the Cloudflare level or just WordPress?**  
A: This plugin uses the Cloudflare API to block IPs at the edge, before they reach your server.

**Q: Can I use an API key instead of a token?**  
A: API tokens are recommended for security and are required for the verification feature.

## License

GNU General Public License v2.0 or later

---

**Contributions welcome!**  
Open an issue or PR on [GitHub](https://github.com/supersoju/block-logins-cf).
