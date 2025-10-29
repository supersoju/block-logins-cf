=== Block Logins with Cloudflare ===
Contributors: supersoju
Tags: security, cloudflare, login, firewall, brute-force
Requires at least: 6.0
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.0
License: GPL-2.0-or-later

Block brute-force login attempts by integrating with Cloudflare's firewall to automatically block IPs after failed logins.

== Description ==

**Block Logins with Cloudflare** helps protect your WordPress site from brute-force attacks by blocking IPs at the Cloudflare firewall after a configurable number of failed login attempts.

- Block IPs via Cloudflare after X failed login attempts
- Automatic unblocking after a configurable duration
- Whitelist IPs to never block or track them
- View and manually unblock blocked IPs from the admin
- Secure settings page with Cloudflare API token validation
- Hourly cron job for automatic maintenance

== External Services ==

This plugin relies on the **Cloudflare API** to function. It communicates with Cloudflare's external servers to block IP addresses at the firewall level.

**What is the Cloudflare API and what is it used for?**
The Cloudflare API is a RESTful service provided by Cloudflare, Inc. that allows programmatic management of Cloudflare firewall rules. This plugin uses it to automatically block and unblock IP addresses based on failed login attempts.

**What data is sent and when?**
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

**Service provider information:**
- Service: Cloudflare API
- Provider: Cloudflare, Inc.
- Terms of Service: https://www.cloudflare.com/terms/
- Privacy Policy: https://www.cloudflare.com/privacypolicy/
- API Documentation: https://developers.cloudflare.com/api/

**Required for functionality:**
This plugin requires a Cloudflare account and will not function without valid Cloudflare API credentials. The external API calls are essential to the plugin's core functionality.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/block-logins-cf` directory, or install through the WordPress plugins screen.
2. Activate the plugin through the 'Plugins' screen.
3. Go to **Block Logins CF** in the admin sidebar to configure your Cloudflare credentials and settings.

== Frequently Asked Questions ==

= What permissions does my Cloudflare API token need? =
Your token needs `Zone.Zone` and `Zone.Firewall` permissions for the relevant zone.

= Where do I find my Cloudflare Zone ID? =
In your Cloudflare dashboard, select your domain and look for the Zone ID in the Overview tab.

= Does this block at the Cloudflare level or just WordPress? =
This plugin blocks IPs at the Cloudflare firewall, stopping attacks before they reach your server.

== Screenshots ==

1. **Settings Page:** Configure your Cloudflare credentials, blocking thresholds, and auto-unblock duration.
2. **Blocked IPs Management:** View currently blocked IPs, unblock them, and manage your whitelist.
3. **Whitelist Management:** Add or remove IP addresses from the whitelist to prevent them from being blocked.

== Changelog ==

= 1.0 =
* Initial release

== Upgrade Notice ==

= 1.0 =
First release.

== License ==

GNU General Public License v2 or later