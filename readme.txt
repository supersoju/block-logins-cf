=== Block Logins with Cloudflare ===
Contributors: supersoju
Tags: security, cloudflare, login, brute force, firewall, block, ip
Requires at least: 5.0
Tested up to: 6.5
Requires PHP: 7.2
Stable tag: 1.0
License: GPLv2 or later

Block brute-force login attempts by integrating with Cloudflare’s firewall. Automatically block IPs after repeated failed logins, manage blocks and whitelists from the admin, and keep your site secure.

== Description ==

**Block Logins with Cloudflare** helps protect your WordPress site from brute-force attacks by blocking IPs at the Cloudflare firewall after a configurable number of failed login attempts.

- Block IPs via Cloudflare after X failed login attempts
- Automatic unblocking after a configurable duration
- Whitelist IPs to never block or track them
- View and manually unblock blocked IPs from the admin
- Secure settings page with Cloudflare API token validation
- Hourly cron job for automatic maintenance

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

GNU General Public License v2.0 or later