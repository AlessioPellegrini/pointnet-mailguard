# PointNet Mail Guard AI

Email deliverability monitoring plugin for WordPress.

Monitors your server IP and mail server against DNSBL blacklists, verifies PTR (reverse DNS) configuration — 100% PHP native, no external dependencies.

## Features

- **Email Monitor** — detects your mail server automatically via MX lookup
- **IP Monitor** — monitor any IPv4 address directly
- SPF record validation — detects missing or invalid SPF configuration
- Checks against 5 major DNSBL blacklists: SpamCop, Barracuda, SORBS, UCEProtect L1, PSBL
- PTR (reverse DNS) verification
- SPF record validation
- Daily automated scan via WP-Cron
- Real-time terminal-style diagnostic console
- Email alerts only when problems are detected
- Full Italian translation included

## Requirements

- WordPress 5.0+
- PHP 7.4+

## Installation

1. Upload the plugin folder to `/wp-content/plugins/`
2. Activate from the WordPress Plugins menu
3. Go to **PointNet Mail Guard AI** in the admin sidebar
4. Configure your Email Monitor and/or IP Monitor
5. Click **Run Diagnosis Now**

## Development

Developed by [PointNet](https://www.pointnet.it/) — web agency based in Italy.

## License

GPLv2 or later — see [LICENSE](LICENSE)
