=== PointNet Mail Guard AI ===
Contributors: pointnet
Tags: security, blacklist, monitor, dnsbl, email deliverability
Requires at least: 5.0
Tested up to: 6.7
<<<<<<< HEAD
Stable tag: 1.2.0
=======
Stable tag: 1.1.0
>>>>>>> 7b5b5e0b9c353e4b88096cfe0f79704c2f5edd4c
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Monitor your mail server and any IP address against DNSBL blacklists — two independent monitors, separate logs, daily automated scans.

== Description ==

**PointNet Mail Guard AI** is a complete email deliverability monitoring system for your WordPress site. It offers two independent monitors in a tabbed admin interface — entirely in PHP, with no external dependencies, no Python and no exec().

**Email Monitor** — enter the email address you send from (e.g. info@yourdomain.com). The plugin automatically detects your mail server via MX record lookup, resolves its IP and runs a full deliverability check. It also tells you whether your mail server shares the same IP as WordPress or runs on a dedicated server.

**IP Monitor** — enter any IPv4 address directly. Useful for monitoring your VPS, a mail relay, or any server you manage, independently from your email configuration.

Both monitors run daily via WP-Cron and keep separate log tables, so you always have a clear, independent history for each.

**Key features:**

* Two independent monitors — Email Monitor and IP Monitor — with separate logs
* Automatic mail server detection from email address via MX record lookup
* Detects whether your mail server shares the same IP as WordPress or is on a dedicated server
* Checks against 5 major DNSBL blacklists: SpamCop, Barracuda, SORBS, UCEProtect L1, PSBL
* PTR (reverse DNS) verification — missing PTR triggers an immediate alert
<<<<<<< HEAD
* SPF Analyzer tab — full RFC 7208 analysis with 9 individual checks, visual results and provider detection
=======
* SPF record validation — detects missing or invalid SPF configuration
>>>>>>> 7b5b5e0b9c353e4b88096cfe0f79704c2f5edd4c
* Real-time terminal-style diagnostic console in the admin dashboard
* Daily automated scan via WP-Cron — covers both monitors in a single cron event
* Email alert only when problems are detected — no noise when everything is clean
* Alerts sent via wp_mail() — fully compatible with WP Mail SMTP, FluentSMTP, Easy WP SMTP and any other SMTP plugin
* Automatic cleanup of log entries older than 30 days
* Modular architecture — DMARC and DKIM checks coming in future releases
* Full multilingual support — Italian translation included

**Coming in future releases:**

* DMARC record validation
* DKIM signature check
* AI-powered deliverability analysis and automated fix suggestions
* Historical trend graphs and PDF reports

PointNet Mail Guard AI is developed and maintained by [PointNet](https://www.pointnet.it/), a web agency based in Italy.

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/` or install directly from the WordPress plugin directory.
2. Activate the plugin from the **Plugins** menu in your WordPress admin.
3. Go to **PointNet Mail Guard AI** in the admin sidebar.
4. **Email Monitor tab** — enter the email address you send from and your alert email, then click Save Settings.
5. **IP Monitor tab** — enter any IPv4 address you want to monitor and your alert email, then click Save Settings.
6. Click **Run Diagnosis Now** on either tab to perform the first check immediately.

The plugin will automatically schedule a daily scan via WP-Cron covering both monitors.

== Frequently Asked Questions ==

= Does it require Python or any server-side dependencies? =

No. The plugin runs entirely in PHP using native functions (`dns_get_record`, `gethostbyname`, `gethostbyaddr`, `filter_var`). No Python, no exec(), no shell commands, no external scripts. It works on any standard WordPress hosting environment.

= What email address should I enter in the Email Monitor? =

Enter the email address you actually send from — for example `info@yourdomain.com`. The plugin extracts the domain, queries its MX record and resolves the mail server IP automatically. You do not need to know your mail server IP.

= What should I enter in the IP Monitor? =

Any IPv4 address you want to monitor — your WordPress VPS, a dedicated mail relay, a secondary server, or any IP you manage. This monitor is completely independent from the Email Monitor.

= What if my mail is hosted by Google Workspace, Aruba or another provider? =

This is exactly what the Email Monitor is designed for. The MX lookup will find the external provider's mail server IP and check that — not your WordPress server IP. The plugin also shows whether your mail and WordPress share the same IP or are on separate servers.

= What does PTR WARNING mean? =

PTR (reverse DNS) maps an IP address back to a hostname. If it is not configured, the plugin sends an alert. Many receiving mail servers require a valid PTR and will reject or mark as spam any email from an IP without one.

= What does SHARED server mean? =

If your WordPress site and your mail server share the same IP, the plugin shows a yellow notice in the terminal. This is not an error — but it means that if that IP ends up on a blacklist, both your website and your email will be affected. A dedicated mail server reduces this risk.

= Which DNSBL blacklists are checked? =

Both monitors check against 5 carefully selected blacklists: SpamCop, Barracuda, SORBS, UCEProtect Level 1 and PSBL. These cover the major databases used by email providers worldwide. Spamhaus is intentionally excluded — their terms of service prohibit use in distributed software without a paid license.

= Are the two monitors completely independent? =

Yes. Each monitor has its own settings, its own log table and its own scan history. The daily cron event runs both in sequence. Alerts are sent independently for each monitor.

= What does SPF WARNING mean? =

SPF (Sender Policy Framework) is a DNS record that tells receiving mail servers which IPs are authorised to send email for your domain. If the SPF record is missing or invalid, email from your domain may be rejected or marked as spam by recipient servers. The plugin checks the SPF record of the monitored email domain and alerts you if it is absent or misconfigured.

= How does the email alert work? =

Alerts are sent via WordPress's `wp_mail()` only when a problem is detected: blacklisted IP, missing or invalid SPF, missing PTR, or a scan error. No email is sent when everything is clean. Each alert includes a full report specific to the monitor that triggered it.

= Does it work with WP Mail SMTP or other SMTP plugins? =

Yes, automatically. Any WordPress SMTP plugin hooks into `wp_mail()` at the WordPress level. Since PointNet Mail Guard AI uses `wp_mail()` for all alerts, your SMTP configuration is picked up with no extra setup required.

= How often are checks performed? =

Automatically once a day via WP-Cron for both monitors. You can also trigger a manual scan at any time from either tab. The next scheduled scan time is shown at the top of the plugin page.

Note: WP-Cron is triggered by site visits. On very low-traffic sites it may fire slightly later than 24 hours. For precise scheduling, disable WP-Cron in wp-config.php and add a real server cron job:
`*/5 * * * * curl -s https://yoursite.com/wp-cron.php?doing_wp_cron > /dev/null`

= How long are logs kept? =

Log entries are automatically deleted after 30 days. Cleanup runs at the end of each scan for both monitors.

= What AI features are included right now? =

<<<<<<< HEAD
The current version (1.2.0) focuses on solid, reliable deliverability monitoring in PHP. AI-powered features are planned for upcoming releases. The name reflects the project's direction and roadmap, not the current feature set.
=======
The current version (1.1.0) focuses on solid, reliable deliverability monitoring in PHP. AI-powered features are planned for upcoming releases. The name reflects the project's direction and roadmap, not the current feature set.
>>>>>>> 7b5b5e0b9c353e4b88096cfe0f79704c2f5edd4c

= Is the plugin compatible with multisite? =

The current version is designed for single-site installations. Multisite support is planned for a future release.

== Screenshots ==

1. Email Monitor tab — settings form and real-time terminal console showing MX resolution and scan results.
2. IP Monitor tab — settings form with direct IPv4 input and scan results.
3. Log table with colour-coded status indicators: CLEAN (green), ALERT (red), PTR WARNING (orange).

== Changelog ==

<<<<<<< HEAD
= 1.2.0 =
* Added dedicated SPF Analyzer tab with full RFC 7208 analysis
* 9 individual SPF checks: record presence, duplicates, length, qualifier, DNS lookup count, void lookups, ptr mechanism, exists mechanism, +all detection
* Automatic detection of known email providers (Google Workspace, Amazon SES, Mailgun, Brevo, etc.)
* Visual results with colour-coded pass/warning/error indicators
* SPF domain saved across sessions
* Italian translation updated

=======
>>>>>>> 7b5b5e0b9c353e4b88096cfe0f79704c2f5edd4c
= 1.1.0 =
* Added SPF record validation to Email Monitor
* SPF status shown in real-time terminal console (green = ok, yellow = missing or invalid)
* SPF check included in email alerts and diagnostic logs
* Italian translation updated

= 1.0.0 =
* Initial public release
* Two independent monitors: Email Monitor (MX-based) and IP Monitor (direct IPv4)
* Separate log tables for each monitor
* Automatic mail server detection from email address via MX record lookup
* Shared vs separate server detection
* DNSBL checks against 5 blacklists: SpamCop, Barracuda, SORBS, UCEProtect L1, PSBL
* PTR (reverse DNS) verification with alert on missing record
* Modular architecture — ready for SPF, DMARC, DKIM in future releases
* Real-time terminal-style diagnostic console with colour-coded results
* Daily automated scan via WP-Cron covering both monitors
* Email alert only on issues — no noise when clean
* Rate limiting on manual scans to protect DNSBL servers
* Automatic log cleanup after 30 days
* Compatible with all WordPress SMTP plugins via wp_mail()
* Full Italian translation included

== Upgrade Notice ==

<<<<<<< HEAD
= 1.2.0 =
Adds a full SPF Analyzer tab with RFC 7208 checks and provider detection. Update recommended.

=======
>>>>>>> 7b5b5e0b9c353e4b88096cfe0f79704c2f5edd4c
= 1.1.0 =
Adds SPF record validation to the Email Monitor. Update recommended.

= 1.0.0 =
Initial release. No previous version to upgrade from.
