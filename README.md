# PointNet Mail Guard

Monitor your mail server and any IP address against DNSBL blacklists — two independent monitors, separate logs, daily automated scans.

**Contributors:** pointnet  
**Tags:** security, blacklist, monitor, dnsbl, email deliverability  
**Requires at least:** WordPress 7.0  
**Tested up to:** 7.0  
**Stable tag:** 1.8.3  
**Requires PHP:** 8.3  
**License:** GPLv2 or later — see [LICENSE](LICENSE)

---

## Description

PointNet Mail Guard is a complete email deliverability monitoring system for WordPress. It runs entirely in PHP with native functions — no Python, no exec(), no external dependencies.

The plugin offers **two independent monitors** in a tabbed admin interface:

- **Email & MX Monitor** — enter your sender email, the plugin detects your mail server automatically via MX lookup and runs a full deliverability check.
- **Custom IP Monitor** — enter any IPv4 or IPv6 address to monitor your VPS, mail relay or any server independently.

Both monitors run daily via WP-Cron, keep separate logs, and send email alerts only when problems are detected.

Developed by [PointNet](https://www.pointnet.it/).

## IPv6 Support

| Feature | IPv4 | IPv6 | Notes |
|---|---|---|---|
| DNSBL checks (9 blacklists) | ✅ | ❌ | Only SPFBL supports IPv6. 8 of 9 blacklists return NXDOMAIN. |
| PTR (reverse DNS) | ✅ | ✅ | Native PHP function `gethostbyaddr()` |
| GeoIP (ipwhois.app) | ✅ | ✅ | API supports both |
| WHOIS (rdap.org) | ✅ | ✅ | API supports both |
| SPF Analyzer | ✅ | ✅ | `ip6:` mechanisms recognized |
| DMARC Analyzer | ✅ | ✅ | DNS-based |
| DKIM Analyzer | ✅ | ✅ | DNS-based |
| IP Monitor | ✅ | ✅ | PTR/GeoIP/WHOIS work; DNSBL shows informative message |
| IP Analysis tool | ✅ | ✅ | PTR/GeoIP/WHOIS work; DNSBL shows informative message |

## Security
- **API Key encryption**: Gemini API keys are encrypted with AES-256-CBC before storage in the database. The encryption key is derived from your WordPress `SECURE_AUTH_KEY` salt. Plaintext keys are automatically migrated on first use.
- **Header-based API authentication**: API keys are sent via `x-goog-api-key` HTTP header instead of URL query string, preventing key leakage in server access logs.
- **Keys never exposed in UI**: The admin interface shows only a placeholder when a key is configured — the actual key (plaintext or encrypted) is never sent to the browser.
- **Full input sanitization**: All user inputs are sanitized with `sanitize_email()`, `sanitize_text_field()`, and `filter_var()` for IP addresses.
- **CSRF protection via nonces**: Every AJAX handler and form submission validates a WordPress nonce.
- **Capability checks**: All administrative actions require `manage_options` capability.

## Features

- Two independent monitors — Email & MX (auto-detected) and Custom IP (manual)
- Separate tabs: "Email & MX Monitor" and "Custom IP Monitor"
- Automatic mail server detection from email address via MX lookup
- Shared vs dedicated server detection (mail and WordPress on same IP)
- DNSBL checks against 9 blacklists: SpamCop, Barracuda, SORBS, UCEProtect L1, PSBL, Abusix, SPFBL, DroneBL, LashBack UBL
- DNSBL results shown as colour-coded badge grid on Monitors tab
- PTR (reverse DNS) verification with alert on missing record
- SPF Analyzer — full RFC 7208 analysis, 9 checks, provider detection
- DMARC Analyzer — full RFC 7489 analysis, policy strength, SPF correlation
- **DMARC Aggregate Report (RUA) parser** — XML, GZIP, and ZIP report processing with persistent DB storage and dashboard management
- **TLSRPT Report (RFC 8460) parser** — JSON, GZIP, and ZIP report processing with persistent DB storage and dashboard management
- DKIM Analyzer — selector auto-detection, key type/length, test mode, hash algorithm
- MTA-STS Analyzer (RFC 8461) — DNS record `_mta-sts`, policy JSON fetch, mode (enforce/testing/none), MX validation, max_age verification
- DMARC and DKIM quick check integrated into Email Monitor scanner
- Recent scans with colour-coded badges for SPF, DMARC, DKIM, PTR, SERVER, DNSBL
- IP Analysis tool — DNSBL, PTR, GeoIP and WHOIS lookup for any IPv4 address
- GeoIP lookup — country, region, city, ISP and ASN via ipwhois.app
- WHOIS lookup — IP block owner, range, organization via RDAP (rdap.org)
- AI-powered deliverability analysis (Gemini API) — score, severity, issues, strengths, next steps
- AI Chat — ask free-text questions about email deliverability
- Gemini AI model selector in Advanced tab
- Export / Support tab — download full diagnostic JSON report for assistance
- Real-time terminal-style diagnostic console with colour-coded log details
- Auto-fill alert email from monitored email during onboarding wizard
- Daily automated scan via WP-Cron
- Email alerts only on problems — sent via wp_mail()
- **Configurable notification levels** — choose between All issues (warnings + errors), Errors only (DNSBL listings, scan failures, SPF missing, DKIM errors/missing), or None (disable email notifications)
- **Error classification** — DNSBL listing, scan failures, SPF missing and DKIM errors/missing are treated as real errors (email-blocking); DMARC, MTA-STS, PTR and SPF warnings are classified as warnings (informational)
- Compatible with WP Mail SMTP, FluentSMTP, Easy WP SMTP and any SMTP plugin
- Automatic log cleanup after 30 days
- Uninstall data cleanup preference (keep or delete data)
- Full Italian translation included

## Requirements

- WordPress 7.0+
- PHP 8.3+

## Installation

1. Upload the plugin folder to `/wp-content/plugins/` or install from the WordPress plugin directory.
2. Activate the plugin from the **Plugins** menu.
3. Go to **PointNet Mail Guard** in the admin sidebar, enter your email address or IP in the respective tab, and click Save Settings.
4. Click **Run Diagnosis Now** to perform the first check immediately.

The plugin will automatically schedule a daily scan via WP-Cron.

## External Services

PointNet Mail Guard makes the following external HTTP requests, all initiated by the WordPress administrator:

- **v4.ident.me** — Automatically at startup. Retrieves the public IPv4 address of your WordPress server to detect shared vs. dedicated mail server setup.
- **Google Gemini API** (generativelanguage.googleapis.com) — Only when an API key is configured. Provides AI-powered deliverability analysis and chat functionality.
- **ipwhois.app** (GeoIP) — On-demand when using the IP Analysis tool in the DNS & IP Tools tab. Looks up geolocation data (country, region, city, ISP, ASN). Free tier, no API key required.
- **rdap.org** (WHOIS) — On-demand when using the IP Analysis tool in the DNS & IP Tools tab. Looks up IP block ownership and registry information. Free REST API, no API key required.
- **DNSBL servers** — On-demand during scans. Queries 9 DNSBL zones (SpamCop, Barracuda, SORBS, UCEProtect, PSBL, Abusix, SPFBL, DroneBL, LashBack) to check IP reputation. Standard DNS queries, no API keys required.

## Multisite Compatibility

This plugin has not been tested with WordPress Multisite. Use on a network installation may produce unexpected results and is not recommended.

## Frequently Asked Questions

### Does it require Python or any server-side dependencies?

No. The plugin runs entirely in PHP using native functions (`dns_get_record`, `gethostbyname`, `gethostbyaddr`, `filter_var`). No Python, no exec(), no shell commands. Works on any standard WordPress hosting.

### What does SHARED server mean?

If your WordPress site and mail server share the same IP, a yellow notice is shown. If that IP gets blacklisted, both your website and email are affected. A dedicated mail server reduces this risk.

### Which DNSBL blacklists are checked?

SpamCop, Barracuda, SORBS, UCEProtect Level 1, PSBL, Abusix, SPFBL, DroneBL and LashBack UBL — 9 blacklists in total. Spamhaus is intentionally excluded — their terms prohibit use in distributed software without a paid license.

### Does it work with WP Mail SMTP or other SMTP plugins?

Yes, automatically. Any SMTP plugin hooks into `wp_mail()`. PointNet Mail Guard uses `wp_mail()` for all alerts, so your SMTP configuration is picked up with no extra setup.

### Does the plugin make external API calls?

Yes. See the "External Services" section above for a full list of external services, what they do, and when they are activated.

### Is the plugin compatible with WordPress Multisite?

This plugin has not been tested on WordPress Multisite. Use on a network installation may result in unexpected behaviour.

### What happens to my data when I delete the plugin?

By default, all plugin data (tables, settings, and logs) is removed when you delete the plugin from the Plugins screen. If you want to keep your data in the database — for example if you plan to reinstall the plugin later — go to **Advanced** → **Uninstall Behavior** and uncheck "Delete all data on uninstall" before deleting the plugin.

## Next Features

Planned improvements for upcoming releases:

- **MTA-STS: Multiple Records check** — detect duplicate `v=STSv1` DNS records
- **MTA-STS: HTTPS Certificate validation** — verify the policy file certificate chain and expiry
- **MTA-STS: MX Host Validation** — compare MX hosts in the policy file against actual DNS MX records
- **MTA-STS Analyzer section in Email Monitor card** — show MTA-STS status alongside SPF/DMARC/DKIM in scan terminal
- **BIMI Analyzer** — Brand Indicators for Message Identification (logo verification in email clients)
- **Dashboard Widget** — monitor status on the WordPress admin dashboard

## Changelog

### 1.8.3
* **New**: DMARC Aggregate Report (RUA) processing — parse XML, GZIP, and ZIP aggregate reports natively in PHP
* **New**: TLSRPT Report (RFC 8460) processing — parse JSON, GZIP, and ZIP TLS failure reports natively in PHP
* **New**: Database schema migration — added dedicated `dmarc_reports`, `dmarc_records`, `tls_reports`, and `tls_records` storage tables
* **New**: Dashboard UI — added DMARC Reports and TLSRPT Reports tabs with report summary cards, detailed record views, manual report uploads, and report deletion

### 1.8.2
* **Fixed**: email alerts not sent for DMARC `warning` and MTA-STS `warning` statuses — `mtasts_warning` and `dmarc_warning` flags now trigger for all non-OK statuses
* **Fixed**: email alerts not sent for DKIM `missing` status — `dkim_warning` flag now correctly includes `missing` status
* **Added**: `pn_mailguard_alert_level` setting — choose notification level: All issues (default, warnings + errors), Errors only (DNSBL, SPF missing, DKIM errors/missing, scan failures), or None (disable email notifications)
* **Added**: Notification level selector in onboarding wizard (Step 3)
* **Added**: Notification level selector in Advanced tab under Alert Configuration
* **Changed**: "Errors only" level now includes SPF missing and DKIM error/missing as real errors per industry standards; DMARC, MTA-STS, PTR, SPF warnings remain warnings

### 1.8.1
* Added: Single source of truth — new `build_report_data()` method centralises all data collection for AI analysis, AI chat, JSON export, and email alerts
* Fixed: Chat AI omitted MTA-STS data from context — AI now sees MTA-STS status and gives accurate responses
* Fixed: Email alert showed "MTA-STS policy not configured or invalid" even when policy existed — now correctly shows 🔴 missing or 🟡 warning
* Refactored: `ajax_export_report()` now uses `build_report_data()` instead of 4 separate DNS calls
* Refactored: `analyze()` and `chat()` both use `build_report_data()` — guaranteed alignment across all output paths
* Added: DNS analysis cache (transient) — Monitors tab analyzers now show full check tables from the last manual or cron scan, without live DNS lookups on page load
* Added: `cache_dns_analysis()` in scanner — runs SPF/DMARC/DKIM/MTA-STS analysis after each email scan and stores results in a 24h transient
* Added: Data/ora ultima scansione accanto a "Last scan" nelle sezioni SPF, DMARC, DKIM, MTA-STS Analyzer e DNSBL Blacklist Check
* Changed: Log cleanup now keeps the most recent N rows (default 30) instead of deleting by date — prevents unbounded growth while preserving history
* Added: `get_keep_rows()` helper in logger — UI label and SQL LIMIT now dynamically follow the filter value
* Changed: Removed 4 synchronous DNS lookups (`SPF::analyze`, `DMARC::analyze`, `DKIM::analyze`, `MTA-STS::analyze`) from `render_monitors()` — page load dropped from 4-20s to <0.1s
* Changed: JSON export uses `build_report_data()` instead of 4 separate calls
* Maintainability: Adding future features (BIMI, TLS-RPT, etc.) requires modifying only `build_report_data()` — all consumers pick up changes automatically

### 1.8.0
* Changed: JavaScript code consolidated — all AJAX handlers moved from inline PHP templates to admin.js
* Removed: Duplicate JS code eliminated (render_dashboard_js, render_dnstools_js, inline script in Advanced tab)
* Fixed: MTA-STS "Analyze" button in DNS & IP Tools tab now correctly triggers the AJAX call
* Fixed: IPv6 DNSBL message now shown as blue info instead of green "CLEAN" pass
* Added: MTA-STS in AI Analysis prompt — AI now sees and reports MTA-STS status
* Added: Export Report now includes mtasts in dns_configuration
* Added: Database migration for mtasts_data column in AI results table
* Added: DMARC, DKIM and MTA-STS sections to email alert body
* Added: DMARC, DKIM and MTA-STS badges to recent scans cards
* Added: DMARC, DKIM and MTA-STS summary icons in email alerts (🔴🟡)
* Added: DMARC, DKIM and MTA-STS issues now trigger alert emails
* Added: MTA-STS field in DNSBL logger details
* Added: Rate limiting (30 seconds) on AJAX scan endpoints
* Added: sanitize_text_field() on DNS-originated data in alert emails
* Added: CSS table-layout:fixed + word-break:break-word on analyzer tables
* Changed: md5() replaced with hash('sha256', ...) in crypto fallback
* Fixed: AI format JSON now includes MTA-STS in valid components list
* Fixed: Migration from v1.7.x now adds mtasts_data column on plugins_loaded
* Maintainability: All client-side behaviour now lives in a single file (assets/admin.js)

### 1.7.9
* New: MTA-STS Analyzer (RFC 8461) — DNS record, policy file, mode, MX list, max_age validation
* New: MTA-STS badge in global status bar (Email & MX Monitor tab)
* New: MTA-STS section in DNS Record Status cards and DNS & IP Tools tab
* New: MTA-STS quick check integrated into Email Monitor scanner
* Changed: AI prompt updated to include MTA-STS in plugin checks
* Added: Italian translations for MTA-STS related strings

### 1.7.8
* Improved: DNSBL Blacklist Check section now uses consistent white background card matching other sections
* Changed: Export / Support tab — removed promotional box, replaced with simple "by PointNet" credit link
* Added: AI sections show a warning and disable buttons when Gemini API key is missing, with direct link to Advanced tab
* Improved: AI prompt updated — DNSBL count corrected from 5 to 9, IPv6 support added, new features documented (GeoIP, WHOIS, Export)
* Changed: AI language detection — no longer hardcoded to Italian; responds in WordPress locale language, or in the same language as the user's question for chat
* Added: Recent scans cards now show the monitored email/IP in a header chip for clear context
* Improved: DNSBL Blacklist Check title now displays the scanned IP address
* Added: Custom IP Monitor scan history now shows the historical IP address next to each scan date (terminal-style dark badge)
* Changed: Removed duplicate "Alert email" field from inline edit forms (Email Monitor and Custom IP Monitor) — now configurable only in Onboarding and Advanced tab
* Added: Alert email field now present in the Advanced tab under a dedicated "Alert Configuration" section
* Changed: Email Monitor inline edit label "Email" improved to "Email da monitorare" for clarity
* Added: Italian translations for all new strings
* Changed: Global status bar IP badge now shows MX-resolved mail server IP from last email scan instead of Custom IP Monitor status
* Changed: WordPress Required at least updated from 6.5 to 7.0
* Fixed: PHPCS error — esc_attr/esc_html escaping on IP MX badge output

### 1.7.7
* New: Custom IP tab separated from Monitors — IP monitor in dedicated tab
* New: Recent scans now show colour-coded badges for each check: SPF, DMARC, DKIM, PTR, SERVER, DNSBL
* New: DMARC and DKIM quick check integrated into Email Monitor scanner
* New: Auto-detected MX IP shown in Email Monitor card
* New: DNSBL Blacklist Check section shown as colour-coded badge grid on Monitors tab
* New: IP Monitor placeholder with "Add IP" button when not configured
* New: Auto-fill alert email from monitored email during onboarding wizard
* Fixed: DMARC warning/error and DKIM warning/error now affect scan status
* Fixed: Uninstall checkbox now correctly saves unchecked state
* Changed: Tabs renamed to "Email & MX Monitor" and "Custom IP Monitor"
* Fixed: WordPress Plugin Check compliance — %i placeholders for table names, unified prepared statements
* Fixed: PHPCS warnings — interpolated table names, load_plugin_textdomain removed
* Updated: Italian translation (.pot/.po) for v1.7.7

### 1.7.6
* Fixed: WordPress Plugin Check compliance — translators comments, ordered placeholders, escaping, unslash, variable prefixing
* Fixed: readme.txt — blacklist count updated from 5 to 9
* Removed: load_plugin_textdomain() manual call (WP handles it automatically since 4.6 for hosted plugins)

### 1.7.5
* **Security**: Gemini API key encrypted with AES-256-CBC before database storage
* **Security**: API key sent via `x-goog-api-key` header instead of URL query string
* **Security**: API key field shows `********` placeholder — actual key never visible
* **IPv6**: DNSBL checks now detect IPv6 and show clear message (only 1 of 9 blacklists supports IPv6)
* **IPv6**: WHOIS lookup now supports IPv6 addresses (rdap.org API)
* **IPv6**: IP Monitor now accepts IPv6 (PTR/GeoIP/WHOIS work; DNSBL shows informative message)
* **IPv6**: IP Analysis tool accepts IPv6 for PTR, GeoIP, WHOIS
* Added: `includes/class-crypto.php` — AES-256-CBC encryption helper using WordPress SECURE_AUTH_KEY

### 1.7.4
* New: Export / Support tab — download full diagnostic JSON report for assistance or AI external analysis
* New: Anonymize option in export — partially masks email and IP addresses for GDPR-safe sharing
* New: GDPR disclaimer in Advanced tab — visible warning about Google Gemini API data transfer
* New: 9 DNSBL blacklists (added Abusix, SPFBL, DroneBL, LashBack UBL)
* New: Coloured terminal details — log entries are now colour-coded per line (green for CLEAN, red for LISTED, yellow for WARNINGS)
* Improved: Onboarding wizard now clarifies that the IP monitor is separate from the auto-detected mail server IP
* Improved: Monitors tab AI sections moved to Export / Support tab
* Improved: Tooltip ℹ️ on monitor cards explains difference between Email and IP monitors
* Fixed: AI Chat not working in Export / Support tab (JS class selection issue)
* Fixed: Edit monitor buttons opening and immediately closing (double binding fix)
* Fixed: Dead code removed from class-mailer.php (duplicate error check)
* Fixed: Dead code removed from render_dashboard_js() (refreshLogs, duplicate diagnosis handlers)

### 1.7.3
* Added: External services section in readme with full disclosure of third-party API calls
* Added: Multisite disclaimer — plugin not tested on network installations
* Added: Uninstall behavior option — users can choose to keep or delete data on uninstall
* Added: .distignore for clean WordPress.org SVN deployment
* Fixed: DKIM selector detection — removed error suppression operator (@) from DNS query
* Fixed: AJAX handlers now use wp_die('0', 403) instead of deprecated wp_die(-1)
* Fixed: Missing options in uninstall.php (gemini_key, gemini_model, available_models transient)
* Improved: CSS and JavaScript extracted to external files for better performance and maintainability
* Improved: Assets are now properly enqueued with versioning and dependency declarations

### 1.7.2
* Fixed: GeoIP lookup — switched from ip-api.com (HTTP 403) to ipwhois.app for reliable geolocation
* Fixed: WHOIS lookup — replaced fsockopen (TCP port 43, often blocked) with RDAP HTTPS API (rdap.org)
* Fixed: Monitor inline edit no longer clears the other monitor (sending email edit no longer removes IP and vice versa)
* Fixed: Advanced tab "Save Settings" no longer clears Email/IP monitors (save_settings now uses isset() check)
* New: DKIM Selector auto-detection in onboarding wizard (Step 4 with 🔍 Detect button)
* New: 🔄 Fetch Models button in Advanced tab — refresh available Gemini models list without reloading
* New: Models cache automatically cleared when API key changes
* Updated Italian translation (.pot/.po)

### 1.7.1
* New: IP Analysis section in DNS & IP Tools tab — analyze any IPv4 address with DNSBL, PTR, GeoIP and WHOIS lookups
* New: GeoIP lookup — country, region, city, ISP, ASN via ip-api.com (free, no API key required)
* New: WHOIS lookup — IP block owner, range, organization via regional internet registries (RIRs)
* New: Inline edit for monitor cards — ✏️ button to change email/IP/alert email directly from the Monitors tab
* Changed: Tab "Settings" renamed to "Advanced" — now only contains DKIM Selector and Gemini AI config
* Changed: Monitor configuration removed from Advanced tab — now editable directly via the Monitor cards
* Changed: Tab "DNS Tools" renamed to "DNS & IP Tools" — expanded with IP analysis section
* Updated Italian translation (.pot/.po)

### 1.7.0
* New: Gemini AI model selector — fetch available models from Gemini API and choose your preferred model in Settings
* New: PN_MAILGUARD_GEMINI_MODEL constant to set the model in wp-config.php
* New: PN_MAILGUARD_GEMINI_KEY constant to set the API key in wp-config.php (replaces PN_MAILGUARD_OPENAI_KEY)
* New: AI Chat — ask free-text questions about email deliverability directly in the Monitors tab (💬 Chat with AI)
* New: Chat supports Italian, Italian prompt for deliverability expert context
* New: PLUGIN_CONTEXT constant — AI now knows what the plugin does, avoids suggesting duplicate services
* Changed: Default AI model switched from GPT-4o-mini to gemini-3.1-flash-lite (Gemini API)
* Changed: AI analysis card uses the same configured model
* Changed: Plugin version bumped to 1.7.0
* Removed: OpenAI API support — migrated to Google Gemini API

### 1.6.3
* New: AI-powered deliverability analysis with GPT-4o-mini via OpenAI API
* New: "Monitors" tab with full SPF/DMARC/DKIM check tables inline
* New: AI Analysis card in Monitors tab — score, severity, issues, strengths, next steps
* New: AJAX endpoint for on-demand AI analysis
* New: Database table for AI analysis results
* New: PN_MAILGUARD_OPENAI_KEY constant to activate AI in wp-config.php
* Updated Italian translation (.po/.pot)

### 1.6.1
* Added monitor labels to alert emails — subject now shows [Email Monitor] or [IP Monitor]
* Added "Monitor:" line in alert body identifying which monitor triggered the alert
* Fixed SPF WARNING and combined status colors (ALERT + PTR + SPF) — now correctly shown in yellow
* Fixed console disappearing after "Run IP/Email Diagnosis" — results stay visible, log cards refresh via AJAX
* Fixed "Run Scheduled Scan Now" — now shows both Email and IP results directly
* Fixed cron event auto-recovery — event re-created automatically if missing or past due
* Fixed alert email not sending when only SPF issues are detected
* Added WP-Cron delay warning when scheduled scan is past due
* Added active monitors info box in Dashboard showing which IPs are being monitored
* Various UI improvements and bug fixes

### 1.6.0
* Redesigned admin interface — 3 tabs: Dashboard, DNS Tools, Settings
* Dashboard tab now shows global status indicator, quick action buttons, scan results and recent logs
* New onboarding wizard guides first-time users through initial setup in 2 minutes
* DNS Tools tab unifies SPF, DMARC and DKIM analysis with a single domain input and "Analyze All Records" button
* Scan results now display instantly as colour-coded cards — removed the slow typewriter terminal
* Quick action buttons in Dashboard for one-click Email and IP diagnosis
* Tooltip hints on disabled buttons explaining what needs to be configured first
* Settings tab is now the only place for configuration — removed duplicate forms from old Monitors tab
* DKIM selector row shown automatically when analyzing DNS records
* Plugin renamed from "PointNet Mail Guard AI" to "PointNet Mail Guard" (continued)

### 1.5.0
* Redesigned admin interface — 4 tabs: Overview, Monitors, Analyzers, Settings
* Overview tab with global status indicator, SPF/DMARC/DKIM badges, monitor logs and analyzer cards
* Monitors tab — Email and IP side by side, responsive on mobile
* Analyzers tab — SPF, DMARC and DKIM in three horizontal cards
* Settings tab — all configuration in one place
* Plugin renamed from "PointNet Mail Guard AI" to "PointNet Mail Guard"
* PointNet professional services link added to Overview

### 1.4.0
* Added DKIM Analyzer tab
* Auto-detection of common DKIM selectors (Google Workspace, Microsoft 365, Mailchimp, Mailgun, etc.)
* Checks: record presence, version tag, key type (RSA/Ed25519), public key presence, RSA key length, test mode flag, hash algorithm
* Manual selector input as fallback when auto-detection fails
* Italian translation updated

### 1.3.0
* Added DMARC Analyzer tab with full RFC 7489 analysis
* Checks: record presence, syntax, policy strength (none/quarantine/reject), percentage, aggregate reports (rua), subdomain policy, alignment, SPF correlation
* Italian translation updated

### 1.2.0
* Added dedicated SPF Analyzer tab with full RFC 7208 analysis
* 9 individual SPF checks: record presence, duplicates, length, qualifier, DNS lookup count, void lookups, ptr mechanism, exists mechanism, +all detection
* Automatic detection of known email providers (Google Workspace, Amazon SES, Mailgun, Brevo, etc.)
* Visual results with colour-coded pass/warning/error indicators
* SPF domain saved across sessions
* Italian translation updated

### 1.1.0
* Added SPF record validation to Email Monitor
* SPF status shown in real-time terminal console (green = ok, yellow = missing or invalid)
* SPF check included in email alerts and diagnostic logs
* Italian translation updated

### 1.0.0
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

## License

GPLv2 or later — see [LICENSE](LICENSE)