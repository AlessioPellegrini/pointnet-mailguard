<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_AI
 *
 * Builds structured prompts from scan + DNS analysis results and calls
 * Google Gemini API returning a deliverability report.
 *
 * Usage:
 *   $report = PN_Mailguard_AI::analyze($email, $domain, $selector);
 */
class PN_Mailguard_AI {

    const string TABLE_AI = 'pointnet_mailguard_ai_results';

    /**
     * Default AI model ID (fallback if none configured).
     */
    const string DEFAULT_MODEL = 'gemini-3.1-flash-lite';
    /**
     * How long to cache the models list (in seconds).
     */
    const int MODELS_CACHE_TTL = 86400; // 24 hours
    /**
     * Transient key for cached models list.
     */
    const string MODELS_TRANSIENT = 'pn_mailguard_available_models';

    /**
     * Plugin context string that tells the AI what PointNet Mail Guard is,
     * what it already checks, and what it does not cover.
     *
     * Used in analysis and chat prompts so the AI does not suggest
     * duplicate features or external tools for checks already built in.
     *
     * @var string
     */
    const string PLUGIN_CONTEXT = "Sei l'assistente AI integrato nel plugin WordPress \"PointNet Mail Guard\". "
        . "Il plugin monitora la deliverability delle email con due monitor indipendenti:\n"
        . "- Email Monitor: rileva automaticamente il server di posta tramite lookup MX\n"
        . "- IP Monitor: monitoraggio diretto di un indirizzo IPv4 o IPv6\n\n"
        . "Il plugin esegue GIÀ automaticamente i seguenti controlli:\n"
        . "- DNSBL: SpamCop, Barracuda, SORBS, UCEProtect L1, PSBL, Abusix, SPFBL, DroneBL, LashBack UBL (9 blacklist)\n"
        . "- PTR (reverse DNS) con alert su record mancante\n"
        . "- SPF: analisi RFC 7208 completa (9 controlli, rilevamento provider)\n"
        . "- DMARC: analisi RFC 7489 (policy strength, correlazione SPF)\n"
        . "- DKIM: auto-rilevamento selettore, tipo/lunghezza chiave, test mode, hash\n"
        . "- MTA-STS: analisi RFC 8461 (record DNS _mta-sts, policy JSON, modalità enforce/testing/none, MX list, max_age)\n"
        . "- DNSSEC: analisi RFC 4033-4035 (verifiche record DS, DNSKEY e flag AD di autenticazione)\n"
        . "- Rilevamento server condiviso vs dedicato\n"
        . "- GeoIP: paese, regione, città, ISP e ASN via ipwhois.app\n"
        . "- WHOIS: proprietario blocco IP, range, organizzazione via RDAP\n"
        . "- IP Analysis tool: analisi DNSBL + PTR + GeoIP + WHOIS per qualsiasi IPv4\n\n"
        . "Il plugin offre inoltre:\n"
        . "- Analisi AI della deliverability (questo stesso assistente)\n"
        . "- Chat AI per domande sulla deliverability\n"
        . "- Export report JSON completo per supporto o analisi esterna\n\n"
        . "Il plugin non fornisce servizi SMTP relay (usa wp_mail() per gli alert, compatibile con WP Mail SMTP, FluentSMTP, Easy WP SMTP)\n"
        . "Il plugin NON modifica record DNS\n"
        . "Il plugin NON fa warm-up IP\n\n"
        . "NON suggerire servizi esterni o tool che duplicano i controlli già integrati (SPF, DMARC, DKIM, MTA-STS, DNSSEC, DNSBL, PTR, GeoIP, WHOIS sono già coperti dal plugin).\n"
        . "Se l'utente chiede servizi professionali di deliverability oltre a quanto già offerto dal plugin, suggerisci di contattare gli sviluppatori: PointNet (https://www.pointnet.it/).\n"
        . "Sii conciso e pertinente allo specifico contesto del plugin e del dominio monitorato.\n";

    /**
     * Gather ALL deliverability data for a domain — the single source of truth.
     *
     * This method is used by analyze(), chat(), and export_report() so that
     * all three paths always see the same, complete data set.
     * When adding a new check module, add it HERE and all consumers will
     * automatically pick it up.
     *
     * @param  string $domain   Domain to analyse
     * @param  string $email    Monitored email address (optional)
     * @param  string $selector DKIM selector (optional)
     * @return array            Structured report data
     */
    public static function build_report_data(string $domain, string $email = '', string $selector = ''): array {
        // 1. Scan data (MX, DNSBL, PTR, shared server)
        $scan_data = self::gather_scan($email, $domain);

        // 2. Full DNS analyses
        $spf_data    = PN_Mailguard_SPF::analyze($domain);
        $dmarc_data  = PN_Mailguard_DMARC::analyze($domain);
        $mtasts_data = PN_Mailguard_MTA_STS::analyze($domain);
        $dnssec_data = PN_Mailguard_Dnssec::analyze($domain);

        // 3. DKIM — auto-detect selector if none provided
        $dkim_data = null;
        if (empty($selector)) {
            $d = PN_Mailguard_DKIM::autodetect($domain);
            if (!empty($d['selector'])) {
                $selector = $d['selector'];
            }
        }
        if (!empty($selector)) {
            $dkim_data = PN_Mailguard_DKIM::analyze($domain, $selector);
        }

        return [
            'scan'   => $scan_data,
            'spf'    => $spf_data,
            'dmarc'  => $dmarc_data,
            'dkim'   => $dkim_data,
            'mtasts' => $mtasts_data,
            'dnssec' => $dnssec_data,
        ];
    }

    /**
     * Analyse the full deliverability status for the given email domain.
     *
     * @param  string $email    Monitored email address (or empty)
     * @param  string $domain   Domain to analyse
     * @param  string $selector DKIM selector (optional)
     * @return array            AI report or error array
     */
    public static function analyze(string $email, string $domain, string $selector = ''): array {
        // 1. Gather all data via the single source of truth
        $data = self::build_report_data($domain, $email, $selector);

        $scan_data    = $data['scan'];
        $spf_data     = $data['spf'];
        $dmarc_data   = $data['dmarc'];
        $dkim_data    = $data['dkim'];
        $mtasts_data  = $data['mtasts'];
        $dnssec_data  = $data['dnssec'];

        // 2. Build prompt
        $prompt = self::build_prompt($scan_data, $spf_data, $dmarc_data, $dkim_data, $mtasts_data, $dnssec_data, $domain);

        // 3. Call Gemini API
        $result = self::call_api($prompt);

        // 4. Save result
        if (!empty($result) && empty($result['error'])) {
            self::save_result($domain, $result, $scan_data, $spf_data, $dmarc_data, $dkim_data, $mtasts_data);
        }

        return $result;
    }

    /**
     * Check if AI is configured and available.
     */
    public static function is_available(): bool {
        if (defined('PN_MAILGUARD_GEMINI_KEY') && !empty(PN_MAILGUARD_GEMINI_KEY)) {
            return true;
        }
        $key = self::get_api_key();
        return !empty($key);
    }

    /**
     * Gather scan data for the monitored domain.
     */
    private static function gather_scan(string $email, string $domain): array {
        if (!empty($email) && is_email($email)) {
            return PN_Mailguard_Scanner::run_email($email);
        }
        $spf = PN_Mailguard_SPF::check($domain);
        return [
            'domain'       => $domain,
            'email'        => $email,
            'mx_ip'        => '',
            'mx_host'      => '',
            'dnsbl'        => [],
            'is_alert'     => false,
            'ptr'          => '',
            'ptr_warning'  => false,
            'spf_record'   => $spf['spf_record'],
            'spf_status'   => $spf['spf_status'],
            'spf_warning'  => $spf['spf_warning'],
            'shared_server' => false,
            'wp_ip'        => '',
            'error'        => '',
        ];
    }

    /**
     * Get the preferred language name for the AI based on WordPress locale.
     */
    private static function get_ai_language(): string {
        $locale = get_locale();
        $lang = substr($locale, 0, 2);
        $lang_map = [
            'it' => 'italiano',
            'en' => 'English',
            'fr' => 'français',
            'de' => 'Deutsch',
            'es' => 'español',
            'pt' => 'português',
            'nl' => 'Nederlands',
            'pl' => 'polski',
            'ru' => 'русский',
        ];
        return $lang_map[$lang] ?? 'English';
    }

    /**
     * Build a structured prompt for the AI.
     */
    private static function build_prompt(array $scan, $spf, $dmarc, $dkim, $mtasts, $dnssec, string $domain): string {
        $language = self::get_ai_language();
        $lines = [];

        $lines[] = self::PLUGIN_CONTEXT;
        $lines[] = '';
        $lines[] = "Procedi con l'analisi dei dati seguenti e produci un report JSON valido.";
        $lines[] = "Rispondi SOLO con JSON, nient'altro.";
        $lines[] = "Il campo summary_it deve essere scritto in {$language}.";
        $lines[] = '';

        $lines[] = '=== MONITOR SCAN ===';
        $lines[] = 'Dominio: ' . $domain;
        if (!empty($scan['mx_host'])) $lines[] = 'MX: ' . $scan['mx_host'] . ' → ' . $scan['mx_ip'];
        if (!empty($scan['wp_ip']))   $lines[] = 'WordPress IP: ' . $scan['wp_ip'] . ' | Server: ' . ($scan['shared_server'] ? 'CONDIVISO' : 'DEDICATO');
        if (!empty($scan['ptr']))     $lines[] = 'PTR: ' . $scan['ptr'] . ($scan['ptr_warning'] ? ' ⚠️ WARNING' : ' ✅');
        if (!empty($scan['dnsbl'])) {
            $dnsbl_parts = [];
            foreach ($scan['dnsbl'] as $name => $val) {
                $icon = $val === 'LISTED' ? '🔴' : '✅';
                $dnsbl_parts[] = "$name: $icon $val";
            }
            $lines[] = 'DNSBL: ' . implode(' | ', $dnsbl_parts);
        }
        $lines[] = '';

        if ($spf) {
            $lines[] = '=== SPF ANALYSIS (RFC 7208) ===';
            $lines[] = 'Record: ' . ($spf['record'] ?? 'N/A');
            $lines[] = 'Status: ' . $spf['status'];
            $lines[] = "Passed: {$spf['passed']} | Warnings: {$spf['warnings']} | Errors: {$spf['errors']}";
            if (!empty($spf['checks'])) {
                foreach ($spf['checks'] as $c) {
                    $icon = match ($c['status']) {
                        'ok'      => '✅',
                        'warning' => '⚠️',
                        default   => '🔴',
                    };
                    $lines[] = "  $icon " . $c['title'];
                }
            }
            if (!empty($spf['providers'])) {
                $lines[] = 'Provider rilevati: ' . implode(', ', $spf['providers']);
            }
            $lines[] = '';
        }

        if ($dmarc) {
            $lines[] = '=== DMARC ANALYSIS (RFC 7489) ===';
            $lines[] = 'Record: ' . ($dmarc['record'] ?? 'N/A');
            $lines[] = 'Status: ' . $dmarc['status'];
            $lines[] = "Passed: {$dmarc['passed']} | Warnings: {$dmarc['warnings']} | Errors: {$dmarc['errors']}";
            if (!empty($dmarc['checks'])) {
                foreach ($dmarc['checks'] as $c) {
                    $icon = match ($c['status']) {
                        'ok'      => '✅',
                        'warning' => '⚠️',
                        'info'    => 'ℹ️',
                        default   => '🔴',
                    };
                    $lines[] = "  $icon " . $c['title'];
                }
            }
            $lines[] = '';
        }

        if ($dkim) {
            $lines[] = '=== DKIM ANALYSIS ===';
            $lines[] = 'Selector: ' . ($dkim['selector'] ?? 'N/A');
            $lines[] = 'Record: ' . ($dkim['record'] ?? 'N/A');
            $lines[] = 'Status: ' . $dkim['status'];
            $lines[] = "Passed: {$dkim['passed']} | Warnings: {$dkim['warnings']} | Errors: {$dkim['errors']}";
            if (!empty($dkim['checks'])) {
                foreach ($dkim['checks'] as $c) {
                    $icon = match ($c['status']) {
                        'ok'      => '✅',
                        'warning' => '⚠️',
                        default   => '🔴',
                    };
                    $lines[] = "  $icon " . $c['title'];
                }
            }
            $lines[] = '';
        }

        if ($mtasts) {
            $lines[] = '=== MTA-STS ANALYSIS (RFC 8461) ===';
            $lines[] = 'Record: ' . ($mtasts['record'] ?? 'N/A');
            $lines[] = 'Status: ' . $mtasts['status'];
            $lines[] = "Passed: {$mtasts['passed']} | Warnings: {$mtasts['warnings']} | Errors: {$mtasts['errors']}";
            if (!empty($mtasts['mx'])) {
                $lines[] = 'MX hosts: ' . implode(', ', $mtasts['mx']);
            }
            if (!empty($mtasts['mode'])) {
                $lines[] = 'Mode: ' . $mtasts['mode'];
            }
            if (!empty($mtasts['max_age'])) {
                $lines[] = 'max_age: ' . $mtasts['max_age'];
            }
            if (!empty($mtasts['checks'])) {
                foreach ($mtasts['checks'] as $c) {
                    $icon = match ($c['status']) {
                        'ok'      => '✅',
                        'warning' => '⚠️',
                        default   => '🔴',
                    };
                    $lines[] = "  $icon " . $c['title'];
                }
            }
            $lines[] = '';
        }

        if ($dnssec) {
            $lines[] = '=== DNSSEC ANALYSIS (RFC 4033-4035) ===';
            $lines[] = 'Status: ' . ($dnssec['status'] ?? 'N/A');
            $lines[] = 'Enabled: ' . (($dnssec['enabled'] ?? false) ? 'YES' : 'NO');
            $lines[] = 'AD Flag: ' . (($dnssec['ad_flag'] ?? false) ? 'YES' : 'NO');
            if (!empty($dnssec['details'])) {
                foreach ($dnssec['details'] as $c) {
                    $icon = match ($c['status']) {
                        'pass'    => '✅',
                        'warning' => '⚠️',
                        'info'    => 'ℹ️',
                        default   => '🔴',
                    };
                    $lines[] = "  $icon " . ($c['label'] ?? '') . ': ' . ($c['message'] ?? '');
                }
            }
            $lines[] = '';
        }

        $lines[] = '=== FORMATO JSON RICHIESTO ===';
        $lines[] = '{';
        $lines[] = '  "severity": "ok|warning|critical",';
        $lines[] = '  "score": 0-100,';
        $lines[] = '  "summary_it": "riassunto in italiano (max 2 frasi)",';
        $lines[] = '  "issues": [';
        $lines[] = '    { "component": "SPF|DMARC|DKIM|MTA-STS|DNSSEC|DNSBL|PTR|MX|GENERAL", "severity": "error|warning|info", "title": "...", "description": "...", "fix": "..." }';
        $lines[] = '  ],';
        $lines[] = '  "strengths": ["..."],';
        $lines[] = '  "next_steps": ["..."]';
        $lines[] = '}';

        return implode("\n", $lines);
    }

    /**
     * Retrieve the Gemini API key.
     *
     * Priority: 1) PN_MAILGUARD_GEMINI_KEY constant, 2) decrypted saved option.
     *
     * @return string The API key, or empty string if not configured.
     */
    private static function get_api_key(): string {
        if (defined('PN_MAILGUARD_GEMINI_KEY') && !empty(PN_MAILGUARD_GEMINI_KEY)) {
            return PN_MAILGUARD_GEMINI_KEY;
        }

        $saved = get_option('pn_mailguard_gemini_key', '');

        if (empty($saved)) {
            return '';
        }

        // If the value looks encrypted, decrypt it.
        // If not encrypted (legacy plaintext key), encrypt it for the future.
        if (PN_Mailguard_Crypto::is_encrypted($saved)) {
            return PN_Mailguard_Crypto::decrypt($saved);
        }

        // Legacy plaintext key — migrate to encrypted storage
        $encrypted = PN_Mailguard_Crypto::encrypt($saved);
        if (!empty($encrypted)) {
            update_option('pn_mailguard_gemini_key', $encrypted);
        }

        return $saved;
    }

    /**
     * Call the Gemini API.
     */
    private static function call_api(string $prompt): array {
        $api_key = self::get_api_key();

        if (empty($api_key)) {
            return [
                'error'      => true,
                'error_msg'  => __('AI not configured. Add your Gemini API key in Settings.', 'pointnet-mailguard'),
                'severity'   => 'warning',
                'score'      => 0,
                'summary_it' => '',
                'issues'     => [],
                'strengths'  => [],
                'next_steps' => [],
            ];
        }

        $model = self::get_configured_model();
        $response = wp_remote_post(
            'https://generativelanguage.googleapis.com/v1beta/models/' . $model . ':generateContent',
            [
                'timeout' => 30,
                'headers' => [
                    'Content-Type'  => 'application/json',
                    'x-goog-api-key' => $api_key,
                ],
                'body' => wp_json_encode([
                    'contents' => [
                        [
                            'parts' => [
                                ['text' => $prompt],
                            ],
                        ],
                    ],
                    'generationConfig' => [
                        'temperature'     => 0.3,
                        'maxOutputTokens' => 1500,
                    ],
                ]),
            ]
        );

        if (is_wp_error($response)) {
            return [
                'error'      => true,
                'error_msg'  => $response->get_error_message(),
                'severity'   => 'error',
                'score'      => 0,
                'summary_it' => '',
                'issues'     => [],
                'strengths'  => [],
                'next_steps' => [],
            ];
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        // Extract text from Gemini response format
        $text = '';
        if (isset($body['candidates'][0]['content']['parts'][0]['text'])) {
            $text = $body['candidates'][0]['content']['parts'][0]['text'];
        } elseif (isset($body['candidates'][0]['finishReason']) && $body['candidates'][0]['finishReason'] !== 'STOP') {
            return [
                'error'      => true,
                /* translators: %s: Gemini API finish reason */
                'error_msg'  => sprintf(__('Gemini API error: %s', 'pointnet-mailguard'), $body['candidates'][0]['finishReason'] ?? 'unknown'),
                'severity'   => 'error',
                'score'      => 0,
                'summary_it' => '',
                'issues'     => [],
                'strengths'  => [],
                'next_steps' => [],
            ];
        } elseif (!empty($body['error']['message'])) {
            return [
                'error'      => true,
                'error_msg'  => 'Gemini API: ' . $body['error']['message'],
                'severity'   => 'error',
                'score'      => 0,
                'summary_it' => '',
                'issues'     => [],
                'strengths'  => [],
                'next_steps' => [],
            ];
        }

        if (empty($text)) {
            return [
                'error'      => true,
                'error_msg'  => __('AI returned an empty response.', 'pointnet-mailguard'),
                'severity'   => 'error',
                'score'      => 0,
                'summary_it' => '',
                'issues'     => [],
                'strengths'  => [],
                'next_steps' => [],
            ];
        }

        // Remove markdown code fences
        $text = preg_replace('/^```(?:json)?\s*|\s*```$/i', '', $text);

        // Use json_validate() in PHP 8.3 for cleaner validation
        if (!json_validate($text)) {
            return [
                'error'      => true,
                'error_msg'  => __('AI response could not be parsed.', 'pointnet-mailguard'),
                'raw'        => $text,
                'severity'   => 'warning',
                'score'      => 0,
                'summary_it' => '',
                'issues'     => [],
                'strengths'  => [],
                'next_steps' => [],
            ];
        }

        $parsed = json_decode($text, true);

        if (!isset($parsed['severity'])) {
            return [
                'error'      => true,
                'error_msg'  => __('AI response could not be parsed.', 'pointnet-mailguard'),
                'raw'        => $text,
                'severity'   => 'warning',
                'score'      => 0,
                'summary_it' => '',
                'issues'     => [],
                'strengths'  => [],
                'next_steps' => [],
            ];
        }

        $defaults = [
            'severity'   => 'warning',
            'score'      => 50,
            'summary_it' => '',
            'issues'     => [],
            'strengths'  => [],
            'next_steps' => [],
        ];

        return array_merge($defaults, $parsed);
    }

    /**
     * Save AI analysis result to the database.
     */
    public static function save_result(string $domain, array $result, $scan, $spf, $dmarc, $dkim, $mtasts = null): void {
        global $wpdb;
        $table = $wpdb->prefix . self::TABLE_AI;

        $wpdb->insert($table, [
            'domain'     => sanitize_text_field($domain),
            'severity'   => sanitize_text_field($result['severity'] ?? 'warning'),
            'score'      => intval($result['score'] ?? 50),
            'summary_it' => sanitize_text_field($result['summary_it'] ?? ''),
            'report'     => wp_json_encode($result),
            'scan_data'  => wp_json_encode($scan),
            'spf_data'   => wp_json_encode($spf),
            'dmarc_data' => wp_json_encode($dmarc),
            'dkim_data'  => wp_json_encode($dkim),
            'mtasts_data' => wp_json_encode($mtasts),
        ]);
    }

    /**
     * Get the latest AI analysis result for a domain.
     */
    public static function get_latest(string $domain = ''): ?object {
        global $wpdb;
        $table = $wpdb->prefix . self::TABLE_AI;

        if (!empty($domain)) {
            return $wpdb->get_row(
                $wpdb->prepare(
                    "SELECT * FROM %i WHERE domain = %s ORDER BY created_at DESC LIMIT 1",
                    $table,
                    $domain
                )
            );
        }

        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM %i ORDER BY created_at DESC LIMIT 1",
                $table
            )
        );
    }

    /**
     * Fetch available Gemini models that support generateContent.
     *
     * Calls the Gemini Models API and caches results for 24 hours.
     *
     * @return array Associative array of [modelId => displayName], or empty array on failure.
     */
    public static function fetch_available_models(): array {
        // Return cached results if available
        $cached = get_transient(self::MODELS_TRANSIENT);
        if (false !== $cached) {
            return $cached;
        }

        $api_key = self::get_api_key();

        if (empty($api_key)) {
            return [];
        }

        $response = wp_remote_get(
            'https://generativelanguage.googleapis.com/v1beta/models',
            [
                'timeout' => 15,
                'headers' => [
                    'x-goog-api-key' => $api_key,
                ],
            ]
        );

        if (is_wp_error($response)) {
            return [];
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (empty($body['models'])) {
            return [];
        }

        $models = [];
        foreach ($body['models'] as $m) {
            $name = $m['name'] ?? '';
            // Only include models that support generateContent
            if (empty($name)) {
                continue;
            }
            $supported = $m['supportedGenerationMethods'] ?? [];
            if (!in_array('generateContent', $supported, true)) {
                continue;
            }
            // Extract short ID from "models/gemini-2.0-flash"
            $id_parts = explode('/', $name);
            $short_id = end($id_parts);
            $display  = $m['displayName'] ?? $short_id;
            $models[$short_id] = $display;
        }

        // Cache for 24 hours
        set_transient(self::MODELS_TRANSIENT, $models, self::MODELS_CACHE_TTL);

        return $models;
    }

    /**
     * Get the currently configured AI model ID.
     *
     * Priority: 1) PN_MAILGUARD_GEMINI_MODEL constant, 2) saved option, 3) DEFAULT_MODEL.
     *
     * @return string Model ID (e.g. 'gemini-2.0-flash').
     */
    public static function get_configured_model(): string {
        if (defined('PN_MAILGUARD_GEMINI_MODEL') && !empty(PN_MAILGUARD_GEMINI_MODEL)) {
            return PN_MAILGUARD_GEMINI_MODEL;
        }
        $saved = get_option('pn_mailguard_gemini_model', '');
        if (!empty($saved)) {
            return $saved;
        }
        return self::DEFAULT_MODEL;
    }

    /**
     * Invalidate the cached models list (e.g. when API key changes).
     */
    public static function clear_models_cache(): void {
        delete_transient(self::MODELS_TRANSIENT);
    }

    /**
     * Send a free-text question to the configured Gemini model and get a response.
     *
     * Useful for admin chat: ask deliverability questions, get advice, etc.
     * If a domain is provided, the latest scan data and DNS analysis are automatically
     * included as context so the AI can give specific, data-driven answers.
     *
     * @param  string $question The user's question (in Italian or English).
     * @param  string $domain   Optional monitored domain to include latest scan context.
     * @param  string $email    Optional email address for fresh scan data.
     * @param  string $selector Optional DKIM selector.
     * @return string           The model's text response, or an error message.
     */
    public static function chat(string $question, string $domain = '', string $email = '', string $selector = ''): string {
        $api_key = self::get_api_key();

        if (empty($api_key)) {
            return __('AI not configured. Add your Gemini API key in Settings.', 'pointnet-mailguard');
        }

        $model = self::get_configured_model();

        // Build context from fresh data using the single source of truth
        $context_parts = [];
        if (!empty($domain)) {
            $data = self::build_report_data($domain, $email, $selector);

            $scan         = $data['scan'];
            $spf          = $data['spf'];
            $dmarc        = $data['dmarc'];
            $dkim         = $data['dkim'];
            $mtasts       = $data['mtasts'];

            $context_parts[] = '=== DATI DEL TUO DOMINIO (correnti) ===';
            $context_parts[] = 'Dominio monitorato: ' . $domain;

            if (!empty($scan['mx_host'])) {
                $context_parts[] = 'MX: ' . $scan['mx_host'] . ' → ' . $scan['mx_ip'];
            }
            if (!empty($scan['wp_ip'])) {
                $context_parts[] = 'WordPress IP: ' . $scan['wp_ip'];
                $context_parts[] = 'Server: ' . ($scan['shared_server'] ? 'Condiviso (stesso IP di WordPress)' : 'Dedicato');
            }
            if (!empty($scan['ptr'])) {
                $context_parts[] = 'PTR: ' . $scan['ptr'] . ($scan['ptr_warning'] ? ' (WARNING)' : ' (OK)');
            }
            if (!empty($scan['dnsbl'])) {
                foreach ($scan['dnsbl'] as $name => $val) {
                    $context_parts[] = "DNSBL {$name}: {$val}";
                }
            }

            if ($spf) {
                $context_parts[] = 'SPF Status: ' . ($spf['status'] ?? 'N/A');
                $context_parts[] = 'SPF Record: ' . ($spf['record'] ?? 'N/A');
                $context_parts[] = "SPF: Passed {$spf['passed']}, Warnings {$spf['warnings']}, Errors {$spf['errors']}";
                if (!empty($spf['checks'])) {
                    foreach ($spf['checks'] as $c) {
                        $icon = match ($c['status']) {
                            'ok'      => '✅',
                            'warning' => '⚠️',
                            default   => '🔴',
                        };
                        $context_parts[] = "  $icon " . $c['title'];
                    }
                }
            }
            if ($dmarc) {
                $context_parts[] = 'DMARC Status: ' . ($dmarc['status'] ?? 'N/A');
                $context_parts[] = 'DMARC Record: ' . ($dmarc['record'] ?? 'N/A');
                $context_parts[] = "DMARC: Passed {$dmarc['passed']}, Warnings {$dmarc['warnings']}, Errors {$dmarc['errors']}";
                if (!empty($dmarc['checks'])) {
                    foreach ($dmarc['checks'] as $c) {
                        $icon = match ($c['status']) {
                            'ok'      => '✅',
                            'warning' => '⚠️',
                            'info'    => 'ℹ️',
                            default   => '🔴',
                        };
                        $context_parts[] = "  $icon " . $c['title'];
                    }
                }
            }
            if ($dkim) {
                $context_parts[] = 'DKIM Status: ' . ($dkim['status'] ?? 'N/A');
                $context_parts[] = 'DKIM Selector: ' . ($dkim['selector'] ?? 'N/A');
                $context_parts[] = "DKIM: Passed {$dkim['passed']}, Warnings {$dkim['warnings']}, Errors {$dkim['errors']}";
                if (!empty($dkim['checks'])) {
                    foreach ($dkim['checks'] as $c) {
                        $icon = match ($c['status']) {
                            'ok'      => '✅',
                            'warning' => '⚠️',
                            default   => '🔴',
                        };
                        $context_parts[] = "  $icon " . $c['title'];
                    }
                }
            }
            if ($mtasts) {
                $context_parts[] = 'MTA-STS Status: ' . ($mtasts['status'] ?? 'N/A');
                $context_parts[] = 'MTA-STS Record: ' . ($mtasts['record'] ?? 'N/A');
                $context_parts[] = 'MTA-STS Mode: ' . ($mtasts['mode'] ?? 'N/A');
                $context_parts[] = "MTA-STS: Passed {$mtasts['passed']}, Warnings {$mtasts['warnings']}, Errors {$mtasts['errors']}";
                if (!empty($mtasts['checks'])) {
                    foreach ($mtasts['checks'] as $c) {
                        $icon = match ($c['status']) {
                            'ok'      => '✅',
                            'warning' => '⚠️',
                            default   => '🔴',
                        };
                        $context_parts[] = "  $icon " . $c['title'];
                    }
                }
            }
            if (!empty($data['dnssec'])) {
                $dnssec = $data['dnssec'];
                $context_parts[] = 'DNSSEC Status: ' . ($dnssec['status'] ?? 'N/A');
                $context_parts[] = 'DNSSEC Enabled: ' . (($dnssec['enabled'] ?? false) ? 'YES' : 'NO');
            }
        }

        $language = self::get_ai_language();
        $full_prompt = self::PLUGIN_CONTEXT . "\n\n";
        $full_prompt .= "Rispondi in {$language}. Se la domanda dell'utente è in una lingua diversa, rispondi nella stessa lingua della domanda.\n\n";
        if (!empty($context_parts)) {
            $full_prompt .= implode("\n", $context_parts) . "\n\n---\n\n";
        }
        $full_prompt .= "=== DOMANDA DELL'UTENTE ===\n";
        $full_prompt .= $question;

        $response = wp_remote_post(
            'https://generativelanguage.googleapis.com/v1beta/models/' . $model . ':generateContent',
            [
                'timeout' => 30,
                'headers' => [
                    'Content-Type'  => 'application/json',
                    'x-goog-api-key' => $api_key,
                ],
                'body' => wp_json_encode([
                    'contents' => [
                        [
                            'role' => 'user',
                            'parts' => [
                                ['text' => $full_prompt],
                            ],
                        ],
                    ],
                    'generationConfig' => [
                        'temperature'     => 0.7,
                        'maxOutputTokens' => 2048,
                    ],
                ]),
            ]
        );

        if (is_wp_error($response)) {
            return $response->get_error_message();
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        // Extract text from Gemini response format
        if (isset($body['candidates'][0]['content']['parts'][0]['text'])) {
            return $body['candidates'][0]['content']['parts'][0]['text'];
        }

        if (!empty($body['error']['message'])) {
            return 'Gemini API: ' . $body['error']['message'];
        }

        return __('AI returned an empty response.', 'pointnet-mailguard');
    }
}