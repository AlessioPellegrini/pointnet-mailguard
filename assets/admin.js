/**
 * PointNet Mail Guard — Admin JavaScript
 * 
 * All AJAX handlers and UI interactions for the admin dashboard.
 * Dynamic data (nonce, translations, URLs) is passed via pnMailguard object
 * from wp_localize_script().
 */
jQuery(document).ready(function($) {
    'use strict';

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------
    function escHtml(str) {
        return $('<div>').text(str).html();
    }

    // -------------------------------------------------------------------------
    // Dashboard — Run Scheduled Scan
    // -------------------------------------------------------------------------
    if ($('#pn-run-scheduled-btn').length) {
        $('#pn-run-scheduled-btn').on('click', function() {
            var btn = $(this);
            btn.prop('disabled', true).text('⏳ ' + pnMailguard.running);
            $.post(ajaxurl, {
                action: 'pn_mailguard_run_scheduled',
                nonce: pnMailguard.nonce
            }, function(res) {
                if (res.success) {
                    location.reload();
                } else {
                    alert(res.data && res.data.message ? res.data.message : pnMailguard.scanFailed);
                    btn.prop('disabled', false).text('▶️ ' + pnMailguard.runScheduled);
                }
            });
        });
    }

    // -------------------------------------------------------------------------
    // Dashboard — Refresh Logs (legacy, keeps internal reference)
    // -------------------------------------------------------------------------
    function refreshLogs() {
        $.post(ajaxurl, { action: 'pn_mailguard_refresh_logs_email', nonce: pnMailguard.nonce }, function(r) {
            if (r.success && $('#pn-email-log-body').length) {
                $('#pn-email-log-body').html(r.data);
            }
        });
        $.post(ajaxurl, { action: 'pn_mailguard_refresh_logs_ip', nonce: pnMailguard.nonce }, function(r) {
            if (r.success && $('#pn-ip-log-body').length) {
                $('#pn-ip-log-body').html(r.data);
            }
        });
    }

    // -------------------------------------------------------------------------
    // Dashboard — Run Email/IP Diagnosis
    // -------------------------------------------------------------------------
    function runScanDashboard(action, btnId, label) {
        var btn = $('#' + btnId);
        if (!btn.length) return;
        btn.prop('disabled', true).text('⏳ ' + pnMailguard.running);

        $.post(ajaxurl, { action: action, nonce: pnMailguard.nonce }, function(res) {
            if (!res.success) {
                var msg = (res.data && res.data.message) ? res.data.message : pnMailguard.scanFailed;
                alert(msg);
                btn.prop('disabled', false).text(label);
                return;
            }
            location.reload();
        });
    }

    // Attach diagnosis buttons
    $(document).on('click', '#pn-dash-email-btn', function() {
        runScanDashboard('pn_mailguard_start_scan_email', 'pn-dash-email-btn', pnMailguard.runEmailDiagnosis);
    });
    $(document).on('click', '#pn-dash-ip-btn', function() {
        runScanDashboard('pn_mailguard_start_scan_ip', 'pn-dash-ip-btn', pnMailguard.runIpDiagnosis);
    });

    // -------------------------------------------------------------------------
    // Dashboard — AI Analysis
    // -------------------------------------------------------------------------
    $(document).on('click', '#pn-ai-analyze-btn', function() {
        var btn = $(this);
        var resultDiv = $('#pn-ai-result');
        btn.prop('disabled', true).text('⏳ ' + pnMailguard.analyzing);
        resultDiv.html('<p style="color:#999;">⏳ ' + pnMailguard.analyzingEmail + '</p>');

        $.post(ajaxurl, { action: 'pn_mailguard_ai_analyze', nonce: pnMailguard.nonce }, function(res) {
            if (res.success) {
                location.reload();
            } else {
                var msg = (res.data && res.data.message) ? res.data.message : pnMailguard.aiAnalysisFailed;
                resultDiv.html('<div class="notice notice-error inline" style="margin:0;"><p>' + msg + '</p></div>');
                btn.prop('disabled', false).text('🤖 ' + pnMailguard.analyzeWithAi);
            }
        });
    });

    // -------------------------------------------------------------------------
    // AI Chat (used by Export / Support tab via shared render_ai_chat_section)
    // -------------------------------------------------------------------------
    function getChatElements() {
        // Use .first() in case the same tab renders multiple chat sections
        var $container = $('.pn-chat-messages').first();
        // .pn-chat-messages is a sibling of .pn-chat-input, .pn-chat-send-btn, .pn-chat-error
        // inside the common parent card div
        var $card = $container.parent();
        return {
            messages: $container,
            input: $card.find('.pn-chat-input'),
            sendBtn: $card.find('.pn-chat-send-btn'),
            error: $card.find('.pn-chat-error')
        };
    }

    function addChatMessage(type, text) {
        var isUser = (type === 'user');
        var align = isUser ? 'right' : 'left';
        var label = isUser ? pnMailguard.you : '🤖 AI';
        var cls = isUser ? 'pn-chat-bubble-user' : 'pn-chat-bubble-ai';
        var $chatMessages = getChatElements().messages;
        var html = '<div style="margin-bottom:10px; text-align:' + align + ';">';
        html += '<div style="font-size:11px; color:#999; margin-bottom:2px;">' + label + '</div>';
        html += '<div class="' + cls + '">' + escHtml(text) + '</div>';
        html += '</div>';
        $chatMessages.append(html);
        $chatMessages.scrollTop($chatMessages[0].scrollHeight);
    }

    function sendChatQuestion() {
        var els = getChatElements();
        var question = els.input.val().trim();
        if (!question) return;

        els.messages.find('p:only-child').remove();

        addChatMessage('user', question);
        els.input.val('');
        els.sendBtn.prop('disabled', true).text('⏳...');
        els.error.hide();

        $.post(ajaxurl, {
            action: 'pn_mailguard_ai_chat',
            nonce: pnMailguard.nonce,
            question: question
        }, function(res) {
            els.sendBtn.prop('disabled', false).text(pnMailguard.send);
            if (res.success) {
                addChatMessage('ai', res.data.response);
            } else {
                var msg = (res.data && res.data.message) ? res.data.message : pnMailguard.chatFailed;
                els.error.text(msg).show();
            }
        }).fail(function() {
            els.sendBtn.prop('disabled', false).text(pnMailguard.send);
            els.error.text(pnMailguard.networkError).show();
        });
    }

    $(document).on('click', '.pn-chat-send-btn', sendChatQuestion);
    $(document).on('keydown', '.pn-chat-input', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendChatQuestion();
        }
    });

    // -------------------------------------------------------------------------
    // Dashboard — Onboarding DKIM detect
    // -------------------------------------------------------------------------
    $(document).on('click', '#onboarding-dkim-detect', function() {
        var email = $('#onboarding-email').val().trim();
        var atPos = email.indexOf('@');
        var $dkimStatus = $('#onboarding-dkim-status');
        var $dkimInput = $('#onboarding-dkim-selector');
        var $detectBtn = $(this);

        if (atPos === -1) {
            $dkimStatus.html('<span style="color:#d63638;">' + pnMailguard.enterEmailFirst + '</span>');
            return;
        }
        var domain = email.substring(atPos + 1).toLowerCase();
        if (!domain) {
            $dkimStatus.html('<span style="color:#d63638;">' + pnMailguard.enterEmailFirst + '</span>');
            return;
        }

        $detectBtn.prop('disabled', true).text('⏳...');
        $dkimStatus.html('<span style="color:#999;">' + pnMailguard.detectingDkim + '</span>');

        $.post(ajaxurl, {
            action: 'pn_mailguard_analyze_dkim',
            nonce: pnMailguard.nonce,
            domain: domain,
            selector: ''
        }, function(res) {
            $detectBtn.prop('disabled', false).text('🔍 ' + pnMailguard.detect);
            if (res.success && res.data.autodetected && res.data.selector) {
                $dkimInput.val(res.data.selector);
                $dkimStatus.html('<span style="color:#00a32a;">✅ ' + pnMailguard.dkimDetected + ' ' + escHtml(res.data.selector) + '</span>');
            } else if (res.success && res.data.selector) {
                $dkimInput.val(res.data.selector);
                $dkimStatus.html('<span style="color:#00a32a;">✅ ' + pnMailguard.dkimFound + ' ' + escHtml(res.data.selector) + '</span>');
            } else {
                $dkimStatus.html('<span style="color:#dba617;">⚠️ ' + pnMailguard.dkimNotDetected + '</span>');
            }
        }).fail(function() {
            $detectBtn.prop('disabled', false).text('🔍 ' + pnMailguard.detect);
            $dkimStatus.html('<span style="color:#d63638;">' + pnMailguard.networkError + '</span>');
        });
    });

    // -------------------------------------------------------------------------
    // Dashboard — Inline Edit for Monitor Cards
    // -------------------------------------------------------------------------
    $(document).on('click', '[id^="pn-dash-email-edit"], [id^="pn-dash-ip-edit"]', function() {
        var formId = $(this).attr('id').replace('-edit', '-edit-form');
        $('#' + formId).slideToggle();
    });

    $(document).on('click', '.pn-edit-cancel', function() {
        $(this).closest('[id$="-edit-form"]').slideUp();
    });

    $(document).on('click', '.pn-edit-save', function() {
        var btn = $(this);
        var form = btn.closest('[id$="-edit-form"]');
        var spinner = form.find('.pn-edit-spinner');
        var msg = form.find('.pn-edit-msg');
        var type = btn.data('type');
        var alertEmail = form.find('.pn-edit-alert').val();
        var postData = {
            action: 'pn_mailguard_save_monitor',
            nonce: pnMailguard.nonce,
            pn_mailguard_email_alert: alertEmail || ''
        };

        if (type === 'email') {
            var email = form.find('.pn-edit-email').val();
            postData.pn_mailguard_check_email = email || '';
        } else {
            var ip = form.find('.pn-edit-ip').val();
            postData.pn_mailguard_check_ip = ip || '';
        }

        btn.prop('disabled', true);
        spinner.show();
        msg.hide().removeClass('notice-error notice-success');

        $.post(ajaxurl, postData, function(res) {
            btn.prop('disabled', false);
            spinner.hide();
            if (res.success) {
                msg.addClass('notice-success').css({
                    color: '#00a32a',
                    background: '#edfaef',
                    padding: '4px 8px',
                    borderRadius: '3px'
                }).text(res.data.message).show();
                setTimeout(function() { location.reload(); }, 1000);
            } else {
                msg.addClass('notice-error').css({
                    color: '#d63638',
                    background: '#fbeaea',
                    padding: '4px 8px',
                    borderRadius: '3px'
                }).text(res.data.message || pnMailguard.saveFailed).show();
            }
        });
    });

    // -------------------------------------------------------------------------
    // DNS Tools — Analyze All Records
    // -------------------------------------------------------------------------
    var isAnalyzing = false;
    var $domainInput = $('#pn-dns-domain');
    var autoDomain = $domainInput.data('auto');
    if (autoDomain && !$domainInput.val()) {
        $domainInput.val(autoDomain);
    }

    function getDomain() {
        return $domainInput.val().trim();
    }

    function getSelector() {
        return $('#pn-dns-dkim-selector').val().trim();
    }

    function analyzeAll() {
        var domain = getDomain();
        if (!domain) return;

        isAnalyzing = true;
        $('#pn-dns-analyze-all').prop('disabled', true).text('⏳ ' + pnMailguard.analyzing);
        $('#pn-dkim-selector-row').slideDown();

        runSingle('spf', domain, null, function() {
            runSingle('dmarc', domain, null, function() {
                runSingle('dkim', domain, getSelector(), function() {
                    runSingle('mtasts', domain, null, function() {
                        isAnalyzing = false;
                        $('#pn-dns-analyze-all').prop('disabled', false).text('🔬 ' + pnMailguard.analyzeAllRecords);
                    });
                });
            });
        });
    }

    function runSingle(type, domain, selector, callback) {
        var action = type === 'spf' ? 'pn_mailguard_analyze_spf'
                   : type === 'dmarc' ? 'pn_mailguard_analyze_dmarc'
                   : type === 'dkim' ? 'pn_mailguard_analyze_dkim'
                   : 'pn_mailguard_analyze_mtasts';

        var $body = $('#pn-dns-' + type + '-body');
        $body.html('<p style="color:#999;">⏳ ' + pnMailguard.analyzing + '</p>');

        var data = { action: action, nonce: pnMailguard.nonce, domain: domain };
        if (type === 'dkim' && selector) {
            data.selector = selector;
        }

        $.post(ajaxurl, data, function(res) {
            if (!res.success) {
                var msg = (res.data && res.data.message) ? res.data.message : pnMailguard.analysisFailed;
                $body.html('<div class="notice notice-error inline" style="margin:0;"><p>' + msg + '</p></div>');
                if (callback) callback();
                return;
            }

            var d = res.data;
            if (d.autodetected && d.selector) {
                $('#pn-dns-dkim-selector').val(d.selector);
            }

            var html = '';
            if (d.record) {
                html += '<div class="pn-dns-record">' + escHtml(d.record) + '</div>';
            }
            if (d.passed !== undefined) {
                html += '<div class="pn-stats-grid" style="margin-bottom:12px;">';
                html += dnsCard(d.passed, pnMailguard.passed, '#00a32a');
                html += dnsCard(d.warnings, pnMailguard.warnings, '#dba617');
                html += dnsCard(d.errors, pnMailguard.errors, '#d63638');
                html += '</div>';
            }
            if (d.checks && d.checks.length) {
                html += '<table class="pn-dns-table">';
                $.each(d.checks, function(i, c) {
                    var dotColor = c.status === 'ok' ? '#00a32a' : (c.status === 'warning' ? '#dba617' : (c.status === 'info' ? '#2271b1' : '#d63638'));
                    var badgeText = c.status === 'ok' ? '✓ ' + pnMailguard.pass : (c.status === 'warning' ? '⚠ ' + pnMailguard.warning : (c.status === 'info' ? 'ℹ Info' : '✗ Error'));
                    var badgeBg = c.status === 'ok' ? '#edfaef' : (c.status === 'warning' ? '#fff8e5' : (c.status === 'info' ? '#e8f0fb' : '#fbeaea'));
                    var badgeColor = c.status === 'ok' ? '#00a32a' : (c.status === 'warning' ? '#996800' : (c.status === 'info' ? '#2271b1' : '#a30000'));
                    var bg = i % 2 === 0 ? '#fff' : '#fafafa';
                    html += '<tr style="background:' + bg + '; border-top:0.5px solid #e8e8e8;">';
                    html += '<td style="padding:6px 4px 6px 8px; width:10px;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + dotColor + ';"></span></td>';
                    html += '<td style="padding:6px 4px; font-weight:600; width:40%;">' + escHtml(c.title) + '</td>';
                    html += '<td style="padding:6px 4px; width:70px;"><span style="background:' + badgeBg + ';color:' + badgeColor + ';font-size:10px;font-weight:600;padding:2px 6px;border-radius:3px;">' + badgeText + '</span></td>';
                    html += '<td style="padding:6px 4px; color:#555; line-height:1.4;">' + escHtml(c.description) + '</td>';
                    html += '</tr>';
                });
                html += '</table>';
            }
            if (d.providers && d.providers.length) {
                html += '<p style="font-size:11px; color:#666; margin:8px 0 0;">' + pnMailguard.detectedProviders + ' ' + d.providers.join(', ') + '</p>';
            }

            $body.html(html);
            if (callback) callback();
        });
    }

    function dnsCard(num, label, color) {
        return '<div class="pn-stat-card"><div class="pn-stat-card-num" style="color:' + color + ';">' + num + '</div><div style="font-size:10px;color:#666;margin-top:2px;">' + label + '</div></div>';
    }

    $(document).on('click', '#pn-dns-analyze-all', analyzeAll);

    $(document).on('click', '.pn-dns-single-btn', function() {
        var type = $(this).data('type');
        var domain = getDomain();
        if (!domain) return;
        if (type === 'dkim') {
            $('#pn-dkim-selector-row').slideDown();
        }
        runSingle(type, domain, type === 'dkim' ? getSelector() : null, null);
    });

    $(document).on('keydown', '#pn-dns-domain', function(e) {
        if (e.key === 'Enter' && !isAnalyzing) {
            e.preventDefault();
            analyzeAll();
        }
    });

    // -------------------------------------------------------------------------
    // DNS Tools — IP Analysis
    // -------------------------------------------------------------------------
    var isIpAnalyzing = false;

    function getIp() {
        return $('#pn-ip-address').val().trim();
    }

    function analyzeIpAll() {
        var ip = getIp();
        if (!ip) return;

        isIpAnalyzing = true;
        $('#pn-ip-analyze-all').prop('disabled', true).text('⏳ ' + pnMailguard.analyzing);

        runIpSingle('dnsbl', ip, function() {
            runIpSingle('ptr', ip, function() {
                runIpSingle('geoip', ip, function() {
                    runIpSingle('whois', ip, function() {
                        isIpAnalyzing = false;
                        $('#pn-ip-analyze-all').prop('disabled', false).text('🔬 ' + pnMailguard.analyzeIp);
                    });
                });
            });
        });
    }

    function runIpSingle(type, ip, callback) {
        var action = type === 'dnsbl' ? 'pn_mailguard_ip_dnsbl'
                   : type === 'ptr' ? 'pn_mailguard_ip_ptr'
                   : type === 'geoip' ? 'pn_mailguard_ip_geoip'
                   : 'pn_mailguard_ip_whois';

        var $body = $('#pn-ip-' + type + '-body');
        $body.html('<p style="color:#999;">⏳ ' + pnMailguard.analyzing + '</p>');

        $.post(ajaxurl, { action: action, nonce: pnMailguard.nonce, ip: ip }, function(res) {
            if (!res.success) {
                var msg = (res.data && res.data.message) ? res.data.message : pnMailguard.analysisFailed;
                $body.html('<div class="notice notice-error inline" style="margin:0;"><p>' + msg + '</p></div>');
                if (callback) callback();
                return;
            }

            var d = res.data;
            var html = '';

            if (type === 'dnsbl') {
                if (d.results) {
                    var anyListed = false;
                    var ipv6Notice = false;
                    html += '<table class="pn-dns-table">';
                    $.each(d.results, function(name, status) {
                        if (name.indexOf('ℹ️') === 0) {
                            // Informational message (e.g. IPv6 notice) — show as blue info
                            ipv6Notice = true;
                            html += '<tr style="border-top:0.5px solid #e8e8e8;">';
                            html += '<td style="padding:6px 4px;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#2271b1;"></span></td>';
                            html += '<td style="padding:6px 4px; font-weight:600; color:#2271b1;">' + escHtml(name) + '</td>';
                            html += '<td style="padding:6px 4px; color:#2271b1; font-size:11px;">' + escHtml(status) + '</td>';
                            html += '</tr>';
                        } else {
                            if (status === 'LISTED') anyListed = true;
                            var dotColor = status === 'LISTED' ? '#d63638' : '#00a32a';
                            var badgeText = status === 'LISTED' ? '✗ LISTED' : '✓ CLEAN';
                            var badgeBg = status === 'LISTED' ? '#fbeaea' : '#edfaef';
                            var badgeColor = status === 'LISTED' ? '#a30000' : '#00a32a';
                            html += '<tr style="border-top:0.5px solid #e8e8e8;">';
                            html += '<td style="padding:6px 4px;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + dotColor + ';"></span></td>';
                            html += '<td style="padding:6px 4px; font-weight:600;">' + escHtml(name) + '</td>';
                            html += '<td style="padding:6px 4px;"><span style="background:' + badgeBg + ';color:' + badgeColor + ';font-size:10px;font-weight:600;padding:2px 6px;border-radius:3px;">' + badgeText + '</span></td>';
                            html += '</tr>';
                        }
                    });
                    html += '</table>';
                    if (anyListed) {
                        html += '<p style="font-size:11px; color:#d63638; margin:8px 0 0;">⚠ ' + pnMailguard.ipListed + '</p>';
                    } else if (!ipv6Notice) {
                        html += '<p style="font-size:11px; color:#00a32a; margin:8px 0 0;">✅ ' + pnMailguard.ipClean + '</p>';
                    }
                } else {
                    html = '<p style="font-size:13px; color:#999; margin:0;">' + pnMailguard.noDnsblResults + '</p>';
                }
            } else if (type === 'ptr') {
                if (d.ptr_warning) {
                    html = '<div style="background:#fff8e5; border:1px solid #f0d080; border-radius:4px; padding:10px; font-size:12px;">';
                    html += '<strong style="color:#996800;">⚠ ' + pnMailguard.noPtrRecord + '</strong>';
                    html += '<p style="margin:4px 0 0; color:#666;">PTR: ' + escHtml(d.ptr) + '</p>';
                    html += '</div>';
                } else {
                    html = '<div class="pn-dns-record">' + escHtml(d.ptr) + '</div>';
                    html += '<p style="font-size:11px; color:#00a32a; margin:6px 0 0;">✅ ' + pnMailguard.ptrFound + '</p>';
                }
            } else if (type === 'geoip') {
                if (d.status === 'success') {
                    html += '<table class="pn-dns-table">';
                    var fields = [
                        [pnMailguard.ip, d.ip],
                        [pnMailguard.country, d.country + ' (' + d.countryCode + ')'],
                        [pnMailguard.region, d.region],
                        [pnMailguard.city, d.city],
                        [pnMailguard.isp, d.isp],
                        [pnMailguard.organization, d.org],
                        [pnMailguard.asn, d.as]
                    ];
                    $.each(fields, function(i, f) {
                        if (f[1]) {
                            html += '<tr style="border-top:0.5px solid #e8e8e8;">';
                            html += '<td style="padding:4px 6px; font-weight:600; width:30%;">' + escHtml(f[0]) + '</td>';
                            html += '<td style="padding:4px 6px; color:#333;">' + escHtml(f[1]) + '</td>';
                            html += '</tr>';
                        }
                    });
                    html += '</table>';
                } else {
                    html = '<p style="font-size:13px; color:#d63638; margin:0;">' + escHtml(d.error) + '</p>';
                }
            } else if (type === 'whois') {
                if (d.status === 'success') {
                    html += '<table class="pn-dns-table">';
                    var fields = [
                        [pnMailguard.ipRange, d.inetnum],
                        [pnMailguard.netName, d.netname],
                        [pnMailguard.organization, d.org],
                        [pnMailguard.country, d.country],
                        [pnMailguard.person, d.person],
                        [pnMailguard.email, d.email],
                        [pnMailguard.source, d.source]
                    ];
                    $.each(fields, function(i, f) {
                        if (f[1]) {
                            html += '<tr style="border-top:0.5px solid #e8e8e8;">';
                            html += '<td style="padding:4px 6px; font-weight:600; width:35%;">' + escHtml(f[0]) + '</td>';
                            html += '<td style="padding:4px 6px; color:#333;">' + escHtml(f[1]) + '</td>';
                            html += '</tr>';
                        }
                    });
                    html += '</table>';
                    if (d.remarks) {
                        html += '<p style="font-size:11px; color:#666; margin:6px 0 0;">' + escHtml(d.remarks) + '</p>';
                    }
                } else {
                    html = '<p style="font-size:13px; color:#d63638; margin:0;">' + escHtml(d.error) + '</p>';
                }
            }

            $body.html(html);
            if (callback) callback();
        }).fail(function() {
            $body.html('<div class="notice notice-error inline" style="margin:0;"><p>' + pnMailguard.networkError + '</p></div>');
            if (callback) callback();
        });
    }

    $(document).on('click', '#pn-ip-analyze-all', analyzeIpAll);
    $(document).on('keydown', '#pn-ip-address', function(e) {
        if (e.key === 'Enter' && !isIpAnalyzing) {
            e.preventDefault();
            analyzeIpAll();
        }
    });

    // -------------------------------------------------------------------------
    // Export / Support — Download Report
    // -------------------------------------------------------------------------
    $(document).on('click', '#pn-export-btn', function() {
        var btn = $(this);
        var anonymize = $('#pn-export-anonymize').is(':checked') ? 1 : 0;

        btn.prop('disabled', true).text('⏳ ' + pnMailguard.loading);

        $.post(ajaxurl, {
            action: 'pn_mailguard_export_report',
            nonce: pnMailguard.nonce,
            anonymize: anonymize
        }, function(res) {
            btn.prop('disabled', false).text('📥 Download Report (JSON)');
            if (!res.success) {
                alert(res.data && res.data.message ? res.data.message : 'Export failed.');
                return;
            }
            var jsonStr = JSON.stringify(res.data, null, 2);
            var blob = new Blob([jsonStr], { type: 'application/json' });
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'pointnet-mailguard-report-' + new Date().toISOString().slice(0, 10) + '.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }).fail(function() {
            btn.prop('disabled', false).text('📥 Download Report (JSON)');
            alert(pnMailguard.networkError);
        });
    });

    // -------------------------------------------------------------------------
    // Advanced — Fetch Models
    // -------------------------------------------------------------------------
    $(document).on('click', '#pn-fetch-models-btn', function() {
        var $fetchBtn = $(this);
        var $modelSelect = $('#pn_mailguard_gemini_model');
        var $fetchStatus = $('#pn-fetch-models-status');

        $fetchBtn.prop('disabled', true).text('⏳ ' + pnMailguard.loading);
        $fetchStatus.html('<span style="color:#999;">' + pnMailguard.fetchingModels + '</span>');

        $.post(ajaxurl, {
            action: 'pn_mailguard_fetch_models',
            nonce: pnMailguard.nonce
        }, function(res) {
            $fetchBtn.prop('disabled', false).text('🔄 ' + pnMailguard.fetchModels);
            if (res.success && res.data) {
                var currentVal = $modelSelect.val();
                $modelSelect.find('option:not(:first)').remove();
                var hasModels = false;
                $.each(res.data, function(id, display) {
                    var selected = (id === currentVal) ? ' selected' : '';
                    $modelSelect.append('<option value="' + id + '"' + selected + '>' + display + ' (' + id + ')</option>');
                    hasModels = true;
                });
                if (hasModels) {
                    $fetchStatus.html('<span style="color:#00a32a;">✅ ' + pnMailguard.modelsUpdated + '</span>');
                } else {
                    $fetchStatus.html('<span style="color:#dba617;">' + pnMailguard.noModelsFound + '</span>');
                }
            } else {
                $fetchStatus.html('<span style="color:#d63638;">' + pnMailguard.fetchModelsFailed + '</span>');
            }
        }).fail(function() {
            $fetchBtn.prop('disabled', false).text('🔄 ' + pnMailguard.fetchModels);
            $fetchStatus.html('<span style="color:#d63638;">' + pnMailguard.networkError + '</span>');
        });
    });
});