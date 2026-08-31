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
                        runSingle('dnssec', domain, null, function() {
                            isAnalyzing = false;
                            $('#pn-dns-analyze-all').prop('disabled', false).text('🔬 ' + pnMailguard.analyzeAllRecords);
                        });
                    });
                });
            });
        });
    }

    function runSingle(type, domain, selector, callback) {
        var action = type === 'spf' ? 'pn_mailguard_analyze_spf'
                   : type === 'dmarc' ? 'pn_mailguard_analyze_dmarc'
                   : type === 'dkim' ? 'pn_mailguard_analyze_dkim'
                   : type === 'mtasts' ? 'pn_mailguard_analyze_mtasts'
                   : 'pn_mailguard_analyze_dnssec';

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
            var items = d.checks || d.details;
            if (items && items.length) {
                html += '<table class="pn-dns-table">';
                $.each(items, function(i, c) {
                    var st = c.status;
                    var isOk = (st === 'ok' || st === 'pass');
                    var dotColor = isOk ? '#00a32a' : (st === 'warning' ? '#dba617' : (st === 'info' ? '#2271b1' : '#d63638'));
                    var badgeText = isOk ? '✓ ' + pnMailguard.pass : (st === 'warning' ? '⚠ ' + pnMailguard.warning : (st === 'info' ? 'ℹ Info' : '✗ Error'));
                    var badgeBg = isOk ? '#edfaef' : (st === 'warning' ? '#fff8e5' : (st === 'info' ? '#e8f0fb' : '#fbeaea'));
                    var badgeColor = isOk ? '#00a32a' : (st === 'warning' ? '#996800' : (st === 'info' ? '#2271b1' : '#a30000'));
                    var bg = i % 2 === 0 ? '#fff' : '#fafafa';
                    var title = c.title || c.label || c.check || '';
                    var desc = c.description || c.message || '';
                    html += '<tr style="background:' + bg + '; border-top:0.5px solid #e8e8e8;">';
                    html += '<td style="padding:6px 4px 6px 8px; width:10px;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + dotColor + ';"></span></td>';
                    html += '<td style="padding:6px 4px; font-weight:600; width:40%;">' + escHtml(title) + '</td>';
                    html += '<td style="padding:6px 4px; width:70px;"><span style="background:' + badgeBg + ';color:' + badgeColor + ';font-size:10px;font-weight:600;padding:2px 6px;border-radius:3px;">' + badgeText + '</span></td>';
                    html += '<td style="padding:6px 4px; color:#555; line-height:1.4;">' + escHtml(desc) + '</td>';
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

    // -------------------------------------------------------------------------
    // Reports Reader — IMAP Test & Fetch Now
    // -------------------------------------------------------------------------
    $(document).on('click', '#pn-imap-test-btn', function() {
        var btn = $(this);
        var status = $('#pn-imap-status');
        btn.prop('disabled', true).text('⏳ Testing...');
        status.hide().removeClass('notice-error notice-success');

        $.post(ajaxurl, {
            action: 'pn_mailguard_test_imap',
            nonce: pnMailguard.nonce,
            host: $('#pn_imap_host').val(),
            port: $('#pn_imap_port').val(),
            encryption: $('#pn_imap_encryption').val(),
            username: $('#pn_imap_username').val(),
            password: $('#pn_imap_password').val(),
            mailbox: $('#pn_imap_mailbox').val(),
            action_after: $('select[name="pn_mailguard_imap_action_after"]').val()
        }, function(res) {
            btn.prop('disabled', false).text('🔌 Test Connection');
            if (res.success) {
                status.css({ color: '#00a32a', background: '#edfaef', padding: '8px 12px', borderRadius: '4px', border: '1px solid #c3e6cb' })
                      .text('✅ ' + (res.data && res.data.message ? res.data.message : 'Connection successful!'))
                      .show();
            } else {
                status.css({ color: '#d63638', background: '#fbeaea', padding: '8px 12px', borderRadius: '4px', border: '1px solid #f5c6cb' })
                      .text('❌ ' + (res.data && res.data.message ? res.data.message : 'Connection failed.'))
                      .show();
            }
        }).fail(function() {
            btn.prop('disabled', false).text('🔌 Test Connection');
            status.css({ color: '#d63638', background: '#fbeaea', padding: '8px 12px', borderRadius: '4px', border: '1px solid #f5c6cb' })
                  .text('❌ ' + (pnMailguard.networkError || 'Network error'))
                  .show();
        });
    });

    $(document).on('click', '#onboarding-imap-test-btn', function() {
        var btn = $(this);
        var status = $('#onboarding-imap-status');
        btn.prop('disabled', true).text('⏳ Testing...');
        status.hide();

        $.post(ajaxurl, {
            action: 'pn_mailguard_test_imap',
            nonce: pnMailguard.nonce,
            host: $('#onboarding-imap-host').val(),
            port: $('#onboarding-imap-port').val(),
            encryption: $('#onboarding-imap-encryption').val(),
            username: $('#onboarding-imap-username').val(),
            password: $('#onboarding-imap-password').val(),
            mailbox: 'INBOX'
        }, function(res) {
            btn.prop('disabled', false).text('🧪 Test IMAP Connection');
            if (res.success) {
                status.css({ color: '#00a32a', background: '#edfaef', padding: '8px 12px', borderRadius: '4px', border: '1px solid #c3e6cb' })
                      .text('✅ ' + (res.data && res.data.message ? res.data.message : 'Connection successful!'))
                      .show();
            } else {
                status.css({ color: '#d63638', background: '#fbeaea', padding: '8px 12px', borderRadius: '4px', border: '1px solid #f5c6cb' })
                      .text('❌ ' + (res.data && res.data.message ? res.data.message : 'Connection failed.'))
                      .show();
            }
        }).fail(function() {
            btn.prop('disabled', false).text('🧪 Test IMAP Connection');
            status.css({ color: '#d63638', background: '#fbeaea', padding: '8px 12px', borderRadius: '4px', border: '1px solid #f5c6cb' })
                  .text('❌ ' + (pnMailguard.networkError || 'Network error'))
                  .show();
        });
    });

    $(document).on('click', '#pn-imap-fetch-btn', function() {
        var btn = $(this);
        var status = $('#pn-imap-status');
        btn.prop('disabled', true).text('⏳ Fetching...');
        status.hide().removeClass('notice-error notice-success');

        $.post(ajaxurl, {
            action: 'pn_mailguard_fetch_imap_now',
            nonce: pnMailguard.nonce
        }, function(res) {
            btn.prop('disabled', false).text('🔄 Fetch Reports Now');
            if (res.success) {
                status.css({ color: '#00a32a', background: '#edfaef', padding: '8px 12px', borderRadius: '4px', border: '1px solid #c3e6cb' })
                      .text('✅ ' + (res.data && res.data.message ? res.data.message : 'Fetch completed!'))
                      .show();
                setTimeout(function() { location.reload(); }, 1500);
            } else {
                status.css({ color: '#d63638', background: '#fbeaea', padding: '8px 12px', borderRadius: '4px', border: '1px solid #f5c6cb' })
                      .text('❌ ' + (res.data && res.data.message ? res.data.message : 'Fetch failed.'))
                      .show();
            }
        }).fail(function() {
            btn.prop('disabled', false).text('🔄 Fetch Reports Now');
            status.css({ color: '#d63638', background: '#fbeaea', padding: '8px 12px', borderRadius: '4px', border: '1px solid #f5c6cb' })
                  .text('❌ ' + (pnMailguard.networkError || 'Network error'))
                  .show();
        });
    });

    // -------------------------------------------------------------------------
    // Contextual Documentation Drawer (Off-Canvas Knowledge Base)
    // -------------------------------------------------------------------------
    var pnKnowledgeBase = {
        spf: {
            icon: '🔐',
            title: 'SPF (Sender Policy Framework)',
            subtitle: 'Autenticazione Mittente & Prevenzione Spoofing',
            tab: 'dnstools',
            summary: 'L\'SPF (RFC 7208) è un record DNS di tipo TXT che elenca gli indirizzi IP e i server di posta autorizzati a inviare email per conto del tuo dominio.',
            whyItMatters: 'Senza SPF, chiunque può inviare email falsificando il tuo indirizzo mittente (email spoofing). Provider come Gmail, Microsoft 365 e Yahoo scartano o contrassegnano come SPAM le email prive di record SPF valido.',
            keyPoints: [
                '<strong>Definisce i mittenti validi:</strong> Specifica IP fisso, subnet o meccanismi <code>include:</code> per servizi esterni (es. Google Workspace, Brevo, Mailchimp).',
                '<strong>Qualificatore finale:</strong> Deve terminare con <code>-all</code> (Hardfail - consigliato) o <code>~all</code> (Softfail - fase di test). Evita <code>+all</code>.',
                '<strong>Limite dei 10 Lookup:</strong> La valutazione del record SPF non deve superare 10 interrogazioni DNS (lookups) per evitare errori permanenti (Permerror).'
            ],
            remediation: 'Verifica la sintassi del record SPF nello strumento <em>DNS & IP Tools</em> per assicurarti che tutti i mittenti legittimi siano censiti.'
        },
        dmarc: {
            icon: '📋',
            title: 'DMARC (Domain-based Reporting)',
            subtitle: 'Politica di Protezione & Reportistica Aggregata',
            tab: 'dmarcreports',
            summary: 'Il DMARC (RFC 7489) si basa su SPF e DKIM per istruire i server destinatari su come gestire i messaggi non autenticati e consente di ricevere report di analisi (RUA/RUF).',
            whyItMatters: 'È lo standard definitivo contro il Phishing e l\'usurpazione di dominio. Senza DMARC i server di posta non sanno se bloccare le email fraudolente inviate a tuo nome.',
            keyPoints: [
                '<strong>Politica <code>p=none</code>:</strong> Modalità monitoraggio (raccoglie report senza bloccare alcuna email).',
                '<strong>Politica <code>p=quarantine</code>:</strong> Sposta nello SPAM del destinatario le email non autenticate.',
                '<strong>Politica <code>p=reject</code>:</strong> Blocca del tutto la consegna dei messaggi non autenticati (massima protezione).',
                '<strong>Report aggregati RUA:</strong> Specifica <code>rua=mailto:...</code> per analizzare i report nel tab <em>DMARC Reports</em>.'
            ],
            remediation: 'Attiva il record TXT DMARC su <code>_dmarc.tuodominio.com</code> e usa la sezione <em>DMARC Reports</em> del plugin per monitorare i report ricevuti.'
        },
        dkim: {
            icon: '🔑',
            title: 'DKIM (DomainKeys Identified Mail)',
            subtitle: 'Firma Digitale Crittografica delle Email',
            tab: 'dnstools',
            summary: 'Il DKIM (RFC 6376) aggiunge una firma crittografica invisibile all\'intestazione delle email inviate. Il destinatario usa la chiave pubblica pubblicata nel tuo DNS per verificarla.',
            whyItMatters: 'Assicura che l\'email sia stata realmente inviata dal tuo server e garantisce che il contenuto del messaggio non sia stato alterato durante il transito.',
            keyPoints: [
                '<strong>Selettore (Selector):</strong> Il nome della chiave pubblicata nel DNS (es. <code>default._domainkey.tuodominio.com</code>).',
                '<strong>Chiave Pubblica & Privata:</strong> La chiave privata firma l\'email sul server, la chiave pubblica nel DNS ne permette la decifratura e verifica.',
                '<strong>Provider Pubblici:</strong> Servizi come Gmail o Outlook usano selettori proprietari quando invii tramite la loro webmail.'
            ],
            remediation: 'Imposta il selettore DKIM nelle impostazioni del plugin o usa il rilevamento automatico nel tab <em>DNS & IP Tools</em> per verificare la firma.'
        },
        mtasts: {
            icon: '🛡️',
            title: 'MTA-STS (MTA Strict Transport Security)',
            subtitle: 'Cifratura Forzata connessioni SMTP TLS (RFC 8461)',
            tab: 'dnstools',
            summary: 'L\'MTA-STS obbliga i server di posta mittenti a stabilire connessioni cifrate sicure (TLS/SSL) con certificato valido prima di consegnare email al tuo dominio.',
            whyItMatters: 'Impedisce gli attacchi Man-in-the-Middle (MitM) ed evita attacchi di "Downgrade TLS" (STARTTLS stripping) dove un attaccante forza la comunicazione in chiaro.',
            keyPoints: [
                '<strong>Record DNS TXT:</strong> Pubblicato su <code>_mta-sts.tuodominio.com</code> con valore <code>v=STSv1; id=YYYYMMDDnn;</code>.',
                '<strong>Policy File HTTPS:</strong> Servito su <code>https://mta-sts.tuodominio.com/.well-known/mta-sts.txt</code> con gli host MX e <code>mode: enforce</code>.',
                '<strong>TLS-RPT (RFC 8460):</strong> Abilita la ricezione dei report sugli errori di cifratura TLS via email.'
            ],
            remediation: 'Verifica la presenza sia del record DNS che del file HTTPS tramite il controllo MTA-STS nel tab <em>DNS & IP Tools</em>.'
        },
        dnssec: {
            icon: '🔒',
            title: 'DNSSEC (DNS Security Extensions)',
            subtitle: 'Autenticazione & Integrità delle Risposte DNS',
            tab: 'dnstools',
            summary: 'Il DNSSEC aggiunge firme digitali crittografiche a tutti i record DNS del tuo dominio per attestare che la risposta proviene dal server autorevole autentico.',
            whyItMatters: 'Protegge il tuo dominio e i tuoi utenti contro attacchi di DNS Spoofing e DNS Cache Poisoning (dirottamento verso server malevoli).',
            keyPoints: [
                '<strong>Record DS (Delegation Signer):</strong> Pubblicato nel Registro TLD principale (.it, .com, .net, ecc.).',
                '<strong>Record DNSKEY:</strong> Chiavi di zona (ZSK/KSK) gestite sul tuo server DNS.',
                '<strong>Flag AD (Authenticated Data):</strong> Attesta che la catena di fiducia dal registro TLD al dominio è valida.'
            ],
            remediation: 'Attiva il DNSSEC presso il tuo provider DNS (es. Cloudflare, Aruba, Route53) e registra la chiave DS nel pannello del Registrar.'
        },
        dnsbl: {
            icon: '🚨',
            title: 'DNSBL / RBL (Blacklist IP Server)',
            subtitle: 'Reputazione dell\'Indirizzo IP Mail Server',
            tab: 'dnstools',
            summary: 'Le DNSBL (DNS Blacklists) sono database di reputazione in tempo reale usati dai provider email per bloccare messaggi da IP associati a SPAM o malware.',
            whyItMatters: 'Se l\'indirizzo IP del tuo server di posta viene inserito in una blacklist (es. Spamhaus, Barracuda), le tue email verranno rifiutate immediatamente dai destinatari.',
            keyPoints: [
                '<strong>Rilevamento Automatico:</strong> Il plugin interroga 9 delle principali blacklist internazionali ad ogni scansione.',
                '<strong>Cause di Blacklisting:</strong> Invio incontrollato di spam, form sul sito abusati da bot, malware sul server o account violati.',
                '<strong>Procedura di Delisting:</strong> Ogni blacklist offre un portale ufficiale per richiedere la rimozione dopo aver risolto la causa.'
            ],
            remediation: 'Se l\'IP risulta in blacklist, usa lo strumento <em>DNS & IP Tools</em> per identificare la lista ed avviare la procedura di de-listing.'
        },
        ip: {
            icon: '🌐',
            title: 'IP Server & Reverse DNS (PTR)',
            subtitle: 'Identificazione Server & Risoluzione Inversa',
            tab: 'dnstools',
            summary: 'L\'indirizzo IP identifica il tuo server di posta (record MX). Il record PTR (Reverse DNS) mappa l\'indirizzo IP nel rispettivo nome host di dominio.',
            whyItMatters: 'I server destinatari (Gmail, M365, Yahoo) controllano il "Reverse DNS". Se l\'IP non ha un record PTR valido corrispondente al nome host, l\'email viene contrassegnata come SPAM.',
            keyPoints: [
                '<strong>Coerenza Host-IP:</strong> Il record PTR dell\'IP deve puntare a un FQDN valido (es. <code>mail.tuodominio.com</code>).',
                '<strong>Gestione dal Provider:</strong> Si configura solitamente nel pannello del provider della macchina/IP (VPS, Hetzner, AWS, Aruba, DigitalOcean).',
                '<strong>IPv4 vs IPv6:</strong> Entrambi i protocolli richiedono la configurazione corretta del Reverse DNS.'
            ],
            remediation: 'Controlla che l\'IP del tuo mail server risolva correttamente in un hostname valido tramite l\'analisi PTR nel tab <em>DNS & IP Tools</em>.'
        }
    };

    $(document).on('click', '[data-docs]', function(e) {
        e.preventDefault();
        var key = $(this).attr('data-docs');
        var data = pnKnowledgeBase[key];
        if (!data) return;

        $('#pn-doc-drawer-icon').text(data.icon);
        $('#pn-doc-drawer-title').text(data.title);
        $('#pn-doc-drawer-subtitle').text(data.subtitle);

        var html = '';
        
        // Section 1: In Sintesi
        html += '<div class="pn-doc-section">';
        html += '<div class="pn-doc-heading">📖 Cos\'è e a cosa serve</div>';
        html += '<p style="margin:0 0 10px;">' + data.summary + '</p>';
        html += '</div>';

        // Section 2: Perché è importante
        html += '<div class="pn-doc-section">';
        html += '<div class="pn-doc-heading">⚡ Perché è fondamentale</div>';
        html += '<p style="margin:0;">' + data.whyItMatters + '</p>';
        html += '</div>';

        // Section 3: Punti Chiave
        if (data.keyPoints && data.keyPoints.length) {
            html += '<div class="pn-doc-section">';
            html += '<div class="pn-doc-heading">🎯 Punti Chiave & Regole</div>';
            html += '<ul style="margin:0; padding-left:18px; line-height:1.6;">';
            data.keyPoints.forEach(function(item) {
                html += '<li style="margin-bottom:6px;">' + item + '</li>';
            });
            html += '</ul>';
            html += '</div>';
        }

        // Section 4: Guida Rapida & Soluzione
        html += '<div class="pn-doc-section">';
        html += '<div class="pn-doc-heading">💡 Come verificare e risolvere</div>';
        html += '<div class="pn-doc-box">' + data.remediation + '</div>';
        html += '</div>';

        $('#pn-doc-drawer-content').html(html);

        // Update action button link
        var targetUrl = (pnMailguard.adminUrl || 'admin.php?page=pn-mailguard') + '&tab=' + (data.tab || 'dnstools');
        $('#pn-doc-drawer-tool-link').attr('href', targetUrl);

        // Show drawer & backdrop
        $('#pn-doc-drawer-backdrop').addClass('active');
        $('#pn-doc-drawer').addClass('active');
    });

    function closePnDocDrawer() {
        $('#pn-doc-drawer-backdrop').removeClass('active');
        $('#pn-doc-drawer').removeClass('active');
    }

    $(document).on('click', '#pn-doc-drawer-close, .pn-doc-drawer-close-btn, #pn-doc-drawer-backdrop', function(e) {
        e.preventDefault();
        closePnDocDrawer();
    });

    $(document).on('keydown', function(e) {
        if (e.key === 'Escape' || e.keyCode === 27) {
            closePnDocDrawer();
        }
    });

    // -------------------------------------------------------------------------
    // Onboarding — Auto-fill Alert Email
    // -------------------------------------------------------------------------
    $(document).on('input', '#onboarding-email', function() {
        var alertField = document.getElementById('onboarding-alert-email');
        if (alertField && !alertField._userEdited) {
            alertField.value = this.value;
        }
    });
    $(document).on('input', '#onboarding-alert-email', function() {
        this._userEdited = true;
    });

    // -------------------------------------------------------------------------
    // Reports Reader — DMARC & TLSRPT Upload (Drag & Drop) & Actions
    // -------------------------------------------------------------------------
    $(document).on('click', '#pn-dmarc-browse-btn, #pn-dmarc-dropzone', function(e) {
        if (e.target.id !== 'pn-dmarc-file-input') {
            $('#pn-dmarc-file-input').trigger('click');
        }
    });

    $(document).on('dragover dragenter', '#pn-dmarc-dropzone', function(e) {
        e.preventDefault();
        e.stopPropagation();
        $(this).css('background', '#e1eeef');
    });

    $(document).on('dragleave drop', '#pn-dmarc-dropzone', function(e) {
        e.preventDefault();
        e.stopPropagation();
        $(this).css('background', '#f0f6ff');
    });

    $(document).on('drop', '#pn-dmarc-dropzone', function(e) {
        var files = e.originalEvent.dataTransfer.files;
        if (files.length > 0) {
            uploadReports(files);
        }
    });

    $(document).on('change', '#pn-dmarc-file-input', function() {
        if (this.files.length > 0) {
            uploadReports(this.files);
        }
    });

    async function uploadReports(files) {
        var total = files.length;
        var successCount = 0;
        var errorCount = 0;
        var errors = [];
        var statusDiv = $('#pn-dmarc-upload-status');

        statusDiv.css('color', '#2271b1').show();

        for (var i = 0; i < total; i++) {
            var file = files[i];
            var progressMsg = (pnMailguard.uploadingFile || 'Processing file %1$s of %2$s (%3$s)...')
                .replace('%1$s', i + 1)
                .replace('%2$s', total)
                .replace('%3$s', escHtml(file.name));
            statusDiv.html('⏳ ' + progressMsg);

            var formData = new FormData();
            formData.append('action', 'pn_mailguard_upload_dmarc_report');
            formData.append('nonce', pnMailguard.nonce);
            formData.append('dmarc_file', file);

            try {
                let response = await $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: formData,
                    contentType: false,
                    processData: false
                });

                if (response.success) {
                    successCount++;
                } else {
                    errorCount++;
                    errors.push(file.name + ': ' + (response.data && response.data.message ? response.data.message : (pnMailguard.uploadFailedGeneric || 'Upload failed')));
                }
            } catch (err) {
                errorCount++;
                errors.push(file.name + ': ' + (pnMailguard.networkError || 'Network error'));
            }
        }

        if (errorCount === 0) {
            var successMsg = total === 1
                ? (pnMailguard.uploadSuccessSingle || 'Report imported successfully!')
                : (pnMailguard.uploadSuccessMultiple || '%d reports imported successfully!').replace('%d', total);
            statusDiv.css('color', '#00a32a').html('✅ ' + successMsg);
            setTimeout(function() { location.reload(); }, 1200);
        } else if (successCount > 0) {
            var partialMsg = (pnMailguard.uploadPartial || 'Imported %1$s of %2$s reports. %3$s error(s):')
                .replace('%1$s', successCount)
                .replace('%2$s', total)
                .replace('%3$s', errorCount);
            statusDiv.css('color', '#dba617').html('⚠️ ' + partialMsg + '<br>' + errors.map(escHtml).join('<br>'));
            setTimeout(function() { location.reload(); }, 3500);
        } else {
            statusDiv.css('color', '#d63638').html('✗ ' + (pnMailguard.uploadFailed || 'Import failed:') + '<br>' + errors.map(escHtml).join('<br>'));
        }
    }

    $(document).on('click', '.pn-toggle-details-btn', function() {
        var targetId = $(this).data('target');
        $('#' + targetId).toggle();
    });

    $(document).on('click', '.pn-delete-report-btn', function() {
        if (!confirm(pnMailguard.confirmDeleteReport || 'Are you sure you want to delete this report?')) return;
        var reportId = $(this).data('id');
        $.post(ajaxurl, {
            action: 'pn_mailguard_delete_dmarc_report',
            nonce: pnMailguard.nonce,
            report_id: reportId
        }, function(res) {
            if (res.success) {
                location.reload();
            } else {
                alert(res.data && res.data.message ? res.data.message : (pnMailguard.deleteFailed || 'Delete failed'));
            }
        });
    });

    $(document).on('click', '.pn-delete-tls-report-btn', function() {
        if (!confirm(pnMailguard.confirmDeleteReport || 'Are you sure you want to delete this report?')) return;
        var reportId = $(this).data('id');
        $.post(ajaxurl, {
            action: 'pn_mailguard_delete_tls_report',
            nonce: pnMailguard.nonce,
            report_id: reportId
        }, function(res) {
            if (res.success) {
                location.reload();
            } else {
                alert(res.data && res.data.message ? res.data.message : (pnMailguard.deleteFailed || 'Delete failed'));
            }
        });
    });
});