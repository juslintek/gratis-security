<?php declare(strict_types=1);

namespace Gratis\Security\Admin;

defined('ABSPATH') || exit;

/**
 * Shared UI helpers, scoped CSS, non-overlapping code blocks, and safe JS copy delegation.
 */
final class UiHelpers {

    private static bool $copy_js_rendered = false;

    /**
     * Output scoped CSS styles for all Gratis Security admin tabs.
     */
    public static function render_styles(): void {
        ?>
        <style>
            .gratis-security-wrap .gs-card {
                background: #fff;
                border: 1px solid #dcdcde;
                border-radius: 6px;
                padding: 18px 20px;
                margin-top: 14px;
                max-width: 1180px;
                box-sizing: border-box;
            }
            .gratis-security-wrap .gs-card h2 {
                margin: 0 0 10px 0;
                font-size: 16px;
            }
            .gratis-security-wrap .gs-card h3 {
                margin: 14px 0 8px 0;
                font-size: 14px;
            }
            .gratis-security-wrap .gs-kpi-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 12px;
                margin: 14px 0;
                max-width: 1180px;
            }
            .gratis-security-wrap .gs-kpi-card {
                background: #f9f9fa;
                border: 1px solid #dcdcde;
                border-radius: 5px;
                padding: 12px 14px;
                box-sizing: border-box;
            }
            .gratis-security-wrap .gs-kpi-label {
                font-size: 12px;
                color: #646970;
                margin-bottom: 4px;
            }
            .gratis-security-wrap .gs-kpi-value {
                font-size: 16px;
                font-weight: 700;
                color: #1d2327;
                word-break: break-word;
            }
            .gratis-security-wrap .gs-kpi-sub {
                font-size: 11px;
                color: #646970;
                margin-top: 3px;
            }
            .gratis-security-wrap .gs-badge {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 3px;
                font-size: 11px;
                font-weight: 600;
                color: #fff;
                line-height: 1.45;
                vertical-align: middle;
                white-space: nowrap;
            }
            .gratis-security-wrap .gs-badge-ok { background: #00a32a; }
            .gratis-security-wrap .gs-badge-warn { background: #dba617; color: #1d2327; }
            .gratis-security-wrap .gs-badge-danger { background: #d63638; }
            .gratis-security-wrap .gs-badge-info { background: #2271b1; }
            .gratis-security-wrap .gs-badge-muted { background: #646970; }
            .gratis-security-wrap .gs-code-wrap {
                border: 1px solid #dcdcde;
                border-radius: 4px;
                overflow: hidden;
                margin-top: 8px;
            }
            .gratis-security-wrap .gs-code-head {
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 8px;
                background: #f0f0f1;
                padding: 6px 10px;
                border-bottom: 1px solid #dcdcde;
                font-size: 12px;
                font-weight: 600;
            }
            .gratis-security-wrap .gs-code-pre {
                margin: 0;
                padding: 12px;
                background: #f6f7f7;
                font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
                font-size: 12px;
                overflow-x: auto;
                white-space: pre;
                line-height: 1.45;
            }
            .gratis-security-wrap .gs-stepper {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
                gap: 10px;
                margin: 14px 0;
            }
            .gratis-security-wrap .gs-step-box {
                border: 1px solid #dcdcde;
                border-radius: 5px;
                padding: 12px 14px;
                background: #f9f9fa;
            }
            .gratis-security-wrap .gs-toolbar {
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
                align-items: center;
                margin-bottom: 12px;
            }
            .gratis-security-wrap .gs-pager {
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 10px;
                margin-top: 10px;
                padding-top: 8px;
                border-top: 1px solid #f0f0f1;
                font-size: 12px;
                color: #50575e;
            }
            .gratis-security-wrap .gs-pager-btns {
                display: flex;
                gap: 6px;
                align-items: center;
            }
            .gratis-security-wrap .gs-snippet {
                display: inline-block;
                max-width: 340px;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
                vertical-align: middle;
                font-size: 11px;
                background: #f6f7f7;
                padding: 2px 5px;
                border-radius: 3px;
            }
            .gratis-security-wrap .gs-score-hero {
                display: flex;
                flex-wrap: wrap;
                gap: 18px;
                align-items: center;
                justify-content: space-between;
            }
            .gratis-security-wrap .gs-score-main {
                display: flex;
                align-items: center;
                gap: 16px;
            }
            .gratis-security-wrap .gs-score-circle {
                width: 82px;
                height: 82px;
                border-radius: 50%;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                color: #fff;
                font-weight: 700;
                flex-shrink: 0;
                line-height: 1.15;
            }
            .gratis-security-wrap .gs-score-num { font-size: 22px; }
            .gratis-security-wrap .gs-score-grade { font-size: 12px; opacity: 0.92; }
            .gratis-security-wrap .gs-pills {
                display: flex;
                flex-wrap: wrap;
                gap: 6px;
                align-items: center;
            }
            .gratis-security-wrap .gs-pill {
                display: inline-flex;
                align-items: center;
                gap: 5px;
                padding: 3px 9px;
                border-radius: 3px;
                background: #f0f0f1;
                font-size: 12px;
                color: #1d2327;
            }
            .gratis-security-wrap details.gs-collapsible {
                border: 1px solid #dcdcde;
                border-radius: 5px;
                padding: 12px 16px;
                background: #f9f9fa;
                margin-top: 14px;
                max-width: 1180px;
                box-sizing: border-box;
            }
            .gratis-security-wrap details.gs-collapsible > summary {
                cursor: pointer;
                font-weight: 600;
                font-size: 14px;
                color: #1d2327;
            }
            .gratis-security-wrap .gs-msg {
                font-size: 12px;
                font-weight: 600;
            }
            .gratis-security-wrap .gs-two-col {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
                gap: 14px;
                margin-top: 12px;
            }
        </style>
        <?php
    }

    /**
     * Render a code block with a non-overlapping flex header bar and copy button.
     */
    public static function render_code_block(string $title, string $code, string $pre_id = ''): void {
        echo '<div class="gs-code-wrap">';
        echo '<div class="gs-code-head">';
        echo '<span>' . esc_html($title) . '</span>';
        echo '<button type="button" class="button button-small gratis-copy-btn" data-copy="' . esc_attr($code) . '">' . esc_html__('Kopijuoti', 'gratis-security') . '</button>';
        echo '</div>';
        echo '<pre class="gs-code-pre"' . ('' !== $pre_id ? ' id="' . esc_attr($pre_id) . '"' : '') . '>' . esc_html($code) . '</pre>';
        echo '</div>';
    }

    /**
     * Map status or severity level string to a badge CSS modifier class.
     */
    public static function badge_class(string $level): string {
        return match (strtolower(trim($level))) {
            'ok', 'pass', 'done', 'resolved', 'logged' => 'gs-badge-ok',
            'warn', 'warning', 'medium', 'acknowledged', 'unverifiable', 'manual_verify' => 'gs-badge-warn',
            'critical', 'high', 'fail', 'missing', 'action_needed', 'blocked' => 'gs-badge-danger',
            'info', 'monitor', 'open' => 'gs-badge-info',
            default => 'gs-badge-muted',
        };
    }

    /**
     * Render shared safe click delegation script for `.gratis-copy-btn` buttons.
     */
    public static function render_copy_helper_js(): void {
        if (self::$copy_js_rendered) {
            return;
        }
        self::$copy_js_rendered = true;
        ?>
        <script>
        (function() {
            if (window.__gratisCopyBound) return;
            window.__gratisCopyBound = true;

            function fallbackCopy(text) {
                var ta = document.createElement('textarea');
                ta.value = text;
                ta.setAttribute('readonly', '');
                ta.style.position = 'fixed';
                ta.style.left = '-9999px';
                document.body.appendChild(ta);
                ta.select();
                try {
                    document.execCommand('copy');
                } catch (err) {
                    // Ignore copy failure in restricted contexts.
                }
                document.body.removeChild(ta);
            }

            document.addEventListener('click', function(e) {
                var btn = e.target && e.target.closest ? e.target.closest('.gratis-copy-btn') : null;
                if (!btn) return;

                var text = btn.getAttribute('data-copy');
                if (!text) {
                    var wrap = btn.closest('.gs-code-wrap');
                    var pre = wrap ? wrap.querySelector('.gs-code-pre, pre') : null;
                    text = pre ? pre.textContent : '';
                }
                if (!text) return;

                var markCopied = function() {
                    var orig = btn.getAttribute('data-orig-label') || btn.textContent;
                    btn.setAttribute('data-orig-label', orig);
                    btn.textContent = 'Nukopijuota!';
                    setTimeout(function() {
                        btn.textContent = btn.getAttribute('data-orig-label') || 'Kopijuoti';
                    }, 1500);
                };

                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(text).then(markCopied, function() {
                        fallbackCopy(text);
                        markCopied();
                    });
                } else {
                    fallbackCopy(text);
                    markCopied();
                }
            });
        })();
        </script>
        <?php
    }
}
