import { Resend } from 'resend';
import { config, validateEmailConfig } from '@/lib/config';
import type { Rollup } from '@/lib/dmarc/rollup';

function fmtDate(unix: number): string {
  if (!unix || !Number.isFinite(unix)) return '?';
  return new Date(unix * 1000).toISOString().slice(0, 10);
}

function pct(num: number, denom: number): string {
  if (denom === 0) return '0.0';
  return ((num / denom) * 100).toFixed(1);
}

function esc(s: string): string {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderHtml(r: Rollup, fetchedAt: string, periodLabel: string): string {
  const passRate = pct(
    r.passedBoth + r.passedDkimOnly + r.passedSpfOnly,
    r.totalMessages,
  );

  const orgRows = [...r.byOrg.entries()]
    .sort((a, b) => b[1].messages - a[1].messages)
    .map(
      ([org, v]) =>
        `<tr><td>${esc(org)}</td><td>${v.reports}</td><td>${v.messages.toLocaleString()}</td><td>${pct(v.passed, v.messages)}%</td><td style="color:${v.failed ? '#b00' : '#0a0'}">${v.failed.toLocaleString()}</td></tr>`,
    )
    .join('');

  const ipRows = [...r.bySourceIp.entries()]
    .sort((a, b) => b[1].messages - a[1].messages)
    .slice(0, 10)
    .map(
      ([ip, v]) =>
        `<tr><td><code>${esc(ip)}</code></td><td>${v.messages.toLocaleString()}</td><td>${pct(v.passed, v.messages)}%</td><td style="color:${v.failed ? '#b00' : '#0a0'}">${v.failed.toLocaleString()}</td></tr>`,
    )
    .join('');

  const failRows =
    r.topFailures.length === 0
      ? '<tr><td colspan="4" style="color:#0a0">No DKIM+SPF dual-failures in this window.</td></tr>'
      : r.topFailures
          .map(
            (f) =>
              `<tr><td><code>${esc(f.sourceIp)}</code></td><td>${esc(f.org)}</td><td>${f.count.toLocaleString()}</td><td>dkim=${esc(f.dkim)} spf=${esc(f.spf)}</td></tr>`,
          )
          .join('');

  return `<!doctype html>
<html><body style="font-family:-apple-system,BlinkMacSystemFont,sans-serif;color:#222;max-width:720px;margin:0 auto;padding:24px;">
<h1 style="margin:0 0 8px">DMARC daily rollup</h1>
<p style="color:#666;margin:0 0 24px">
  ${periodLabel} . ${r.reportCount} reports . period ${fmtDate(r.rangeStart)} to ${fmtDate(r.rangeEnd)}<br>
  Built ${fetchedAt}
</p>

<table style="width:100%;border-collapse:collapse;background:#f7f7f7;padding:16px;border-radius:8px;margin-bottom:24px">
  <tr><td style="padding:6px 12px"><strong>Total messages evaluated</strong></td><td style="text-align:right;padding:6px 12px;font-size:20px">${r.totalMessages.toLocaleString()}</td></tr>
  <tr><td style="padding:6px 12px">Pass rate (DKIM or SPF aligned)</td><td style="text-align:right;padding:6px 12px;font-size:20px;color:${Number(passRate) >= 99 ? '#0a0' : Number(passRate) >= 95 ? '#a80' : '#b00'}">${passRate}%</td></tr>
  <tr><td style="padding:6px 12px">  passed both</td><td style="text-align:right;padding:6px 12px">${r.passedBoth.toLocaleString()}</td></tr>
  <tr><td style="padding:6px 12px">  DKIM only</td><td style="text-align:right;padding:6px 12px">${r.passedDkimOnly.toLocaleString()}</td></tr>
  <tr><td style="padding:6px 12px">  SPF only</td><td style="text-align:right;padding:6px 12px">${r.passedSpfOnly.toLocaleString()}</td></tr>
  <tr><td style="padding:6px 12px">  failed both</td><td style="text-align:right;padding:6px 12px;color:${r.failedBoth ? '#b00' : '#0a0'}">${r.failedBoth.toLocaleString()}</td></tr>
  ${r.failedReportCount > 0 ? `<tr><td style="padding:6px 12px;color:#a80">Reports that failed to parse</td><td style="text-align:right;padding:6px 12px;color:#a80">${r.failedReportCount}</td></tr>` : ''}
</table>

<h2 style="margin:24px 0 8px;font-size:16px">By reporting org</h2>
<table style="width:100%;border-collapse:collapse;font-size:14px">
  <thead><tr style="background:#eee"><th style="text-align:left;padding:6px 8px">Org</th><th style="text-align:right;padding:6px 8px">Reports</th><th style="text-align:right;padding:6px 8px">Messages</th><th style="text-align:right;padding:6px 8px">Pass %</th><th style="text-align:right;padding:6px 8px">Failed</th></tr></thead>
  <tbody>${orgRows}</tbody>
</table>

<h2 style="margin:24px 0 8px;font-size:16px">Top source IPs</h2>
<table style="width:100%;border-collapse:collapse;font-size:14px">
  <thead><tr style="background:#eee"><th style="text-align:left;padding:6px 8px">IP</th><th style="text-align:right;padding:6px 8px">Messages</th><th style="text-align:right;padding:6px 8px">Pass %</th><th style="text-align:right;padding:6px 8px">Failed</th></tr></thead>
  <tbody>${ipRows}</tbody>
</table>

<h2 style="margin:24px 0 8px;font-size:16px">Dual-failures (DKIM + SPF both failed)</h2>
<table style="width:100%;border-collapse:collapse;font-size:14px">
  <thead><tr style="background:#eee"><th style="text-align:left;padding:6px 8px">IP</th><th style="text-align:left;padding:6px 8px">Reporter</th><th style="text-align:right;padding:6px 8px">Count</th><th style="text-align:left;padding:6px 8px">Verdict</th></tr></thead>
  <tbody>${failRows}</tbody>
</table>

<p style="color:#999;font-size:12px;margin-top:32px">Auto-generated daily by /api/cron/dmarc-daily.</p>
</body></html>`;
}

export async function sendDMARCRollupEmail(
  rollup: Rollup,
  periodLabel: string,
): Promise<{ success: boolean; error?: string; id?: string }> {
  const v = validateEmailConfig();
  if (!v.valid) {
    return {
      success: false,
      error: `Missing configuration: ${v.missing.join(', ')}`,
    };
  }

  const resend = new Resend(config.resendApiKey);
  const html = renderHtml(rollup, new Date().toISOString(), periodLabel);
  const subject = `DMARC ${periodLabel} — ${rollup.totalMessages.toLocaleString()} messages, ${rollup.failedBoth} dual-failures`;

  try {
    const { data, error } = await resend.emails.send({
      from: config.senderEmail,
      to: config.recipientEmail,
      subject,
      html,
    });
    if (error) return { success: false, error: error.message };
    return { success: true, id: data?.id };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}
