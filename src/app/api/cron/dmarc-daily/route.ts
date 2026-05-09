import { type NextRequest, NextResponse } from 'next/server';
import { Resend } from 'resend';
import { config } from '@/lib/config';
import { parseAndAnalyze, processAttachments } from '@/lib/dmarc';
import { aggregate } from '@/lib/dmarc/rollup';
import { sendDMARCRollupEmail } from '@/lib/email/send-rollup';
import type { DMARCAnalysis } from '@/types/dmarc';

export const maxDuration = 300;

type ReceivedEmail = {
  id: string;
  from: string;
  subject: string;
  created_at: string;
  attachments: Array<{
    id: string;
    filename: string;
    content_type: string;
    content_disposition: string;
  }>;
};

const RESEND_API = 'https://api.resend.com';
const PAGE_SIZE = 100;

function isDmarcReport(e: ReceivedEmail): boolean {
  if (e.attachments.length === 0) return false;
  if (/dmarc/i.test(e.from)) return true;
  if (/^report (domain|id):/i.test(e.subject)) return true;
  if (/dmarc aggregate report/i.test(e.subject)) return true;
  return e.attachments.some(
    (a) => /\.(zip|gz|xml)$/i.test(a.filename) && a.filename.includes('!'),
  );
}

async function listSince(sinceMs: number): Promise<ReceivedEmail[]> {
  const all: ReceivedEmail[] = [];
  let after: string | undefined;
  for (;;) {
    const url = new URL(`${RESEND_API}/emails/receiving`);
    url.searchParams.set('limit', String(PAGE_SIZE));
    if (after) url.searchParams.set('after', after);
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${config.resendApiKey}` },
    });
    if (!res.ok) {
      throw new Error(`list failed: ${res.status}`);
    }
    const json = (await res.json()) as {
      data: ReceivedEmail[];
      has_more?: boolean;
    };
    let reachedFloor = false;
    for (const e of json.data) {
      if (Date.parse(e.created_at) < sinceMs) {
        reachedFloor = true;
        break;
      }
      all.push(e);
    }
    if (reachedFloor || !json.has_more || json.data.length === 0) break;
    after = json.data[json.data.length - 1].id;
  }
  return all;
}

export async function GET(request: NextRequest) {
  // Vercel cron auth: requires Bearer CRON_SECRET
  const auth = request.headers.get('authorization');
  if (auth !== `Bearer ${process.env.CRON_SECRET}`) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }

  if (!config.resendApiKey) {
    return NextResponse.json(
      { error: 'RESEND_API_KEY not configured' },
      { status: 500 },
    );
  }

  // Window: last 24h, ending at "now"
  const now = Date.now();
  const sinceMs = now - 24 * 60 * 60 * 1000;
  const periodLabel = `24h to ${new Date(now).toISOString().slice(0, 16)}Z`;

  let received: ReceivedEmail[];
  try {
    received = await listSince(sinceMs);
  } catch (err) {
    return NextResponse.json(
      { error: 'list-failed', details: (err as Error).message },
      { status: 502 },
    );
  }

  const dmarc = received.filter(isDmarcReport);
  console.log(
    `[dmarc-daily] window=${periodLabel} received=${received.length} dmarc=${dmarc.length}`,
  );

  if (dmarc.length === 0) {
    return NextResponse.json({
      ok: true,
      sent: false,
      reason: 'no DMARC reports in window',
      window: periodLabel,
    });
  }

  const resend = new Resend(config.resendApiKey);
  const analyses: DMARCAnalysis[] = [];
  let failures = 0;

  for (const email of dmarc) {
    const meta = email.attachments[0];
    if (!meta) {
      failures++;
      continue;
    }
    try {
      const { data: att } = await resend.emails.receiving.attachments.get({
        emailId: email.id,
        id: meta.id,
      });
      if (!att?.download_url) {
        failures++;
        continue;
      }
      const dl = await fetch(att.download_url);
      if (!dl.ok) {
        failures++;
        continue;
      }
      const buf = Buffer.from(await dl.arrayBuffer());
      const xmls = await processAttachments([
        { filename: att.filename ?? meta.filename, content: buf },
      ]);
      for (const xml of xmls) {
        analyses.push(parseAndAnalyze(xml));
      }
    } catch (e) {
      console.warn(`[dmarc-daily] parse failed for ${email.id}: ${(e as Error).message}`);
      failures++;
    }
  }

  if (analyses.length === 0) {
    return NextResponse.json(
      { error: 'all reports failed to parse', failures, dmarc: dmarc.length },
      { status: 500 },
    );
  }

  const rollup = aggregate(analyses, failures);
  const sent = await sendDMARCRollupEmail(rollup, periodLabel);

  return NextResponse.json({
    ok: sent.success,
    sent: sent.success,
    email_id: sent.id,
    error: sent.error,
    parsed: analyses.length,
    parse_failures: failures,
    total_messages: rollup.totalMessages,
    failed_both: rollup.failedBoth,
  });
}
