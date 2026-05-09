import { type NextRequest, NextResponse } from 'next/server';
import { config, validateWebhookConfig } from '@/lib/config';
import {
  extractWebhookHeaders,
  verifyWebhookSignature,
} from '@/lib/webhook/verify';

/**
 * Resend `email.received` webhook for DMARC reports.
 *
 * Behavior is intentionally minimal: verify signature, log, ack 200.
 * The actual rollup is sent once a day by /api/cron/dmarc-daily, which
 * walks Resend's /emails/receiving and aggregates the past 24h into a
 * single email. This handler exists so Resend's retry queue stays clean.
 */
export async function POST(request: NextRequest) {
  const v = validateWebhookConfig();
  if (!v.valid) {
    console.error('Missing configuration:', v.missing);
    return NextResponse.json(
      { error: 'Server configuration error' },
      { status: 500 },
    );
  }

  const rawBody = await request.text();
  const headers = extractWebhookHeaders(request.headers);
  if (!headers) {
    return NextResponse.json(
      { error: 'Missing webhook signature headers' },
      { status: 401 },
    );
  }

  if (!verifyWebhookSignature(rawBody, headers, config.webhookSecret)) {
    return NextResponse.json(
      { error: 'Invalid webhook signature' },
      { status: 401 },
    );
  }

  try {
    const payload = JSON.parse(rawBody) as {
      type: string;
      data: { email_id: string; from: string; subject: string };
    };
    console.log(
      `[rua] noop ack — type=${payload.type} email_id=${payload.data?.email_id} from=${payload.data?.from}`,
    );
  } catch {
    // Even if the body doesn't parse, return 200 so Resend doesn't retry —
    // the daily cron walks /emails/receiving directly and is unaffected.
  }

  return NextResponse.json({ ok: true, mode: 'noop-cron-handles-rollup' });
}
