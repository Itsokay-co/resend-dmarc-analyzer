import { type NextRequest, NextResponse } from 'next/server';
import { Resend } from 'resend';
import {
  config,
  validateEmailConfig,
  validateWebhookConfig,
} from '@/lib/config';
import { parseAndAnalyze, processAttachments } from '@/lib/dmarc';
import { sendDMARCReportEmail } from '@/lib/email/send-report';
import {
  extractWebhookHeaders,
  verifyWebhookSignature,
} from '@/lib/webhook/verify';
import type { DMARCAnalysis } from '@/types/dmarc';

interface ResendWebhookPayload {
  type: string;
  created_at: string;
  data: {
    email_id: string;
    from: string;
    to: string[];
    subject: string;
    attachments: Array<{
      id: string;
      filename: string;
      content_type: string;
      content_disposition: string;
      content_id?: string;
    }>;
  };
}

export async function POST(request: NextRequest) {
  // Validate config
  const configValidation = validateWebhookConfig();
  if (!configValidation.valid) {
    console.error('Missing configuration:', configValidation.missing);
    return NextResponse.json(
      { error: 'Server configuration error' },
      { status: 500 },
    );
  }

  // Get raw body for signature verification
  const rawBody = await request.text();

  // Verify webhook signature
  const webhookHeaders = extractWebhookHeaders(request.headers);
  if (!webhookHeaders) {
    return NextResponse.json(
      { error: 'Missing webhook signature headers' },
      { status: 401 },
    );
  }

  const isValid = verifyWebhookSignature(
    rawBody,
    webhookHeaders,
    config.webhookSecret,
  );

  if (!isValid) {
    return NextResponse.json(
      { error: 'Invalid webhook signature' },
      { status: 401 },
    );
  }

  // Parse the webhook payload
  let webhook: ResendWebhookPayload;
  try {
    webhook = JSON.parse(rawBody);
  } catch {
    return NextResponse.json(
      { error: 'Invalid JSON payload' },
      { status: 400 },
    );
  }

  if (webhook.type !== 'email.received') {
    return NextResponse.json(
      { error: 'Unexpected event type' },
      { status: 400 },
    );
  }

  const { data: email } = webhook;

  // Process attachments
  if (!email.attachments || email.attachments.length === 0) {
    return NextResponse.json(
      { error: 'No attachments found' },
      { status: 400 },
    );
  }

  try {
    // Fetch attachment content via Resend API
    const resend = new Resend(config.resendApiKey);
    const { data: attachmentList } =
      await resend.emails.receiving.attachments.list({
        emailId: email.email_id,
      });

    if (!attachmentList || attachmentList.data.length === 0) {
      return NextResponse.json(
        { error: 'No attachments found via API' },
        { status: 400 },
      );
    }

    // Download attachment content
    const attachmentsWithContent: Array<{ filename: string; content: Buffer }> =
      [];
    for (const attachment of attachmentList.data) {
      const response = await fetch(attachment.download_url);
      if (!response.ok) {
        console.error(`Failed to download ${attachment.filename}`);
        continue;
      }
      const buffer = Buffer.from(await response.arrayBuffer());
      attachmentsWithContent.push({
        filename: attachment.filename ?? 'unknown',
        content: buffer,
      });
    }

    // Extract XML from attachments
    const xmlContents = await processAttachments(attachmentsWithContent);

    if (xmlContents.length === 0) {
      return NextResponse.json(
        { error: 'No DMARC reports found in attachments' },
        { status: 400 },
      );
    }

    // Parse and analyze each report
    const analyses: DMARCAnalysis[] = [];
    for (const xml of xmlContents) {
      const analysis = parseAndAnalyze(xml);
      analyses.push(analysis);
    }

    // TODO: Store in database when ready

    // Send email digest if configured
    const emailConfig = validateEmailConfig();
    const emailResults: Array<{ success: boolean; error?: string }> = [];

    if (emailConfig.valid) {
      for (const analysis of analyses) {
        const result = await sendDMARCReportEmail(analysis);
        emailResults.push(result);
        if (result.success) {
          console.log(
            `Sent DMARC report email for ${analysis.report.report_metadata.org_name}`,
          );
        } else {
          console.error(`Failed to send email: ${result.error}`);
        }
      }
    }

    console.log(
      `Processed ${analyses.length} DMARC report(s) from ${email.from}`,
    );
    console.log(
      'Reports:',
      analyses.map((a) => ({
        org: a.report.report_metadata.org_name,
        domain: a.report.policy_published.domain,
        totalMessages: a.summary.totalMessages,
        passRate:
          ((a.summary.passedBoth / a.summary.totalMessages) * 100).toFixed(1) +
          '%',
      })),
    );

    return NextResponse.json({
      success: true,
      processed: analyses.length,
      emails_sent: emailResults.filter((r) => r.success).length,
      reports: analyses.map((a) => ({
        org_name: a.report.report_metadata.org_name,
        report_id: a.report.report_metadata.report_id,
        domain: a.report.policy_published.domain,
        total_messages: a.summary.totalMessages,
        passed_both: a.summary.passedBoth,
      })),
    });
  } catch (error) {
    console.error('Error processing DMARC report:', error);
    return NextResponse.json(
      {
        error: 'Failed to process DMARC report',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 },
    );
  }
}
