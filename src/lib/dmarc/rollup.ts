import type { DMARCAnalysis } from '@/types/dmarc';

export type Rollup = {
  reportCount: number;
  failedReportCount: number;
  totalMessages: number;
  passedBoth: number;
  passedDkimOnly: number;
  passedSpfOnly: number;
  failedBoth: number;
  rangeStart: number;
  rangeEnd: number;
  byOrg: Map<
    string,
    { reports: number; messages: number; passed: number; failed: number }
  >;
  bySourceIp: Map<
    string,
    { messages: number; passed: number; failed: number }
  >;
  topFailures: Array<{
    sourceIp: string;
    org: string;
    count: number;
    dkim: string;
    spf: string;
  }>;
};

export function aggregate(
  analyses: DMARCAnalysis[],
  failedReportCount: number,
): Rollup {
  const r: Rollup = {
    reportCount: analyses.length,
    failedReportCount,
    totalMessages: 0,
    passedBoth: 0,
    passedDkimOnly: 0,
    passedSpfOnly: 0,
    failedBoth: 0,
    rangeStart: Number.POSITIVE_INFINITY,
    rangeEnd: 0,
    byOrg: new Map(),
    bySourceIp: new Map(),
    topFailures: [],
  };

  for (const a of analyses) {
    const meta = a.report.report_metadata;
    if (meta.date_range.begin && meta.date_range.begin < r.rangeStart) {
      r.rangeStart = meta.date_range.begin;
    }
    if (meta.date_range.end && meta.date_range.end > r.rangeEnd) {
      r.rangeEnd = meta.date_range.end;
    }

    const orgKey = meta.org_name;
    const orgAgg = r.byOrg.get(orgKey) ?? {
      reports: 0,
      messages: 0,
      passed: 0,
      failed: 0,
    };
    orgAgg.reports++;
    r.byOrg.set(orgKey, orgAgg);

    for (const rec of a.report.record) {
      const count = rec.row.count;
      const pe = rec.row.policy_evaluated;
      if (!pe) continue;

      r.totalMessages += count;
      orgAgg.messages += count;

      const dkimPass = pe.dkim === 'pass';
      const spfPass = pe.spf === 'pass';
      if (dkimPass && spfPass) {
        r.passedBoth += count;
        orgAgg.passed += count;
      } else if (dkimPass && !spfPass) {
        r.passedDkimOnly += count;
        orgAgg.passed += count;
      } else if (!dkimPass && spfPass) {
        r.passedSpfOnly += count;
        orgAgg.passed += count;
      } else {
        r.failedBoth += count;
        orgAgg.failed += count;
        r.topFailures.push({
          sourceIp: rec.row.source_ip,
          org: meta.org_name,
          count,
          dkim: pe.dkim,
          spf: pe.spf,
        });
      }

      const ipAgg = r.bySourceIp.get(rec.row.source_ip) ?? {
        messages: 0,
        passed: 0,
        failed: 0,
      };
      ipAgg.messages += count;
      if (dkimPass || spfPass) ipAgg.passed += count;
      else ipAgg.failed += count;
      r.bySourceIp.set(rec.row.source_ip, ipAgg);
    }
  }

  r.topFailures.sort((a, b) => b.count - a.count);
  r.topFailures = r.topFailures.slice(0, 15);
  return r;
}
