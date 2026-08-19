import React from 'react';
import { AlertTriangle, CheckCircle, Globe, Lock, ShieldAlert } from 'lucide-react';
import type { AnalysisResult, RiskLevel } from '../lib/analysis-api';

interface SecurityAnalysisPanelProps {
  result: AnalysisResult;
}

const levelClasses: Record<RiskLevel, string> = {
  LOW: 'border-emerald-200 bg-emerald-50 text-emerald-800',
  MEDIUM: 'border-amber-200 bg-amber-50 text-amber-800',
  HIGH: 'border-orange-200 bg-orange-50 text-orange-800',
  CRITICAL: 'border-red-200 bg-red-50 text-red-800',
};

function statusLabel(value: string) {
  return value.replace(/-/g, ' ');
}

export function SecurityAnalysisPanel({ result }: SecurityAnalysisPanelProps) {
  const { assessment, threatIntelligence, redirects } = result;
  const vt = threatIntelligence.virusTotal;
  const tlsOk = threatIntelligence.tls.authorized && !threatIntelligence.tls.error;
  const hasRedirectRisk = redirects.redirectCount >= 3 || redirects.hostnameChanged || Boolean(redirects.error);

  return (
    <section className="space-y-6" aria-label="Security analysis results">
      <div className={`rounded-2xl border p-6 ${levelClasses[assessment.level]}`}>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide">
              <ShieldAlert className="h-5 w-5" />
              Security assessment
            </div>
            <div className="mt-2 flex items-end gap-3">
              <span className="text-5xl font-bold leading-none">{assessment.score}</span>
              <span className="pb-1 text-sm font-semibold">/ 100</span>
            </div>
            <p className="mt-2 text-sm font-medium">
              {assessment.level} risk · {assessment.confidence}% confidence
            </p>
          </div>

          <div className="rounded-xl bg-white/70 p-4 text-sm shadow-sm">
            <p className="font-semibold">{assessment.findings.length} evidence items</p>
            <p className="mt-1 opacity-80">Deterministic score from collected security evidence.</p>
          </div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-2xl border bg-white p-5 shadow-sm">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-700"><Globe className="h-4 w-4" /> DNS</div>
          <p className="mt-3 text-2xl font-bold text-slate-900">{threatIntelligence.dns.ipv4.length + threatIntelligence.dns.ipv6.length}</p>
          <p className="text-xs text-slate-500">resolved addresses</p>
          {threatIntelligence.dns.errors.length > 0 && <p className="mt-2 text-xs text-amber-700">{threatIntelligence.dns.errors.length} lookup issue(s)</p>}
        </div>

        <div className="rounded-2xl border bg-white p-5 shadow-sm">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-700"><Lock className="h-4 w-4" /> TLS</div>
          <p className="mt-3 text-2xl font-bold text-slate-900">{tlsOk ? 'Valid' : 'Review'}</p>
          <p className="text-xs text-slate-500">{threatIntelligence.tls.protocol ?? 'No protocol'}</p>
        </div>

        <div className="rounded-2xl border bg-white p-5 shadow-sm">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-700"><ShieldAlert className="h-4 w-4" /> VirusTotal</div>
          <p className="mt-3 text-2xl font-bold text-slate-900">{vt.malicious + vt.suspicious}</p>
          <p className="text-xs text-slate-500">malicious + suspicious detections</p>
          <p className="mt-2 text-xs text-slate-500">Status: {statusLabel(vt.status)}</p>
        </div>

        <div className="rounded-2xl border bg-white p-5 shadow-sm">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-700"><AlertTriangle className="h-4 w-4" /> Redirects</div>
          <p className="mt-3 text-2xl font-bold text-slate-900">{redirects.redirectCount}</p>
          <p className="text-xs text-slate-500">redirect hop(s)</p>
          <p className="mt-2 text-xs text-slate-500">{redirects.hostnameChanged ? 'Hostname changed' : 'Same hostname'}</p>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-2xl border bg-white p-6 shadow-sm">
          <h3 className="text-base font-semibold text-slate-900">Evidence</h3>
          <div className="mt-4 space-y-3">
            {assessment.findings.length === 0 ? (
              <div className="flex items-center gap-2 text-sm text-emerald-700"><CheckCircle className="h-4 w-4" /> No suspicious findings were recorded.</div>
            ) : (
              assessment.findings.map((finding) => (
                <div key={finding.id} className="rounded-xl border border-slate-200 p-4">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <p className="font-medium text-slate-900">{finding.label}</p>
                      <p className="mt-1 text-sm text-slate-600">{finding.description}</p>
                    </div>
                    <span className="rounded-full bg-slate-100 px-2 py-1 text-xs font-semibold text-slate-700">S{finding.severity}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="rounded-2xl border bg-white p-6 shadow-sm">
          <h3 className="text-base font-semibold text-slate-900">Infrastructure intelligence</h3>
          <dl className="mt-4 space-y-3 text-sm">
            <div className="flex justify-between gap-4"><dt className="text-slate-500">Hostname</dt><dd className="font-medium text-slate-900">{threatIntelligence.hostname}</dd></div>
            <div className="flex justify-between gap-4"><dt className="text-slate-500">Registrar</dt><dd className="font-medium text-slate-900">{threatIntelligence.whois.registrar ?? 'Unavailable'}</dd></div>
            <div className="flex justify-between gap-4"><dt className="text-slate-500">Name servers</dt><dd className="font-medium text-slate-900">{threatIntelligence.whois.nameServers.length}</dd></div>
            <div className="flex justify-between gap-4"><dt className="text-slate-500">Final URL</dt><dd className="max-w-[65%] break-all text-right font-medium text-slate-900">{redirects.finalUrl}</dd></div>
            <div className="flex justify-between gap-4"><dt className="text-slate-500">Redirect risk</dt><dd className={`font-medium ${hasRedirectRisk ? 'text-amber-700' : 'text-emerald-700'}`}>{hasRedirectRisk ? 'Review' : 'Normal'}</dd></div>
          </dl>
        </div>
      </div>
    </section>
  );
}
