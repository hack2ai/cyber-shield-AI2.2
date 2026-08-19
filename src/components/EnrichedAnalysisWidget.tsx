import React, { useEffect, useRef, useState } from 'react';
import { RefreshCcw, ShieldAlert } from 'lucide-react';
import { analyzeUrl, type AnalysisResult } from '../lib/analysis-api';
import { SecurityAnalysisPanel } from './SecurityAnalysisPanel';

interface EnrichedAnalysisWidgetProps {
  target: string;
  enabled?: boolean;
}

export function EnrichedAnalysisWidget({ target, enabled = true }: EnrichedAnalysisWidgetProps) {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const requestId = useRef(0);

  useEffect(() => {
    if (!enabled || !target.trim()) {
      setResult(null);
      setError(null);
      return;
    }

    const controller = new AbortController();
    const currentRequest = ++requestId.current;

    setLoading(true);
    setError(null);

    analyzeUrl(target.trim(), controller.signal)
      .then((nextResult) => {
        if (currentRequest === requestId.current) setResult(nextResult);
      })
      .catch((nextError) => {
        if (controller.signal.aborted || currentRequest !== requestId.current) return;
        setResult(null);
        setError(nextError instanceof Error ? nextError.message : 'Analysis request failed');
      })
      .finally(() => {
        if (currentRequest === requestId.current) setLoading(false);
      });

    return () => controller.abort();
  }, [target, enabled]);

  if (!enabled || !target.trim()) return null;

  if (loading) {
    return (
      <section className="rounded-2xl border border-[#39FF14]/20 bg-black/70 p-6 text-[#39FF14]" aria-live="polite">
        <div className="flex items-center gap-3">
          <RefreshCcw className="h-5 w-5 animate-spin" />
          <div>
            <p className="text-sm font-semibold uppercase tracking-widest">Enriched analysis running</p>
            <p className="mt-1 text-xs opacity-60">Collecting DNS, TLS, WHOIS, VirusTotal and redirect evidence.</p>
          </div>
        </div>
      </section>
    );
  }

  if (error) {
    return (
      <section className="rounded-2xl border border-red-500/30 bg-red-950/20 p-6 text-red-300" role="alert">
        <div className="flex items-start gap-3">
          <ShieldAlert className="h-5 w-5 shrink-0 text-red-400" />
          <div>
            <p className="text-sm font-semibold uppercase tracking-widest">Enriched analysis unavailable</p>
            <p className="mt-1 text-xs opacity-80">{error}</p>
          </div>
        </div>
      </section>
    );
  }

  return result ? <SecurityAnalysisPanel result={result} /> : null;
}
