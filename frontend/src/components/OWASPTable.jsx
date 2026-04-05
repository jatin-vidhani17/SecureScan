import React, { useState } from 'react';

const statusStyles = {
  pass: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  fail: 'bg-red-500/20 text-red-400 border-red-500/30',
};

const severityDot = {
  High: 'bg-red-500',
  Medium: 'bg-amber-500',
  Low: 'bg-emerald-500',
};

export default function OWASPTable({ owaspResults }) {
  const [expanded, setExpanded] = useState(null);

  return (
    <div className="rounded-2xl border border-white/10 bg-slate-800/50 backdrop-blur-md shadow-lg overflow-hidden">
      <div className="border-b border-white/10 bg-slate-800/80 px-6 py-4">
        <h2 className="text-lg font-bold text-white tracking-wide">OWASP Top 10 Assessment</h2>
        <p className="text-xs text-slate-400 mt-1">Detailed results for each security category</p>
      </div>

      <div className="divide-y divide-white/5">
        {owaspResults.map((result, idx) => (
          <div key={result.owasp_id} className="group">
            {/* Row */}
            <button
              onClick={() => setExpanded(expanded === idx ? null : idx)}
              className="w-full flex items-center gap-4 px-6 py-4 text-left hover:bg-white/5 transition-colors"
            >
              {/* OWASP ID */}
              <span className="flex-shrink-0 w-12 text-xs font-bold text-indigo-400 font-mono">
                {result.owasp_id}
              </span>

              {/* Name */}
              <span className="flex-1 text-sm font-medium text-slate-200">
                {result.owasp_name}
              </span>

              {/* Severity dot */}
              <span className={`h-2.5 w-2.5 rounded-full ${severityDot[result.severity] || 'bg-slate-500'}`} />

              {/* Status badge */}
              <span className={`inline-flex items-center rounded-full border px-3 py-0.5 text-xs font-bold uppercase ${statusStyles[result.status]}`}>
                {result.status === 'pass' ? '✓ Pass' : '✗ Fail'}
              </span>

              {/* Expand chevron */}
              <svg
                className={`h-4 w-4 text-slate-500 transition-transform ${expanded === idx ? 'rotate-180' : ''}`}
                fill="none" viewBox="0 0 24 24" stroke="currentColor"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>

            {/* Expanded detail */}
            {expanded === idx && (
              <div className="px-6 pb-4 space-y-3 bg-slate-900/50 border-t border-white/5">
                <div className="pt-3">
                  <p className="text-xs font-bold text-slate-500 uppercase mb-1">Description</p>
                  <p className="text-sm text-slate-300">{result.description}</p>
                </div>
                {result.status === 'fail' && result.recommendation && (
                  <div>
                    <p className="text-xs font-bold text-slate-500 uppercase mb-1">Recommendation</p>
                    <p className="text-sm text-cyan-300">{result.recommendation}</p>
                  </div>
                )}
                {result.findings && result.findings.length > 0 && (
                  <div>
                    <p className="text-xs font-bold text-slate-500 uppercase mb-1">Findings ({result.findings.length})</p>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {result.findings.map((f, fIdx) => (
                        <div key={fIdx} className="rounded-lg bg-slate-800 p-3 text-xs">
                          <p className="text-slate-200 font-medium">{f.issue || f.url || 'Finding'}</p>
                          {f.url && <p className="text-slate-500 mt-1 truncate">URL: {f.url}</p>}
                          {f.evidence && <p className="text-slate-400 mt-1">Evidence: {f.evidence}</p>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
