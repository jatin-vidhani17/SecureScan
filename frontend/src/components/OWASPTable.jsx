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
  const [copiedId, setCopiedId] = useState(null);

  const handleCopy = (code, id) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

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
              <div className="px-6 pb-4 space-y-4 bg-slate-900/50 border-t border-white/5">
                {/* Description */}
                <div className="pt-3">
                  <p className="text-xs font-bold text-slate-500 uppercase mb-1">Description</p>
                  <p className="text-sm text-slate-300">{result.description}</p>
                </div>

                {/* Framework specific reason */}
                {result.status === 'fail' && result.reason && (
                  <div className="rounded-xl bg-red-500/5 border border-red-500/10 p-4 text-xs text-slate-300 leading-relaxed">
                    <span className="font-bold text-red-400 block mb-1">Why this is a risk:</span>
                    {result.reason}
                  </div>
                )}

                {/* Recommendation */}
                {result.status === 'fail' && result.recommendation && (
                  <div>
                    <p className="text-xs font-bold text-slate-500 uppercase mb-1">General Recommendation</p>
                    <p className="text-sm text-slate-300">{result.recommendation}</p>
                  </div>
                )}

                {/* Remediation steps list */}
                {result.status === 'fail' && result.tips && result.tips.length > 0 && (
                  <div>
                    <p className="text-xs font-bold text-slate-500 uppercase mb-1.5">Actionable Remediation Tips</p>
                    <ul className="list-disc pl-5 space-y-1.5 text-xs text-slate-300">
                      {result.tips.map((tip, tIdx) => (
                        <li key={tIdx}>{tip}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Remediation code snippet */}
                {result.status === 'fail' && result.code_snippet && (
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <p className="text-xs font-bold text-slate-500 uppercase">Remediation Code Example</p>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleCopy(result.code_snippet, result.owasp_id);
                        }}
                        className="text-xs text-indigo-400 hover:text-indigo-300 transition-colors flex items-center gap-1 font-semibold focus:outline-none"
                      >
                        {copiedId === result.owasp_id ? (
                          <>
                            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                            </svg>
                            Copied!
                          </>
                        ) : (
                          <>
                            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
                            </svg>
                            Copy Code
                          </>
                        )}
                      </button>
                    </div>
                    <pre className="bg-slate-950 border border-white/5 rounded-xl p-4 font-mono text-xs text-emerald-400 overflow-x-auto max-w-full shadow-inner leading-relaxed">
                      <code>{result.code_snippet}</code>
                    </pre>
                  </div>
                )}

                {/* Findings list */}
                {result.findings && result.findings.length > 0 && (
                  <div>
                    <p className="text-xs font-bold text-slate-500 uppercase mb-1">Discovered Findings ({result.findings.length})</p>
                    <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                      {result.findings.map((f, fIdx) => (
                        <div key={fIdx} className="rounded-xl bg-slate-900 border border-white/5 p-3.5 text-xs">
                          <p className="text-slate-200 font-medium">{f.issue || f.url || 'Finding'}</p>
                          {f.url && <p className="text-slate-500 mt-1 truncate">URL: {f.url}</p>}
                          {f.evidence && <p className="text-slate-400 mt-1 font-mono bg-slate-950/50 rounded px-1.5 py-1 inline-block">Evidence: {f.evidence}</p>}
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

