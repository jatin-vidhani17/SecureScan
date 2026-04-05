import React, { useRef, useEffect } from 'react';

export default function ScanLogs({ logs, status, downloadLogs }) {
  const logsEndRef = useRef(null);

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  return (
    <div className="rounded-2xl border border-white/10 bg-slate-800/50 backdrop-blur-md shadow-lg overflow-hidden">
      <div className="flex items-center justify-between border-b border-white/10 bg-slate-800/80 px-6 py-4">
        <div>
          <h2 className="text-lg font-bold text-white tracking-wide">Scan Logs</h2>
          <p className="text-xs text-slate-400 mt-0.5">Real-time engine output</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => downloadLogs('txt')}
            className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-300 transition border border-white/10"
          >
            ↓ TXT
          </button>
          <button
            onClick={() => downloadLogs('json')}
            className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-300 transition border border-white/10"
          >
            ↓ JSON
          </button>
        </div>
      </div>

      <div className="bg-slate-950 p-6 h-64 overflow-y-auto font-mono text-xs text-emerald-400">
        {logs.length === 0 ? (
          <div className="text-slate-600 italic">Waiting for scan initialization...</div>
        ) : (
          logs.map((log, idx) => {
            const timeStr = new Date(log.timestamp + 'Z').toLocaleTimeString([], { hour12: false });
            return (
              <div key={idx} className="mb-1 leading-relaxed">
                <span className="text-slate-600">[{timeStr}]</span>{' '}
                <span className="text-slate-500">$</span> {log.message}
              </div>
            );
          })
        )}
        {status === 'running' && (
          <div className="mt-2 flex items-center text-emerald-400 opacity-80">
            <span className="mr-2 animate-pulse">Running</span>
            <span className="flex space-x-1">
              <span className="animate-bounce" style={{ animationDelay: '0ms' }}>.</span>
              <span className="animate-bounce" style={{ animationDelay: '150ms' }}>.</span>
              <span className="animate-bounce" style={{ animationDelay: '300ms' }}>.</span>
            </span>
            <span className="ml-2 w-2 h-3 bg-emerald-400 animate-pulse" />
          </div>
        )}
        <div ref={logsEndRef} />
      </div>
    </div>
  );
}
