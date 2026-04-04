import { useMemo, useState, useEffect, useRef } from 'react';
import { startScan, getScanStatus, getScanResults, getScanLogs } from './api';

const severityClass = {
  High: 'bg-red-100 text-red-700 border-red-200',
  Medium: 'bg-amber-100 text-amber-700 border-amber-200',
  Low: 'bg-emerald-100 text-emerald-700 border-emerald-200',
};

export default function App() {
  const [url, setUrl] = useState('http://testphp.vulnweb.com');
  const [status, setStatus] = useState('idle'); // idle, running, completed, error
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [logs, setLogs] = useState([]);
  const logsEndRef = useRef(null);

  const stats = useMemo(() => {
    if (!result?.summary) {
      return { total: 0, high: 0, medium: 0, low: 0 };
    }
    return result.summary;
  }, [result]);

  useEffect(() => {
    let interval;
    if (status === 'running') {
      interval = setInterval(async () => {
        try {
          const res = await getScanStatus(url);
          
          try {
            const logsRes = await getScanLogs(url);
            if (logsRes.logs) setLogs(logsRes.logs);
          } catch (e) {
            // Ignore log fetch errors before scan is fully initialized in db
          }

          if (res.status === 'completed') {
            setStatus('completed');
            const data = await getScanResults(url);
            setResult(data);
            
            try {
              const logsRes = await getScanLogs(url);
              if (logsRes.logs) setLogs(logsRes.logs);
            } catch (e) {}
          }
        } catch (err) {
          console.error("Polling error", err);
        }
      }, 1500); // Polling every 1.5 seconds for snappier log updates
    }
    return () => clearInterval(interval);
  }, [status, url]);

  useEffect(() => {
    // Auto-scroll logs
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  const downloadLogs = (format) => {
    if (!logs.length) return;
    
    let content, mimeType, filename;
    if (format === 'json') {
        content = JSON.stringify(logs, null, 2);
        mimeType = 'application/json';
        filename = 'scan_logs.json';
    } else {
        content = logs.map(l => `[${l.timestamp}] ${l.message}`).join('\\n');
        mimeType = 'text/plain';
        filename = 'scan_logs.txt';
    }
    
    const blob = new Blob([content], { type: mimeType });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setStatus('running');
    setError('');
    setResult(null);
    setLogs([]);

    try {
      await startScan(url);
    } catch (err) {
      const message = err?.response?.data?.error || 'Failed to start scan';
      setError(message);
      setStatus('error');
    }
  };

  return (
    <main className="min-h-screen bg-slate-50 text-slate-800 font-sans">
      <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
        <header className="mb-8 flex flex-col items-start justify-between rounded-xl border border-slate-200 bg-white p-6 shadow-sm md:flex-row md:items-center">
          <div>
            <p className="text-xs font-bold tracking-widest text-indigo-500 uppercase">SecureScan</p>
            <h1 className="mt-1 text-3xl font-extrabold text-slate-900">Dashboard</h1>
            <p className="mt-2 max-w-2xl text-slate-500">
              Vulnerability scanner checking for SQLi, XSS, and Sensitive Data Exposure using Python Engine & SQLite.
            </p>
          </div>
          {status === 'running' && (
            <div className="mt-4 flex items-center gap-3 rounded-full bg-indigo-50 px-4 py-2 text-indigo-700 md:mt-0">
              <span className="relative flex h-3 w-3">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-indigo-400 opacity-75"></span>
                <span className="relative inline-flex h-3 w-3 rounded-full bg-indigo-500"></span>
              </span>
              <span className="font-medium text-sm">Scan Engine Running...</span>
            </div>
          )}
        </header>

        <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <form onSubmit={handleSubmit} className="flex flex-col gap-4 sm:flex-row">
            <input
              type="url"
              required
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="http://testphp.vulnweb.com"
              className="flex-1 rounded-lg border border-slate-300 px-4 py-3 outline-none ring-indigo-200 transition focus:ring"
            />
            <button
              type="submit"
              disabled={status === 'running'}
              className="rounded-lg bg-indigo-600 px-8 py-3 font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-slate-300 transition-colors"
            >
              Start Scan
            </button>
          </form>
          {error && <p className="mt-4 rounded-lg bg-red-50 p-3 text-red-700">{error}</p>}
        </section>

        {status === 'completed' && result && (
          <div className="mt-8 space-y-6">
            <section className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <StatCard label="Total Vulnerabilities" value={stats.total} accent="text-slate-800" />
              <StatCard label="High Severity" value={stats.high} accent="text-red-600" />
              <StatCard label="Medium Severity" value={stats.medium} accent="text-amber-600" />
              <StatCard label="Low Severity" value={stats.low} accent="text-emerald-600" />
            </section>

            <section className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
              <div className="border-b border-slate-200 bg-slate-50 px-6 py-4">
                <h2 className="text-xl font-bold text-slate-800">Scan Results for {result.target}</h2>
                <p className="text-sm text-slate-500 mt-1">Found {result.vulnerabilities.length} issues during crawl phase.</p>
              </div>

              <div className="p-6">
                {result.vulnerabilities.length === 0 ? (
                  <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-6 text-center text-emerald-700 font-medium">
                    No vulnerabilities found! Your application appears secure against basic attacks.
                  </div>
                ) : (
                  <div className="space-y-4">
                    {result.vulnerabilities.map((finding, index) => (
                      <article key={`${finding.type}-${index}`} className="rounded-lg border border-slate-200 px-5 py-4 hover:border-indigo-300 transition-colors">
                        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-3">
                              <h3 className="text-lg font-bold text-slate-900">{finding.type}</h3>
                              <span className={`inline-flex rounded-md border px-2.5 py-0.5 text-xs font-semibold uppercase ${severityClass[finding.severity]}`}>
                                {finding.severity}
                              </span>
                            </div>
                            <div className="mt-2 grid grid-cols-1 gap-y-2 sm:grid-cols-2 text-sm">
                              <div><span className="font-semibold text-slate-700">URL:</span> <code className="block mt-1 bg-slate-100 rounded px-2 py-1 text-xs break-all text-slate-600">{finding.url}</code></div>
                              {finding.parameter && <div><span className="font-semibold text-slate-700">Parameter:</span> <span className="block mt-1 text-slate-600 font-mono text-xs">{finding.parameter}</span></div>}
                              {finding.payload && <div><span className="font-semibold text-slate-700">Payload:</span> <code className="block mt-1 bg-red-50 text-red-600 rounded px-2 py-1 text-xs font-mono">{finding.payload}</code></div>}
                              {finding.description && <div><span className="font-semibold text-slate-700">Details:</span> <span className="block mt-1 text-slate-600">{finding.description}</span></div>}
                            </div>
                          </div>
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </div>
            </section>
          </div>
        )}

        {(status === 'running' || status === 'completed') && (
          <section className="mt-8 rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-200 bg-slate-50 px-6 py-4">
              <h2 className="text-xl font-bold text-slate-800">Scan Logs</h2>
              <div className="flex gap-2">
                <button onClick={() => downloadLogs('txt')} className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-slate-200 hover:bg-slate-300 text-slate-700 transition">
                  Download TXT
                </button>
                <button onClick={() => downloadLogs('json')} className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-slate-200 hover:bg-slate-300 text-slate-700 transition">
                  Download JSON
                </button>
              </div>
            </div>
            <div className="bg-slate-900 p-6 h-64 overflow-y-auto font-mono text-xs text-emerald-400">
              {logs.length === 0 ? (
                <div className="text-slate-500 italic">Waiting for scan initialization...</div>
              ) : (
                logs.map((log, idx) => (
                  <div key={idx} className="mb-1 leading-relaxed">
                    <span className="text-slate-500">[{log.timestamp}]</span> <span className="text-slate-300">$</span> {log.message}
                  </div>
                ))
              )}
              <div ref={logsEndRef} />
            </div>
          </section>
        )}
      </div>
    </main>
  );
}

function StatCard({ label, value, accent }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm text-center">
      <p className="text-sm font-medium text-slate-500">{label}</p>
      <p className={`mt-2 text-4xl font-black ${accent}`}>{value}</p>
    </div>
  );
}
