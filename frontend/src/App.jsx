import { useMemo, useState, useEffect } from 'react';
import { startScan, cancelScan, getScanStatus, getScanResults, getScanLogs } from './api';

import ScoreCard from './components/ScoreCard';
import OWASPTable from './components/OWASPTable';
import VulnerabilityList from './components/VulnerabilityList';
import ScanLogs from './components/ScanLogs';
import ReportExport from './components/ReportExport';
import ScanHistory from './components/ScanHistory';
import { PassFailChart, OWASPRadarChart, SeverityDonut } from './components/Charts';

export default function App() {
  const [currentPage, setCurrentPage] = useState('scanner'); // 'scanner' or 'history'
  const [url, setUrl] = useState('http://testphp.vulnweb.com');
  const [status, setStatus] = useState('idle'); // idle, running, completed, error, cancelled
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [logs, setLogs] = useState([]);

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
            // Ignore log fetch errors before scan is fully initialized
          }

          if (res.status === 'completed') {
            setStatus('completed');
            const data = await getScanResults(url);
            setResult(data);

            try {
              const logsRes = await getScanLogs(url);
              if (logsRes.logs) setLogs(logsRes.logs);
            } catch (e) {}
          } else if (res.status === 'cancelled') {
            setStatus('cancelled');
            setError('Scan was cancelled by user.');
            try {
              const data = await getScanResults(url);
              setResult(data);
            } catch (e) {
              // Partial results may not be available
            }
            try {
              const logsRes = await getScanLogs(url);
              if (logsRes.logs) setLogs(logsRes.logs);
            } catch (e) {}
          } else if (res.status === 'error') {
            setStatus('error');
            setError('The scan failed due to an error on the server.');
          } else if (res.status === 'interrupted') {
            setStatus('cancelled');
            setError('Scan was interrupted — the server was restarted while the scan was running.');
            try {
              const logsRes = await getScanLogs(url);
              if (logsRes.logs) setLogs(logsRes.logs);
            } catch (e) {}
          }
        } catch (err) {
          console.error('Polling error', err);
        }
      }, 1500);
    }
    return () => clearInterval(interval);
  }, [status, url]);

  const downloadLogs = (format) => {
    if (!logs.length) return;

    let content, mimeType, filename;
    if (format === 'json') {
      content = JSON.stringify(logs, null, 2);
      mimeType = 'application/json';
      filename = 'scan_logs.json';
    } else {
      content = logs.map(l => `[${l.timestamp}] ${l.message}`).join('\n');
      mimeType = 'text/plain';
      filename = 'scan_logs.txt';
    }

    const blob = new Blob([content], { type: mimeType });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    URL.revokeObjectURL(link.href);
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

  const handleCancel = async () => {
    try {
      await cancelScan(url);
      setStatus('cancelled');
      setError('Scan cancellation requested...');
    } catch (err) {
      const message = err?.response?.data?.error || 'Failed to cancel scan';
      setError(message);
    }
  };

  // Show history page if selected
  if (currentPage === 'history') {
    return (
      <main className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-slate-200 font-body">
        {/* Background grid effect */}
        <div className="fixed inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGRlZnM+PHBhdHRlcm4gaWQ9ImdyaWQiIHdpZHRoPSI0MCIgaGVpZ2h0PSI0MCIgcGF0dGVyblVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+PHBhdGggZD0iTSAwIDEwIEwgNDAgMTAgTSAxMCAwIEwgMTAgNDAgTSAwIDIwIEwgNDAgMjAgTSAyMCAwIEwgMjAgNDAgTSAwIDMwIEwgNDAgMzAgTSAzMCAwIEwgMzAgNDAiIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzFlMjkzYiIgb3BhY2l0eT0iMC4zIiBzdHJva2Utd2lkdGg9IjEiLz48L3BhdHRlcm4+PC9kZWZzPjxyZWN0IHdpZHRoPSIxMDAlIiBoZWlnaHQ9IjEwMCUiIGZpbGw9InVybCgjZ3JpZCkiLz48L3N2Zz4=')] opacity-30 pointer-events-none" />

        <div className="relative mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
          {/* Header with nav tabs */}
          <header className="mb-8 flex flex-col items-start justify-between rounded-2xl border border-white/10 bg-slate-800/50 backdrop-blur-md p-6 shadow-xl md:flex-row md:items-center">
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500 to-cyan-400 shadow-lg shadow-indigo-500/20">
                <svg className="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <div>
                <p className="text-xs font-bold tracking-[0.2em] text-indigo-400 uppercase">SecureScan</p>
                <h1 className="text-2xl font-extrabold text-white font-heading">Security Dashboard</h1>
              </div>
            </div>
            {/* Navigation tabs */}
            <div className="mt-4 flex gap-2 md:mt-0">
              <button
                onClick={() => setCurrentPage('scanner')}
                className="px-4 py-2 rounded-lg bg-slate-700/50 hover:bg-slate-700 text-slate-300 font-semibold transition-colors"
              >
                Scanner
              </button>
              <button
                onClick={() => setCurrentPage('history')}
                className="px-4 py-2 rounded-lg bg-indigo-600 text-white font-semibold transition-colors"
              >
                History
              </button>
            </div>
          </header>

          <ScanHistory />
        </div>
      </main>
    );
  }

  // Scanner page (default)
  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-slate-200 font-body">
      {/* Background grid effect */}
      <div className="fixed inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGRlZnM+PHBhdHRlcm4gaWQ9ImdyaWQiIHdpZHRoPSI0MCIgaGVpZ2h0PSI0MCIgcGF0dGVyblVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+PHBhdGggZD0iTSAwIDEwIEwgNDAgMTAgTSAxMCAwIEwgMTAgNDAgTSAwIDIwIEwgNDAgMjAgTSAyMCAwIEwgMjAgNDAgTSAwIDMwIEwgNDAgMzAgTSAzMCAwIEwgMzAgNDAiIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzFlMjkzYiIgb3BhY2l0eT0iMC4zIiBzdHJva2Utd2lkdGg9IjEiLz48L3BhdHRlcm4+PC9kZWZzPjxyZWN0IHdpZHRoPSIxMDAlIiBoZWlnaHQ9IjEwMCUiIGZpbGw9InVybCgjZ3JpZCkiLz48L3N2Zz4=')] opacity-30 pointer-events-none" />

      <div className="relative mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Header */}
        <header className="mb-8 flex flex-col items-start justify-between rounded-2xl border border-white/10 bg-slate-800/50 backdrop-blur-md p-6 shadow-xl md:flex-row md:items-center">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500 to-cyan-400 shadow-lg shadow-indigo-500/20">
              <svg className="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <p className="text-xs font-bold tracking-[0.2em] text-indigo-400 uppercase">SecureScan</p>
              <h1 className="text-2xl font-extrabold text-white font-heading">Security Dashboard</h1>
              <p className="mt-1 text-sm text-slate-400">
                OWASP Top 10 Vulnerability Scanner • SQLi • XSS • Sensitive Data
              </p>
            </div>
          </div>
          <div className="flex items-center gap-4 mt-4 md:mt-0">
            {status === 'running' && (
              <div className="flex items-center gap-3 rounded-full bg-indigo-500/10 border border-indigo-500/20 px-4 py-2 text-indigo-400">
                <span className="relative flex h-3 w-3">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-indigo-400 opacity-75" />
                  <span className="relative inline-flex h-3 w-3 rounded-full bg-indigo-500" />
                </span>
                <span className="font-medium text-sm">Scan Engine Running...</span>
              </div>
            )}
            {/* Navigation tabs */}
            <div className="flex gap-2">
              <button
                onClick={() => setCurrentPage('scanner')}
                className="px-4 py-2 rounded-lg bg-indigo-600 text-white font-semibold transition-colors"
              >
                Scanner
              </button>
              <button
                onClick={() => setCurrentPage('history')}
                className="px-4 py-2 rounded-lg bg-slate-700/50 hover:bg-slate-700 text-slate-300 font-semibold transition-colors"
              >
                History
              </button>
            </div>
          </div>
        </header>

        {/* ── Scan Form ── */}
        <section className="mb-8 rounded-2xl border border-white/10 bg-slate-800/50 backdrop-blur-md p-6 shadow-lg">
          <form onSubmit={handleSubmit} className="flex flex-col gap-4 sm:flex-row">
            <input
              type="url"
              required
              id="scan-url-input"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              className="flex-1 rounded-xl border border-white/10 bg-slate-900/50 px-4 py-3 text-white placeholder-slate-500 outline-none ring-indigo-500/50 transition focus:ring-2 focus:border-indigo-500"
            />
            <button
              type="submit"
              id="start-scan-btn"
              disabled={status === 'running'}
              className="rounded-xl bg-gradient-to-r from-indigo-600 to-indigo-500 px-8 py-3 font-semibold text-white shadow-lg shadow-indigo-500/20 hover:shadow-indigo-500/40 disabled:cursor-not-allowed disabled:opacity-40 transition-all"
            >
              {status === 'running' ? 'Scanning...' : 'Start Scan'}
            </button>
            {status === 'running' && (
              <button
                type="button"
                id="stop-scan-btn"
                onClick={handleCancel}
                className="rounded-xl bg-gradient-to-r from-red-600 to-red-500 px-8 py-3 font-semibold text-white shadow-lg shadow-red-500/20 hover:shadow-red-500/40 transition-all flex items-center gap-2"
              >
                <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 10a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z" />
                </svg>
                Stop Scan
              </button>
            )}
          </form>
          {status === 'error' && (
            <p className="mt-4 rounded-xl bg-red-500/10 border border-red-500/20 p-3 text-red-400 text-sm">
              {error || 'The scan encountered a critical error and could not complete.'}
            </p>
          )}
          {status === 'cancelled' && (
            <div className="mt-4 rounded-xl bg-amber-500/10 border border-amber-500/20 p-4 flex items-center gap-3">
              <svg className="h-5 w-5 text-amber-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
              <span className="text-amber-400 text-sm font-medium">Scan was cancelled. Partial results may be available below.</span>
            </div>
          )}
          {error && status !== 'error' && status !== 'cancelled' && (
            <p className="mt-4 rounded-xl bg-red-500/10 border border-red-500/20 p-3 text-red-400 text-sm">{error}</p>
          )}
        </section>

        {/* ── Results ── */}
        {status === 'completed' && result && (
          <div className="space-y-8 animate-fadeIn">
            {/* Score Cards */}
            <ScoreCard
              score={result.score || 0}
              grade={result.grade || 'F'}
              testsPassed={result.tests_passed || 0}
              testsTotal={result.tests_total || 10}
            />

            {/* Charts Row */}
            <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <PassFailChart
                testsPassed={result.tests_passed || 0}
                testsTotal={result.tests_total || 10}
              />
              <OWASPRadarChart owaspResults={result.owasp_results || []} />
              <SeverityDonut summary={stats} />
            </section>

            {/* OWASP Table */}
            {result.owasp_results && result.owasp_results.length > 0 && (
              <OWASPTable owaspResults={result.owasp_results} />
            )}

            {/* Vulnerability List */}
            <VulnerabilityList vulnerabilities={result.vulnerabilities} />

            {/* Export */}
            <section className="rounded-2xl border border-white/10 bg-slate-800/50 backdrop-blur-md p-6 shadow-lg">
              <h2 className="text-lg font-bold text-white mb-4">Export Report</h2>
              <ReportExport url={url} />
            </section>
          </div>
        )}

        {/* ── Logs ── */}
        {(status === 'running' || status === 'completed' || status === 'cancelled') && (
          <section className="mt-8">
            <ScanLogs logs={logs} status={status} downloadLogs={downloadLogs} />
          </section>
        )}

        {/* Footer */}
        <footer className="mt-12 text-center text-xs text-slate-600">
          SecureScan v2.0 — OWASP Top 10 Vulnerability Scanner • Built with Flask + React
        </footer>
      </div>
    </main>
  );
}
