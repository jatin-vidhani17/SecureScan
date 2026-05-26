import React, { useState, useEffect } from 'react';
import { getScanHistory, getHistoricalScanReport } from '../api';
import ScoreCard from './ScoreCard';
import OWASPTable from './OWASPTable';
import VulnerabilityList from './VulnerabilityList';
import ScanLogs from './ScanLogs';
import { PassFailChart, OWASPRadarChart, SeverityDonut } from './Charts';

export default function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [selectedReport, setSelectedReport] = useState(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(1);

  // Fetch scan history on mount and page change
  useEffect(() => {
    const fetchHistory = async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await getScanHistory(page, 10);
        setScans(data.scans);
      } catch (err) {
        setError('Failed to load scan history');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchHistory();
  }, [page]);

  // Fetch detailed report when scan is selected
  useEffect(() => {
    const fetchReport = async () => {
      if (!selectedScanId) return;
      try {
        setReportLoading(true);
        const report = await getHistoricalScanReport(selectedScanId);
        setSelectedReport(report);
      } catch (err) {
        setError('Failed to load scan report');
        console.error(err);
      } finally {
        setReportLoading(false);
      }
    };
    fetchReport();
  }, [selectedScanId]);

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  const getStatusBadge = (status) => {
    const statusClasses = {
      completed: 'bg-emerald-500/20 text-emerald-400',
      running: 'bg-blue-500/20 text-blue-400',
      error: 'bg-red-500/20 text-red-400',
    };
    return statusClasses[status] || 'bg-slate-500/20 text-slate-400';
  };

  const getGradeColor = (grade) => {
    const colors = {
      A: 'text-emerald-400',
      B: 'text-blue-400',
      C: 'text-amber-400',
      D: 'text-orange-400',
      F: 'text-red-400',
    };
    return colors[grade] || 'text-slate-400';
  };

  // If no scans and not loading, show empty state
  if (!loading && scans.length === 0) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-4xl font-black text-white mb-2">Scan History</h1>
          <p className="text-slate-400 mb-12">No scans yet</p>
          
          <div className="border border-dashed border-slate-600 rounded-2xl p-12 text-center">
            <div className="mb-6">
              <svg className="mx-auto h-16 w-16 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8m0 8l-6-2m6 2l6-2" />
              </svg>
            </div>
            <h3 className="text-xl font-semibold text-white mb-2">Start your first scan</h3>
            <p className="text-slate-400 mb-6">Run a security scan to see results and build your history</p>
            <a
              href="/"
              className="inline-block px-6 py-3 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold transition-colors"
            >
              Go to Scanner
            </a>
          </div>
        </div>
      </div>
    );
  }

  // If a report is selected, show full report view
  if (selectedScanId && selectedReport) {
    if (reportLoading) {
      return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6">
          <div className="max-w-7xl mx-auto">
            <button
              onClick={() => {
                setSelectedScanId(null);
                setSelectedReport(null);
              }}
              className="mb-6 px-4 py-2 rounded-lg bg-slate-700/50 hover:bg-slate-700 text-slate-300 font-semibold transition-colors"
            >
              ← Back to History
            </button>
            <div className="text-center py-12">
              <div className="inline-block">
                <div className="animate-spin rounded-full h-12 w-12 border-4 border-slate-600 border-t-indigo-500"></div>
              </div>
              <p className="mt-4 text-slate-400">Loading report...</p>
            </div>
          </div>
        </div>
      );
    }

    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6">
        <div className="max-w-7xl mx-auto">
          {/* Back button and header */}
          <button
            onClick={() => {
              setSelectedScanId(null);
              setSelectedReport(null);
            }}
            className="mb-6 px-4 py-2 rounded-lg bg-slate-700/50 hover:bg-slate-700 text-slate-300 font-semibold transition-colors"
          >
            ← Back to History
          </button>

          <h1 className="text-4xl font-black text-white mb-2">
            Scan Report: {selectedReport.target}
          </h1>
          <p className="text-slate-400 mb-8">
            Scanned on {formatDate(selectedReport.started_at)} | Status: {selectedReport.status}
          </p>

          {/* Score Cards */}
          <ScoreCard
            score={selectedReport.score}
            grade={selectedReport.grade}
            testsPassed={selectedReport.tests_passed}
            testsTotal={selectedReport.tests_total}
          />

          {/* Charts */}
          <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
            <PassFailChart
              testsPassed={selectedReport.tests_passed}
              testsTotal={selectedReport.tests_total}
            />
            <OWASPRadarChart owaspResults={selectedReport.owasp_results || []} />
            <SeverityDonut summary={selectedReport.summary || { total: 0, high: 0, medium: 0, low: 0 }} />
          </div>

          {/* OWASP Results */}
          {selectedReport.owasp_results && selectedReport.owasp_results.length > 0 && (
            <div className="mt-12">
              <h2 className="text-2xl font-bold text-white mb-6">OWASP Top 10 Results</h2>
              <OWASPTable owaspResults={selectedReport.owasp_results} />
            </div>
          )}

          {/* Summary */}
          {selectedReport.summary && (
            <div className="mt-12 grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="rounded-xl bg-slate-800/50 border border-white/10 p-6">
                <p className="text-slate-400 text-sm font-semibold uppercase mb-2">Total Issues</p>
                <p className="text-3xl font-black text-white">{selectedReport.summary.total}</p>
              </div>
              <div className="rounded-xl bg-red-900/20 border border-red-500/30 p-6">
                <p className="text-red-400 text-sm font-semibold uppercase mb-2">High Severity</p>
                <p className="text-3xl font-black text-red-400">{selectedReport.summary.high}</p>
              </div>
              <div className="rounded-xl bg-amber-900/20 border border-amber-500/30 p-6">
                <p className="text-amber-400 text-sm font-semibold uppercase mb-2">Medium Severity</p>
                <p className="text-3xl font-black text-amber-400">{selectedReport.summary.medium}</p>
              </div>
              <div className="rounded-xl bg-blue-900/20 border border-blue-500/30 p-6">
                <p className="text-blue-400 text-sm font-semibold uppercase mb-2">Low Severity</p>
                <p className="text-3xl font-black text-blue-400">{selectedReport.summary.low}</p>
              </div>
            </div>
          )}

          {/* Vulnerability List */}
          {selectedReport.vulnerabilities && selectedReport.vulnerabilities.length > 0 && (
            <div className="mt-12">
              <VulnerabilityList vulnerabilities={selectedReport.vulnerabilities} />
            </div>
          )}

          {/* Scan Logs */}
          <div className="mt-12">
            <ScanLogs logs={selectedReport.logs || []} status="completed" />
          </div>
        </div>
      </div>
    );
  }

  // Main history view
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-4xl font-black text-white mb-2">Scan History</h1>
        <p className="text-slate-400 mb-8">View and analyze your previous security scans</p>

        {error && (
          <div className="mb-6 p-4 rounded-lg bg-red-900/20 border border-red-500/30 text-red-400">
            {error}
          </div>
        )}

        {loading ? (
          <div className="text-center py-12">
            <div className="inline-block">
              <div className="animate-spin rounded-full h-12 w-12 border-4 border-slate-600 border-t-indigo-500"></div>
            </div>
            <p className="mt-4 text-slate-400">Loading scan history...</p>
          </div>
        ) : (
          <>
            {/* Scans Timeline */}
            <div className="space-y-3">
              {scans.map((scan) => (
                <div
                  key={scan.id}
                  onClick={() => setSelectedScanId(scan.id)}
                  className="p-5 rounded-xl bg-slate-800/50 border border-white/10 hover:border-indigo-500/50 hover:bg-slate-800/70 cursor-pointer transition-all duration-200"
                >
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="text-lg font-semibold text-white truncate">{scan.target_url}</h3>
                        <span className={`px-2 py-1 rounded text-xs font-semibold whitespace-nowrap ${getStatusBadge(scan.status)}`}>
                          {scan.status}
                        </span>
                      </div>
                      <p className="text-sm text-slate-400">
                        Scanned on {formatDate(scan.started_at)}
                      </p>
                    </div>

                    {/* Score and Grade */}
                    <div className="flex items-center gap-6 flex-shrink-0">
                      {scan.score !== null && (
                        <>
                          <div className="text-center">
                            <p className="text-2xl font-black text-white">{scan.score}</p>
                            <p className="text-xs text-slate-400">Score</p>
                          </div>
                          <div className="text-center">
                            <p className={`text-3xl font-black ${getGradeColor(scan.grade)}`}>
                              {scan.grade}
                            </p>
                            <p className="text-xs text-slate-400">Grade</p>
                          </div>
                        </>
                      )}
                    </div>

                    {/* Arrow indicator */}
                    <svg className="w-5 h-5 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  </div>
                </div>
              ))}
            </div>

            {/* Pagination */}
            <div className="mt-8 flex items-center justify-center gap-2">
              <button
                onClick={() => setPage(Math.max(1, page - 1))}
                disabled={page === 1}
                className="px-4 py-2 rounded-lg bg-slate-700/50 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed text-slate-300 font-semibold transition-colors"
              >
                Previous
              </button>
              <span className="text-slate-400 text-sm">Page {page}</span>
              <button
                onClick={() => setPage(page + 1)}
                className="px-4 py-2 rounded-lg bg-slate-700/50 hover:bg-slate-700 text-slate-300 font-semibold transition-colors"
              >
                Next
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
