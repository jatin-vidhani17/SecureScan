import React from 'react';

const gradeColors = {
  A: 'from-emerald-400 to-emerald-600',
  B: 'from-blue-400 to-blue-600',
  C: 'from-amber-400 to-amber-600',
  D: 'from-orange-400 to-orange-600',
  F: 'from-red-400 to-red-600',
};

const gradeGlow = {
  A: 'shadow-emerald-500/30',
  B: 'shadow-blue-500/30',
  C: 'shadow-amber-500/30',
  D: 'shadow-orange-500/30',
  F: 'shadow-red-500/30',
};

export default function ScoreCard({ score, grade, testsPassed, testsTotal }) {
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const gradientClass = gradeColors[grade] || gradeColors.F;
  const glowClass = gradeGlow[grade] || gradeGlow.F;

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      {/* Circular Score */}
      <div className="flex flex-col items-center justify-center rounded-2xl border border-white/10 bg-slate-800/50 backdrop-blur-md p-8 shadow-lg">
        <div className="relative">
          <svg width="170" height="170" className="-rotate-90">
            <circle cx="85" cy="85" r={radius} fill="none" stroke="#1e293b" strokeWidth="12" />
            <circle
              cx="85" cy="85" r={radius} fill="none"
              stroke="url(#scoreGradient)"
              strokeWidth="12"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              className="transition-all duration-1000 ease-out"
            />
            <defs>
              <linearGradient id="scoreGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#818cf8" />
                <stop offset="100%" stopColor="#6366f1" />
              </linearGradient>
            </defs>
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-4xl font-black text-white">{score}</span>
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">out of 100</span>
          </div>
        </div>
        <p className="mt-4 text-sm font-semibold text-slate-400 uppercase tracking-widest">Security Score</p>
      </div>

      {/* Grade Badge */}
      <div className="flex flex-col items-center justify-center rounded-2xl border border-white/10 bg-slate-800/50 backdrop-blur-md p-8 shadow-lg">
        <div className={`flex h-28 w-28 items-center justify-center rounded-2xl bg-gradient-to-br ${gradientClass} shadow-2xl ${glowClass}`}>
          <span className="text-5xl font-black text-white">{grade}</span>
        </div>
        <p className="mt-4 text-sm font-semibold text-slate-400 uppercase tracking-widest">Grade</p>
        <p className="mt-1 text-xs text-slate-500">
          {grade === 'A' && 'Excellent security posture'}
          {grade === 'B' && 'Good — minor improvements needed'}
          {grade === 'C' && 'Fair — several issues found'}
          {grade === 'D' && 'Poor — significant vulnerabilities'}
          {grade === 'F' && 'Critical — immediate action required'}
        </p>
      </div>

      {/* Tests Passed */}
      <div className="flex flex-col items-center justify-center rounded-2xl border border-white/10 bg-slate-800/50 backdrop-blur-md p-8 shadow-lg">
        <div className="flex items-baseline gap-1">
          <span className="text-5xl font-black text-white">{testsPassed}</span>
          <span className="text-2xl font-bold text-slate-500">/ {testsTotal}</span>
        </div>
        <p className="mt-4 text-sm font-semibold text-slate-400 uppercase tracking-widest">Tests Passed</p>
        <div className="mt-3 w-full bg-slate-700 rounded-full h-2.5">
          <div
            className="bg-gradient-to-r from-indigo-500 to-cyan-400 h-2.5 rounded-full transition-all duration-1000"
            style={{ width: `${(testsPassed / testsTotal) * 100}%` }}
          />
        </div>
      </div>
    </div>
  );
}
