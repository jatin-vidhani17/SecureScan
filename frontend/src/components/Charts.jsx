import React from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
  PieChart, Pie
} from 'recharts';

const COLORS = {
  pass: '#34d399',
  fail: '#f87171',
};

/**
 * Bar chart: Passed vs Failed tests
 */
export function PassFailChart({ testsPassed, testsTotal }) {
  const data = [
    { name: 'Passed', value: testsPassed, color: COLORS.pass },
    { name: 'Failed', value: testsTotal - testsPassed, color: COLORS.fail },
  ];

  return (
    <div className="rounded-2xl border border-white/10 bg-slate-800/50 backdrop-blur-md p-6 shadow-lg">
      <h3 className="mb-4 text-sm font-bold text-slate-400 uppercase tracking-widest">Pass / Fail Overview</h3>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} barCategoryGap="30%">
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 12 }} />
          <YAxis allowDecimals={false} tick={{ fill: '#94a3b8', fontSize: 12 }} />
          <Tooltip
            contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '12px', color: '#e2e8f0' }}
          />
          <Bar dataKey="value" radius={[8, 8, 0, 0]}>
            {data.map((entry, index) => (
              <Cell key={index} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/**
 * Radar chart: OWASP category strength
 */
export function OWASPRadarChart({ owaspResults }) {
  const data = owaspResults.map(r => ({
    category: r.owasp_id,
    fullName: r.owasp_name,
    score: r.status === 'pass' ? 10 : (r.severity === 'High' ? 0 : r.severity === 'Medium' ? 3 : 6),
    fullMark: 10,
  }));

  return (
    <div className="rounded-2xl border border-white/10 bg-slate-800/50 backdrop-blur-md p-6 shadow-lg">
      <h3 className="mb-4 text-sm font-bold text-slate-400 uppercase tracking-widest">OWASP Coverage Radar</h3>
      <ResponsiveContainer width="100%" height={300}>
        <RadarChart data={data} cx="50%" cy="50%" outerRadius="70%">
          <PolarGrid stroke="#334155" />
          <PolarAngleAxis dataKey="category" tick={{ fill: '#94a3b8', fontSize: 11 }} />
          <PolarRadiusAxis angle={90} domain={[0, 10]} tick={false} />
          <Radar
            name="Score"
            dataKey="score"
            stroke="#818cf8"
            fill="#6366f1"
            fillOpacity={0.35}
            strokeWidth={2}
          />
          <Tooltip
            contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '12px', color: '#e2e8f0' }}
            formatter={(value, name, props) => [`${value}/10`, props.payload.fullName]}
          />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  );
}

/**
 * Severity donut: High / Medium / Low breakdown
 */
export function SeverityDonut({ summary }) {
  const data = [
    { name: 'High', value: summary.high, fill: '#ef4444' },
    { name: 'Medium', value: summary.medium, fill: '#f59e0b' },
    { name: 'Low', value: summary.low, fill: '#22c55e' },
  ].filter(d => d.value > 0);

  if (data.length === 0) {
    data.push({ name: 'No Issues', value: 1, fill: '#22c55e' });
  }

  return (
    <div className="rounded-2xl border border-white/10 bg-slate-800/50 backdrop-blur-md p-6 shadow-lg">
      <h3 className="mb-4 text-sm font-bold text-slate-400 uppercase tracking-widest">Severity Breakdown</h3>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={data}
            cx="50%" cy="50%"
            innerRadius={55} outerRadius={80}
            paddingAngle={4}
            dataKey="value"
            stroke="none"
          >
            {data.map((entry, index) => (
              <Cell key={index} fill={entry.fill} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '12px', color: '#e2e8f0' }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="flex justify-center gap-4 mt-2">
        {[
          { label: 'High', color: 'bg-red-500', count: summary.high },
          { label: 'Medium', color: 'bg-amber-500', count: summary.medium },
          { label: 'Low', color: 'bg-emerald-500', count: summary.low },
        ].map(item => (
          <div key={item.label} className="flex items-center gap-1.5 text-xs text-slate-400">
            <span className={`h-2.5 w-2.5 rounded-full ${item.color}`} />
            {item.label}: {item.count}
          </div>
        ))}
      </div>
    </div>
  );
}
