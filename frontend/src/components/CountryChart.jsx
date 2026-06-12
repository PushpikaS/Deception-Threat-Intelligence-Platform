import { useMemo } from 'react'
import {
  Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import Card from './Card'
import { SkeletonCard } from './LoadingSkeleton'

const RANGES = [
  { hours: 24, label: '24h' },
  { hours: 48, label: '48h' },
  { hours: 168, label: '7d' },
]

function flagEmoji(code) {
  if (!code || code.length !== 2 || code === 'Un') return '🌐'
  return code.toUpperCase().replace(/./g, (c) => String.fromCodePoint(127397 + c.charCodeAt(0)))
}

function severity(score) {
  if (score >= 70) return { label: 'Critical', className: 'country-sev--critical' }
  if (score >= 40) return { label: 'Elevated', className: 'country-sev--elevated' }
  return { label: 'Low', className: 'country-sev--low' }
}

function barColor(score) {
  if (score >= 70) return '#ef4444'
  if (score >= 40) return '#f59e0b'
  return '#38bdf8'
}

function CountryTooltip({ active, payload }) {
  if (!active || !payload?.length) return null
  const row = payload[0]?.payload
  if (!row) return null
  const sev = severity(row.maxRisk)
  return (
    <div className="country-chart-tooltip">
      <p className="font-semibold text-slate-100">{row.country} {row.code ? `(${row.code})` : ''}</p>
      <dl className="mt-2 space-y-1 text-[11px] text-slate-400">
        <div className="flex justify-between gap-4"><dt>Events</dt><dd className="text-slate-200 tabular-nums">{row.events}</dd></div>
        <div className="flex justify-between gap-4"><dt>Unique IPs</dt><dd className="text-slate-200 tabular-nums">{row.ips}</dd></div>
        <div className="flex justify-between gap-4"><dt>Share</dt><dd className="text-slate-200 tabular-nums">{row.share}%</dd></div>
        <div className="flex justify-between gap-4"><dt>Avg risk</dt><dd className="text-slate-200 tabular-nums">{row.avgRisk}</dd></div>
        <div className="flex justify-between gap-4"><dt>Peak risk</dt><dd className="text-slate-200 tabular-nums">{row.maxRisk}</dd></div>
        {row.highRiskIps > 0 && (
          <div className="flex justify-between gap-4"><dt>High-risk IPs</dt><dd className="text-red-400 tabular-nums">{row.highRiskIps}</dd></div>
        )}
      </dl>
      <span className={`inline-block mt-2 px-2 py-0.5 rounded-full text-[10px] font-medium ${sev.className}`}>{sev.label}</span>
    </div>
  )
}

export default function CountryChart({ data, loading, hours = 24, onHoursChange }) {
  const rows = useMemo(() => {
    const list = (data || []).map((d) => ({
      code: d.country_code && d.country_code !== 'Unknown' ? d.country_code : null,
      country: d.country || 'Unknown',
      shortName: (d.country || 'Unknown').length > 14 ? `${(d.country || 'Unknown').slice(0, 12)}…` : (d.country || 'Unknown'),
      events: d.event_count || 0,
      ips: d.unique_ips || 0,
      maxRisk: d.max_risk || 0,
      avgRisk: d.avg_risk || 0,
      highRiskIps: d.high_risk_ips || 0,
      share: d.share_percent || 0,
    }))
    const total = list.reduce((s, r) => s + r.events, 0) || 1
    return list.map((r) => ({ ...r, share: r.share || Math.round((r.events / total) * 100) }))
  }, [data])

  const stats = useMemo(() => {
    const totalEvents = rows.reduce((s, r) => s + r.events, 0)
    const top = rows[0]
    const critical = rows.filter((r) => r.maxRisk >= 70).length
    const highRiskIps = rows.reduce((s, r) => s + r.highRiskIps, 0)
    return { totalEvents, top, critical, highRiskIps, countryCount: rows.length }
  }, [rows])

  const chartData = useMemo(
    () => [...rows].reverse().map((r) => ({ ...r, name: r.shortName })),
    [rows],
  )

  return (
    <Card
      title="Top Attacking Countries"
      className="xl:col-span-2"
      actions={(
        <div className="flex items-center gap-1">
          {RANGES.map((r) => (
            <button
              key={r.hours}
              type="button"
              onClick={() => onHoursChange?.(r.hours)}
              className={`px-2 py-0.5 text-[10px] font-medium rounded transition-colors ${
                hours === r.hours
                  ? 'bg-accent/20 text-accent border border-accent/40'
                  : 'text-slate-500 hover:text-slate-300 border border-transparent'
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
      )}
    >
      {loading && !rows.length ? (
        <div className="h-72"><SkeletonCard /></div>
      ) : !rows.length ? (
        <div className="text-center py-14">
          <p className="text-slate-300 text-sm font-medium">No geographic attack data</p>
          <p className="text-slate-500 text-xs mt-2 max-w-sm mx-auto">
            Traffic from public IPs is geolocated automatically. Use X-Forwarded-For when testing locally.
          </p>
        </div>
      ) : (
        <div className="space-y-5">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <Kpi label="Events" value={stats.totalEvents} accent />
            <Kpi label="Countries" value={stats.countryCount} />
            <Kpi
              label="Top share"
              value={stats.top ? `${stats.top.share}%` : '—'}
              sub={stats.top?.country}
            />
            <Kpi
              label="Critical origins"
              value={stats.critical}
              warn={stats.critical > 0}
              sub={stats.highRiskIps ? `${stats.highRiskIps} high-risk IPs` : undefined}
            />
          </div>

          <div className="h-52 sm:h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} layout="vertical" margin={{ left: 4, right: 12, top: 4, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis
                  type="category"
                  dataKey="name"
                  tick={{ fill: '#94a3b8', fontSize: 10 }}
                  width={72}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip content={<CountryTooltip />} cursor={{ fill: 'rgba(56, 189, 248, 0.06)' }} />
                <Bar dataKey="events" radius={[0, 6, 6, 0]} barSize={14} animationDuration={700}>
                  {chartData.map((entry) => (
                    <Cell key={entry.code || entry.country} fill={barColor(entry.maxRisk)} fillOpacity={0.9} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="country-rank-table rounded-lg border border-surface-border overflow-hidden">
            <div className="grid country-rank-head text-[10px] uppercase tracking-wider text-slate-500 bg-surface/50 px-3 py-2 border-b border-surface-border">
              <span>#</span>
              <span>Country</span>
              <span className="text-right">Events</span>
              <span className="text-right hidden sm:block">IPs</span>
              <span className="text-right">Share</span>
              <span className="text-right">Severity</span>
            </div>
            {rows.map((r, i) => {
              const sev = severity(r.maxRisk)
              return (
                <div key={`${r.code}-${r.country}`} className="grid country-rank-row px-3 py-2.5 text-xs border-b border-surface-border/50 last:border-0 hover:bg-surface/30 transition-colors">
                  <span className="text-slate-600 tabular-nums">{i + 1}</span>
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-base shrink-0" aria-hidden>{flagEmoji(r.code)}</span>
                    <div className="min-w-0">
                      <p className="text-slate-200 font-medium truncate">{r.country}</p>
                      {r.code && <p className="text-[10px] text-slate-600 mono">{r.code}</p>}
                    </div>
                  </div>
                  <span className="text-right font-semibold text-slate-100 tabular-nums">{r.events}</span>
                  <span className="text-right text-slate-400 tabular-nums hidden sm:block">{r.ips}</span>
                  <div className="text-right">
                    <span className="text-slate-300 tabular-nums">{r.share}%</span>
                    <div className="country-share-track mt-1 ml-auto max-w-[72px]">
                      <div className="country-share-fill" style={{ width: `${Math.max(r.share, 6)}%`, background: barColor(r.maxRisk) }} />
                    </div>
                  </div>
                  <div className="text-right">
                    <span className={`country-sev ${sev.className}`}>{sev.label}</span>
                    <p className="text-[10px] text-slate-600 mt-0.5 tabular-nums">avg {r.avgRisk}</p>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </Card>
  )
}

function Kpi({ label, value, sub, accent, warn }) {
  return (
    <div className="country-kpi rounded-lg border border-surface-border bg-surface/40 px-3 py-2.5">
      <p className="text-[10px] uppercase tracking-wider text-slate-500">{label}</p>
      <p className={`text-xl font-bold tabular-nums mt-0.5 ${
        warn ? 'text-red-400' : accent ? 'text-slate-100' : 'text-slate-200'
      }`}>
        {value}
      </p>
      {sub && <p className="text-[10px] text-slate-600 mt-0.5 truncate">{sub}</p>}
    </div>
  )
}