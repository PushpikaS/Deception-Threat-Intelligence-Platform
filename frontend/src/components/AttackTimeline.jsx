import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import Card from './Card'
import { SkeletonCard } from './LoadingSkeleton'

export default function AttackTimeline({ data, loading }) {
  const chartData = (data || []).map((d) => ({
    time: new Date(d.bucket).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    events: Number(d.count),
    ips: Number(d.unique_ips),
  }))

  if (loading && chartData.length === 0) {
    return (
      <Card title="Attack Timeline (24h)">
        <div className="h-64"><SkeletonCard /></div>
      </Card>
    )
  }

  return (
    <Card title="Attack Timeline (24h)">
      <div className="h-64">
        {chartData.length === 0 ? (
          <p className="text-slate-500 text-sm text-center py-16">No events in the selected period.</p>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="eventGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="ipGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#f59e0b" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 11 }} />
              <YAxis tick={{ fill: '#64748b', fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }}
                labelStyle={{ color: '#94a3b8' }}
              />
              <Area type="monotone" dataKey="events" stroke="#38bdf8" fill="url(#eventGrad)" strokeWidth={2} name="Events" animationDuration={800} />
              <Area type="monotone" dataKey="ips" stroke="#f59e0b" fill="url(#ipGrad)" strokeWidth={1.5} name="Unique IPs" animationDuration={800} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  )
}