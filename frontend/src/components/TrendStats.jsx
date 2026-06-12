import { trendDelta } from '../api'
import Card from './Card'

export default function TrendStats({ trends, loading }) {
  if (loading && !trends) {
    return (
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <Card key={i} className="h-20 animate-pulse bg-surface" />
        ))}
      </div>
    )
  }
  if (!trends) return null

  const items = [
    { label: 'Events (7d)', value: trends.events_7d, delta: trendDelta(trends.events_7d, trends.events_prev_7d) },
    { label: 'Events (30d)', value: trends.events_30d, delta: null },
    { label: 'Unique IPs (7d)', value: trends.unique_ips_7d, delta: null },
    { label: 'High risk (7d)', value: trends.high_risk_7d, delta: trendDelta(trends.high_risk_7d, trends.high_risk_prev_7d), warn: true },
  ]

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {items.map((item) => (
        <Card key={item.label} className="hover:border-accent/20 transition-colors">
          <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">{item.label}</p>
          <div className="flex items-end justify-between">
            <p className={`text-2xl font-bold ${item.warn ? 'text-accent-warn' : 'text-white'}`}>
              {Number(item.value || 0).toLocaleString()}
            </p>
            {item.delta && (
              <span className={`text-[10px] font-medium ${item.delta.startsWith('+') ? 'text-accent-warn' : 'text-accent-ok'}`}>
                {item.delta} vs prior week
              </span>
            )}
          </div>
        </Card>
      ))}
    </div>
  )
}